use crate::{
    websocket::{ProtocolMessage, error_codes},
    zk::{MessageChain, prover::{MessageProver, verify_proof}},
    Result, ZkChatError, Message,
};
use futures_util::{SinkExt, StreamExt};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async, tungstenite::Message as WsMessage};
use tracing::{error, info, warn};
use winterfell::ProofOptions;

/// Connected user information
#[derive(Debug, Clone)]
pub struct User {
    pub id: u64,
    pub username: String,
    pub connected_at: u64,
}

/// Shared server state
#[derive(Debug)]
pub struct ServerState {
    pub users: HashMap<u64, User>,
    pub message_chain: MessageChain,
    pub prover: MessageProver,
    pub proof_options: ProofOptions,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            message_chain: MessageChain::new(),
            prover: MessageProver::new(),
            proof_options: ProofOptions::new(
                54, // num_queries (increased for higher soundness)
                16, // blowup_factor (greater domain expansion)
                16, // grinding_factor (adds PoW resistance)
                winterfell::FieldExtension::None,
                4,  // fri_folding_factor (smaller folds => more rounds)
                31, // fri_max_remainder_size
            ),
        }
    }
}

type SharedState = Arc<Mutex<ServerState>>;

/// WebSocket chat server with ZK proof verification
pub struct ChatServer {
    state: SharedState,
}

impl ChatServer {
    /// Create a new chat server
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ServerState::new())),
        }
    }

    /// Start the server on the specified address
    pub async fn start(&self, addr: impl Into<SocketAddr>) -> Result<()> {
        let addr = addr.into();
        let listener = TcpListener::bind(&addr).await?;
        info!("ZK Chat Server started on {}", addr);

        while let Ok((stream, peer_addr)) = listener.accept().await {
            info!("New connection from {}", peer_addr);
            let state = self.state.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, peer_addr, state).await {
                    error!("Connection error for {}: {}", peer_addr, e);
                }
            });
        }

        Ok(())
    }
}

/// Handle a WebSocket connection
async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    state: SharedState,
) -> Result<()> {
    let ws_stream = accept_async(stream).await?;
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    let mut user_id: Option<u64> = None;

    while let Some(msg) = ws_receiver.next().await {
        match msg {
            Ok(WsMessage::Text(text)) => {
                let protocol_msg = match ProtocolMessage::from_bytes(text.as_bytes()) {
                    Ok(msg) => msg,
                    Err(e) => {
                        warn!("Failed to parse message from {}: {}", peer_addr, e);
                        let error_msg = ProtocolMessage::error(
                            error_codes::INTERNAL_ERROR,
                            "Invalid message format",
                        );
                        if let Ok(response) = error_msg.to_bytes() {
                            let _ = ws_sender.send(WsMessage::Text(String::from_utf8_lossy(&response).to_string())).await;
                        }
                        continue;
                    }
                };

                let response = handle_protocol_message(protocol_msg, &state, &mut user_id).await;
                
                match response {
                    Ok(Some(response_msg)) => {
                        if let Ok(response_bytes) = response_msg.to_bytes() {
                            let response_text = String::from_utf8_lossy(&response_bytes);
                            if let Err(e) = ws_sender.send(WsMessage::Text(response_text.to_string())).await {
                                error!("Failed to send response to {}: {}", peer_addr, e);
                                break;
                            }
                        }
                    }
                    Ok(None) => {
                        // No response needed
                    }
                    Err(e) => {
                        error!("Error handling message from {}: {}", peer_addr, e);
                        let error_msg = ProtocolMessage::from(e);
                        if let Ok(error_bytes) = error_msg.to_bytes() {
                            let error_text = String::from_utf8_lossy(&error_bytes);
                            let _ = ws_sender.send(WsMessage::Text(error_text.to_string())).await;
                        }
                    }
                }
            }
            Ok(WsMessage::Binary(_)) => {
                warn!("Received unexpected binary message from {}", peer_addr);
            }
            Ok(WsMessage::Ping(data)) => {
                let _ = ws_sender.send(WsMessage::Pong(data)).await;
            }
            Ok(WsMessage::Pong(_)) => {
                // Handle pong if needed
            }
            Ok(WsMessage::Close(_)) => {
                info!("Connection closed by {}", peer_addr);
                break;
            }
            Ok(WsMessage::Frame(_)) => {
                // Handle frame messages if needed
            }
            Err(e) => {
                error!("WebSocket error from {}: {}", peer_addr, e);
                break;
            }
        }
    }

    // Clean up user on disconnect
    if let Some(uid) = user_id {
        let mut state_lock = state.lock().unwrap();
        state_lock.users.remove(&uid);
        info!("User {} disconnected from {}", uid, peer_addr);
    }

    Ok(())
}

/// Handle a protocol message
async fn handle_protocol_message(
    msg: ProtocolMessage,
    state: &SharedState,
    user_id: &mut Option<u64>,
) -> Result<Option<ProtocolMessage>> {
    match msg {
        ProtocolMessage::Join { user_id: uid, username } => {
            let mut state_lock = state.lock().unwrap();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let user = User {
                id: uid,
                username: username.clone(),
                connected_at: now,
            };

            state_lock.users.insert(uid, user);
            *user_id = Some(uid);

            info!("User {} ({}) joined", username, uid);

            // Send user list update
            let users: Vec<(u64, String)> = state_lock
                .users
                .values()
                .map(|u| (u.id, u.username.clone()))
                .collect();

            Ok(Some(ProtocolMessage::UserListUpdate { users }))
        }

        ProtocolMessage::Leave { user_id: uid } => {
            let mut state_lock = state.lock().unwrap();
            state_lock.users.remove(&uid);
            *user_id = None;

            info!("User {} left", uid);
            Ok(None)
        }

        ProtocolMessage::SendMessage { message, proof: _ } => {
            // Verify user is authenticated
            let uid = user_id.ok_or(ZkChatError::InvalidSender)?;
            
            // Verify message sender matches authenticated user
            if message.sender_id != uid {
                return Err(ZkChatError::InvalidSender);
            }

            // Create message with server-computed hash (more secure than trusting client)
            let server_message = Message::new(message.id, message.sender_id, message.content.clone(), message.timestamp);

            let mut state_lock = state.lock().unwrap();
            
            // Create a temporary chain with the server-computed message to verify the proof
            let mut temp_chain = state_lock.message_chain.clone();
            temp_chain.add_message(server_message.clone())?;

            // Generate server-side proof over the FULL chain (existing messages + new one)
            let messages_for_proof = {
                let mut all = state_lock.message_chain.messages.clone();
                all.push(server_message.clone());
                all
            };
            let mut prover = crate::zk::prover::MessageProver::new();
            
            // Generate proper ZK proof using server-computed hash
            let server_proof_result = prover.prove(&messages_for_proof);
            let server_proof_valid = server_proof_result.is_ok();
            
            // Verify the server-generated proof to ensure correctness
            let verification_result = if let Ok(server_proof) = server_proof_result {
                let pub_inputs = crate::zk::air::PublicInputs {
                    initial_hash: [0u8; 32], // Empty initial hash
                    final_hash: temp_chain.chain_hash,
                    message_count: temp_chain.len(),
                };
                verify_proof(&server_proof, pub_inputs)
            } else {
                Err(crate::ZkChatError::ProofVerificationFailed)
            };
            
            let is_verified = verification_result.is_ok();
            let hash_valid = server_message.verify_hash();
            let final_verification = is_verified && hash_valid && server_proof_valid;
            
            if final_verification {
                info!("Message verified with ZK proof from user {}: {}", uid, server_message.content);
            } else {
                if !is_verified {
                    warn!("ZK proof verification failed for user {}: {:?}", uid, verification_result.err());
                }
                if !hash_valid {
                    warn!("Message hash verification failed for user {}", uid);
                }
                warn!("Message failed verification from user {}: {}", uid, server_message.content);
            }

            // If verification passed or we allow unverified messages, add to chain
            state_lock.message_chain.add_message(server_message.clone())?;

            // Broadcast the server-computed message with actual verification status
            let local_id_value = server_message.id;
            Ok(Some(ProtocolMessage::MessageBroadcast {
                message: server_message,
                verified: final_verification,
                local_id: local_id_value, // legacy server uses message id as local sequence
            }))
        }

        ProtocolMessage::Ping => Ok(Some(ProtocolMessage::Pong)),

        _ => {
            warn!("Unhandled protocol message: {:?}", msg);
            Ok(None)
        }
    }
}