use crate::{
    websocket::ProtocolMessage,
    zk::prover::MessageProver,
    Message, Result,
};
use futures_util::{SinkExt, StreamExt};
use std::{
    time::{SystemTime, UNIX_EPOCH},
};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use tracing::{error, info, warn};

/// WebSocket chat client
pub struct ChatClient {
    user_id: u64,
    username: String,
    prover: MessageProver,
    message_counter: u64,
}

impl ChatClient {
    /// Create a new chat client
    pub fn new(user_id: u64, username: String) -> Self {
        Self {
            user_id,
            username,
            prover: MessageProver::new(),
            message_counter: 0,
        }
    }

    /// Connect to the chat server and start the client
    pub async fn connect(&mut self, server_url: &str) -> Result<()> {
        let (ws_stream, _) = connect_async(server_url).await?;
        let (mut ws_sender, mut ws_receiver) = ws_stream.split();

        info!("Connected to server at {}", server_url);

        // Send join message
        let join_msg = ProtocolMessage::Join {
            user_id: self.user_id,
            username: self.username.clone(),
        };

        let join_bytes = join_msg.to_bytes()?;
        ws_sender
            .send(WsMessage::Text(String::from_utf8_lossy(&join_bytes).to_string()))
            .await?;

        // Variables for future use in input handling
        let _user_id = self.user_id;
        let _prover = self.prover.clone();
        let _counter = self.message_counter;

        // For now, we'll use a simple synchronous input loop
        // In a real implementation, you'd use async input handling
        println!("Chat client connected! Type messages and press Enter.");
        println!("Type '/quit' to exit.");

        // Handle incoming messages
        while let Some(msg) = ws_receiver.next().await {
            match msg {
                Ok(WsMessage::Text(text)) => {
                    match ProtocolMessage::from_bytes(text.as_bytes()) {
                        Ok(protocol_msg) => {
                            self.handle_server_message(protocol_msg).await;
                        }
                        Err(e) => {
                            warn!("Failed to parse server message: {}", e);
                        }
                    }
                }
                Ok(WsMessage::Ping(data)) => {
                    if let Err(e) = ws_sender.send(WsMessage::Pong(data)).await {
                        error!("Failed to send pong: {}", e);
                    }
                }
                Ok(WsMessage::Close(_)) => {
                    info!("Server closed connection");
                    break;
                }
                Err(e) => {
                    error!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Handle messages from the server
    async fn handle_server_message(&self, msg: ProtocolMessage) {
        match msg {
            ProtocolMessage::MessageBroadcast { message, verified, local_id } => {
                let verification_status = if verified { "✓" } else { "✗" };
                println!(
                    "[{}] user={} local#{} msg_id={} :: {} {}",
                    verification_status,
                    message.sender_id,
                    local_id,
                    message.id,
                    message.content,
                    format_timestamp(message.timestamp)
                );
            }
            ProtocolMessage::UserListUpdate { users } => {
                println!("Users online: {:?}", users);
            }
            ProtocolMessage::Error { code, message } => {
                println!("Error {}: {}", code, message);
            }
            ProtocolMessage::Pong => {
                // Handle pong if needed for keep-alive
            }
            _ => {
                warn!("Unhandled server message: {:?}", msg);
            }
        }
    }

    /// Send a message to the server
    pub fn send_message(&mut self, content: &str) -> Result<ProtocolMessage> {
        let (message, proof) = create_message_with_proof(
            self.user_id, 
            content, 
            &mut self.message_counter, 
            &mut self.prover
        )?;
        
        Ok(ProtocolMessage::SendMessage { message, proof })
    }
}

/// Create a message with ZK proof
fn create_message_with_proof(
    user_id: u64,
    content: &str,
    counter: &mut u64,
    prover: &mut MessageProver,
) -> Result<(Message, Vec<u8>)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    *counter += 1;
    let message = Message::new(*counter, user_id, content.to_string(), now);

    // For simplicity, we'll create a proof for just this single message
    let messages = vec![message.clone()];
    let proof = prover.prove(&messages)?;

    Ok((message, proof))
}

/// Format timestamp for display
fn format_timestamp(timestamp: u64) -> String {
    use chrono::{DateTime, Utc};
    let dt = DateTime::from_timestamp(timestamp as i64, 0)
        .unwrap_or_else(|| Utc::now());
    dt.format("%H:%M:%S").to_string()
}