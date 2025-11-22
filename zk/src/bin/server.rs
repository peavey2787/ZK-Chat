use warp::Filter;
use tracing::{info, warn, Level};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zk_chat::test_harness;
use base64::{engine::general_purpose, Engine as _};
use zk_chat::zk::{air::{PublicInputs, build_trace}, prover::{MessageProver, verify_proof}, elements_to_hash};
use winterfell::math::FieldElement; // for BaseElement::ZERO

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    info!("ZK Chat Server - WebSocket Messenger with ZK-STARK Proofs");
    info!("=========================================================");

    // Serve static files from the static directory
    let static_files = warp::fs::dir("static");

    // WebSocket route (chat paused, retained for backward compatibility)
    let websocket = warp::path("ws")
        .and(warp::ws())
        .map(|ws: warp::ws::Ws| {
            ws.on_upgrade(handle_websocket)
        });

    // --- ZK Proof API: Single-message proof generation & verification ---

    // Request for /api/prove
    #[derive(Debug, Deserialize)]
    struct ProveRequest { id: Option<u64>, sender_id: u64, content: String, timestamp: Option<u64> }

    #[derive(Debug, Serialize)]
    struct ProveResponse { message: zk_chat::Message, proof_base64: String, public_inputs: PublicInputs }

    // Request for /api/verify
    #[derive(Debug, Deserialize)]
    struct VerifyRequest { message: zk_chat::Message, proof_base64: String }

    #[derive(Debug, Serialize)]
    struct VerifyResponse { verified: bool, public_inputs: PublicInputs }

    // POST /api/prove
    let prove_route = warp::path!("api" / "prove")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(|req: ProveRequest| async move {
            tracing::info!("/api/prove request received: sender_id={}, id={:?}", req.sender_id, req.id);
            let id = req.id.unwrap_or(1);
            let timestamp = req.timestamp.unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            });
            let message = zk_chat::Message::new(id, req.sender_id, req.content, timestamp);
            let trace = build_trace(&[message.clone()]);
            let mut final_hash_elements = [winterfell::math::fields::f128::BaseElement::ZERO; 4];
            for i in 0..4 { final_hash_elements[i] = trace[4 + i][0]; }
            let final_hash = elements_to_hash(&final_hash_elements);
            let public_inputs = PublicInputs { initial_hash: [0u8; 32], final_hash, message_count: 1 };
            let mut prover = MessageProver::new();
            let proof_bytes = match prover.prove(&[message.clone()]) {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!("Proof generation failed: {:?}", e);
                    return Ok::<Box<dyn warp::Reply>, warp::Rejection>(Box::new(
                        warp::reply::with_status(
                            format!("proof generation failed: {e}"),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        )
                    ));
                }
            };
            let proof_b64 = general_purpose::STANDARD.encode(&proof_bytes);
            let response = ProveResponse { message, proof_base64: proof_b64, public_inputs };
            tracing::info!("/api/prove success for message id={}, sender_id={}", response.message.id, response.message.sender_id);
            Ok::<Box<dyn warp::Reply>, warp::Rejection>(Box::new(warp::reply::json(&response)))
        });

    // POST /api/verify
    let verify_route = warp::path!("api" / "verify")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(|req: VerifyRequest| async move {
            tracing::info!("/api/verify request received: message_id={}, sender_id={}", req.message.id, req.message.sender_id);
            // Hard fail early if client-supplied hash is invalid
            if !req.message.verify_hash() {
                tracing::error!("/api/verify invalid message hash: id={}, sender_id={}", req.message.id, req.message.sender_id);
                return Ok::<Box<dyn warp::Reply>, warp::Rejection>(Box::new(
                    warp::reply::with_status(
                        "invalid message hash",
                        warp::http::StatusCode::BAD_REQUEST,
                    )
                ));
            }
            let trace = build_trace(&[req.message.clone()]);
            let mut final_hash_elements = [winterfell::math::fields::f128::BaseElement::ZERO; 4];
            for i in 0..4 { final_hash_elements[i] = trace[4 + i][0]; }
            let final_hash = elements_to_hash(&final_hash_elements);
            let public_inputs = PublicInputs { initial_hash: [0u8; 32], final_hash, message_count: 1 };
            let proof_bytes = match general_purpose::STANDARD.decode(&req.proof_base64) {
                Ok(p) => p,
                Err(_) => {
                    tracing::error!("Proof base64 decode failed");
                    return Ok::<Box<dyn warp::Reply>, warp::Rejection>(Box::new(
                        warp::reply::with_status(
                            "invalid base64 proof",
                            warp::http::StatusCode::BAD_REQUEST,
                        )
                    ));
                }
            };
            let verified = verify_proof(&proof_bytes, public_inputs.clone()).is_ok();
            let response = VerifyResponse { verified, public_inputs };
            tracing::info!("/api/verify result: verified={}", verified);
            Ok::<Box<dyn warp::Reply>, warp::Rejection>(Box::new(warp::reply::json(&response)))
        });

    // POST /api/trace - build execution trace and public inputs for a single message without proof
    #[derive(Debug, Deserialize)]
    struct TraceRequest { sender_id: u64, content: String, timestamp: Option<u64>, id: Option<u64> }
    #[derive(Debug, Serialize)]
    struct TraceRow { step: usize, prev_hash: [String;4], chain_hash: [String;4], prev_timestamp: String, timestamp: String, sender_id: String }
    #[derive(Debug, Serialize)]
    struct TraceResponse { message: zk_chat::Message, public_inputs: PublicInputs, trace: Vec<TraceRow> }
    let trace_route = warp::path!("api" / "trace")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(|req: TraceRequest| async move {
            tracing::info!("/api/trace request received: sender_id={}, id={:?}", req.sender_id, req.id);
            let id = req.id.unwrap_or(1);
            let timestamp = req.timestamp.unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            });
            let message = zk_chat::Message::new(id, req.sender_id, req.content, timestamp);
            let trace = build_trace(&[message.clone()]);
            let mut final_hash_elements = [winterfell::math::fields::f128::BaseElement::ZERO; 4];
            for i in 0..4 { final_hash_elements[i] = trace[4 + i][0]; }
            let final_hash = elements_to_hash(&final_hash_elements);
            let public_inputs = PublicInputs { initial_hash: [0u8; 32], final_hash, message_count: 1 };
            // Build JSON-friendly trace rows (only the actual message step = 0)
            let mut rows = Vec::new();
            let step = 0usize;
            let mut prev_hash = [String::new(), String::new(), String::new(), String::new()];
            let mut chain_hash = [String::new(), String::new(), String::new(), String::new()];
            for i in 0..4 { prev_hash[i] = format!("{}", trace[i][step]); chain_hash[i] = format!("{}", trace[4 + i][step]); }
            let row = TraceRow { step, prev_hash, chain_hash, prev_timestamp: format!("{}", trace[8][step]), timestamp: format!("{}", trace[9][step]), sender_id: format!("{}", trace[10][step]) };
            rows.push(row);
            let response = TraceResponse { message, public_inputs, trace: rows };
            tracing::info!("/api/trace success for message id={}, sender_id={}", response.message.id, response.message.sender_id);
            Ok::<Box<dyn warp::Reply>, warp::Rejection>(Box::new(warp::reply::json(&response)))
        });

    // --- Test Harness API (list & run tests) ---
    #[derive(Serialize)]
    struct ListedTest { name: &'static str, category: &'static str, description: &'static str }
    #[derive(Serialize)]
    struct RunTestResponse { result: test_harness::TestResult }

    let tests_list_route = warp::path!("api" / "tests" / "list")
        .and(warp::get())
        .map(|| {
            let tests: Vec<ListedTest> = test_harness::all_tests().into_iter()
                .map(|t| ListedTest { name: t.name, category: t.category, description: t.description })
                .collect();
            warp::reply::json(&tests)
        });

    let tests_run_route = warp::path!("api" / "tests" / "run")
        .and(warp::get())
        .and(warp::query::<HashMap<String,String>>())
        .and_then(|q: HashMap<String,String>| async move {
            if let Some(name) = q.get("name") {
                if let Some(result) = test_harness::run_named(name) {
                    return Ok::<Box<dyn warp::Reply>, warp::Rejection>(Box::new(warp::reply::json(&RunTestResponse { result })));
                }
                return Ok(Box::new(warp::reply::with_status("unknown test", warp::http::StatusCode::NOT_FOUND)));
            }
            let results = test_harness::run_all();
            Ok(Box::new(warp::reply::json(&results)))
        });

    // Root redirect to index.html
    let root = warp::path::end()
        .map(|| warp::redirect::redirect(warp::http::Uri::from_static("/index.html")));

    // Combine routes
    let routes = root
        .or(trace_route)
        .or(prove_route)
        .or(verify_route)
        .or(tests_list_route)
        .or(tests_run_route)
        .or(websocket)
        .or(static_files);

    info!("🚀 Server starting on http://127.0.0.1:8081");
    info!("📱 Open your browser and navigate to http://127.0.0.1:8081");
    info!("🔐 Each message will be verified using ZK-STARK proofs");
    
    warp::serve(routes)
        .run(([127, 0, 0, 1], 8081))
        .await;

    Ok(())
}

async fn handle_websocket(websocket: warp::ws::WebSocket) {
    use futures_util::{SinkExt, StreamExt};
    use zk_chat::websocket::ProtocolMessage;
    use std::{
        sync::{Arc, Mutex},
    };
    use once_cell::sync::Lazy;
    use tokio::sync::broadcast;

    // Global state with broadcast channel for real-time updates
    static GLOBAL_STATE: Lazy<Arc<Mutex<GlobalState>>> = Lazy::new(|| {
        Arc::new(Mutex::new(GlobalState::new()))
    });

    static BROADCAST_TX: Lazy<broadcast::Sender<String>> = Lazy::new(|| {
        let (tx, _) = broadcast::channel(100);
        tx
    });

    let (mut ws_sender, mut ws_receiver) = websocket.split();
    let mut user_id: Option<u64> = None;
    let mut broadcast_rx = BROADCAST_TX.subscribe();

    // Use a channel to send messages to the WebSocket sender
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    
    // Spawn task to handle outgoing messages
    tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            let _ = ws_sender.send(warp::ws::Message::text(message)).await;
        }
    });
    
    // Spawn task to handle broadcasts from other clients
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        while let Ok(message) = broadcast_rx.recv().await {
            let _ = tx_clone.send(message);
        }
    });

    while let Some(result) = ws_receiver.next().await {
        match result {
            Ok(msg) => {
                if msg.is_text() {
                    let text = msg.to_str().unwrap();
                    match serde_json::from_str::<ProtocolMessage>(text) {
                        Ok(protocol_msg) => {
                            let response = handle_protocol_message(protocol_msg, &*GLOBAL_STATE, &mut user_id, &BROADCAST_TX).await;
                            
                            if let Ok(Some(response_msg)) = response {
                                if let Ok(response_json) = serde_json::to_string(&response_msg) {
                                    let _ = tx.send(response_json);
                                }
                            }
                        }
                        Err(e) => {
                            info!("Failed to parse message: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                info!("WebSocket error: {}", e);
                break;
            }
        }
    }

    // Clean up user on disconnect
    if let Some(uid) = user_id {
        let mut state_lock = match GLOBAL_STATE.lock() {
            Ok(lock) => lock,
            Err(poisoned) => {
                warn!("GLOBAL_STATE mutex was poisoned during cleanup, recovering");
                poisoned.into_inner()
            }
        };
        state_lock.users.remove(&uid);
        info!("User {} disconnected", uid);
        
        // Broadcast user list update
        let users: Vec<(u64, String)> = state_lock
            .users
            .iter()
            .map(|(&id, name)| (id, name.clone()))
            .collect();
        
        if let Ok(update_msg) = serde_json::to_string(&ProtocolMessage::UserListUpdate { users }) {
            let _ = BROADCAST_TX.send(update_msg);
        }
    }
}

#[derive(Debug)]
struct GlobalState {
    users: std::collections::HashMap<u64, String>,
    message_chain: zk_chat::zk::MessageChain,
    next_global_id: u64,
    per_sender_local: std::collections::HashMap<u64, u64>,
    // Removed prover/proof_options stored here; per-message instantiated
}

impl GlobalState {
    fn new() -> Self {
        Self {
            users: std::collections::HashMap::new(),
            message_chain: zk_chat::zk::MessageChain::new(),
            next_global_id: 1,
            per_sender_local: std::collections::HashMap::new(),
            // Prover instantiated on demand
        }
    }
}

async fn handle_protocol_message(
    msg: zk_chat::websocket::ProtocolMessage,
    state: &std::sync::Arc<std::sync::Mutex<GlobalState>>,
    user_id: &mut Option<u64>,
    broadcast_tx: &tokio::sync::broadcast::Sender<String>,
) -> zk_chat::Result<Option<zk_chat::websocket::ProtocolMessage>> {
    use zk_chat::{
        websocket::ProtocolMessage,
        ZkChatError,
    };

    match msg {
        ProtocolMessage::Join { user_id: uid, username } => {
            let mut state_lock = state.lock().unwrap();
            state_lock.users.insert(uid, username.clone());
            *user_id = Some(uid);

            info!("✅ User {} ({}) joined the chat", username, uid);

            let users: Vec<(u64, String)> = state_lock
                .users
                .iter()
                .map(|(&id, name)| (id, name.clone()))
                .collect();

            // Broadcast user list update to all clients
            if let Ok(broadcast_msg) = serde_json::to_string(&ProtocolMessage::UserListUpdate { users: users.clone() }) {
                let _ = broadcast_tx.send(broadcast_msg);
            }

            Ok(Some(ProtocolMessage::UserListUpdate { users }))
        }

        ProtocolMessage::SendMessage { message, proof: _ } => {
            let uid = user_id.ok_or(ZkChatError::InvalidSender)?;
            
            if message.sender_id != uid {
                return Err(ZkChatError::InvalidSender);
            }

            let mut state_lock = match state.lock() {
                Ok(lock) => lock,
                Err(poisoned) => {
                    warn!("State mutex was poisoned, recovering");
                    poisoned.into_inner()
                }
            };

            // Assign global id and derive per-sender local id (ignore client-provided id)
            let global_id = state_lock.next_global_id;
            state_lock.next_global_id += 1;
            let local_entry = state_lock.per_sender_local.entry(uid).or_insert(0);
            *local_entry += 1;
            let local_id = *local_entry;
            // We use global_id for ZK hashing, local_id only for display; existing Message has single id field so we store global id.
            
            // Create message with server-assigned global id (ignoring client id)
            let server_message = zk_chat::Message::new(global_id, message.sender_id, format!("{}", message.content.clone()), message.timestamp);
            
            // CRITICAL: Build proof with ALL messages in chain INCLUDING new one
            let messages_for_proof = {
                let mut msgs = state_lock.message_chain.messages.clone();
                msgs.push(server_message.clone());
                msgs
            };
            
            let mut prover = zk_chat::zk::prover::MessageProver::new();
            
            // Generate ZK-STARK proof for complete chain
            let proof_result = prover.prove(&messages_for_proof);
            
            let verified = match proof_result {
                Ok(proof) => {
                    // Verify the generated proof
                    let mut temp_chain = state_lock.message_chain.clone();
                    match temp_chain.add_message(server_message.clone()) {
                        Ok(_) => {
                            let pub_inputs = zk_chat::zk::air::PublicInputs {
                                initial_hash: [0u8; 32], // Empty initial hash
                                final_hash: temp_chain.chain_hash,
                                message_count: temp_chain.len(),
                            };
                            
                            match zk_chat::zk::prover::verify_proof(&proof, pub_inputs) {
                                Ok(_) => {
                                    // Also verify hash consistency
                                    server_message.verify_hash()
                                },
                                Err(e) => {
                                    info!("❌ ZK proof verification failed: {:?}", e);
                                    false
                                }
                            }
                        },
                        Err(e) => {
                            info!("❌ Failed to add message to chain for verification: {:?}", e);
                            false
                        }
                    }
                },
                Err(e) => {
                    info!("❌ ZK proof generation failed: {:?}", e);
                    false
                }
            };
            
            if verified {
                info!("✅ Message verified with ZK-STARK proof from user {}: {}", uid, server_message.content);
            } else {
                info!("❌ ZK-STARK proof verification failed for user {}: {}", uid, server_message.content);
            };
            
            if verified {
                match state_lock.message_chain.add_message(server_message.clone()) {
                    Ok(_) => {}
                    Err(e) => {
                        info!("❌ Failed to add message to chain: {}", e);
                    }
                }
            }

            // Broadcast server-computed message to all clients
            let broadcast_message = ProtocolMessage::MessageBroadcast {
                message: server_message,
                verified,
                local_id,
            };
            
            if let Ok(broadcast_json) = serde_json::to_string(&broadcast_message) {
                let _ = broadcast_tx.send(broadcast_json);
            }

            Ok(None) // Don't send individual response since we broadcast
        }

        ProtocolMessage::Ping => Ok(Some(ProtocolMessage::Pong)),
        _ => Ok(None),
    }
}

// Removed unused local compute_chain_hash; chain hashing is centralized in zk::MessageChain