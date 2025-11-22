use crate::{Message, Result, ZkChatError};
use serde::{Deserialize, Serialize};

/// Protocol messages for WebSocket communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolMessage {
    /// Client joins the chat room
    Join { user_id: u64, username: String },
    
    /// Client leaves the chat room
    Leave { user_id: u64 },
    
    /// Client sends a message with ZK proof
    SendMessage {
        message: Message,
        proof: Vec<u8>, // Serialized StarkProof
    },
    
    /// Server broadcasts a verified message
    MessageBroadcast {
        message: Message,
        verified: bool,
        // Per-sender local sequential ID (starts at 1 per sender)
        local_id: u64,
    },
    
    /// Server sends user list update
    UserListUpdate {
        users: Vec<(u64, String)>,
    },
    
    /// Error message
    Error {
        code: u32,
        message: String,
    },
    
    /// Keep-alive ping
    Ping,
    
    /// Keep-alive pong
    Pong,
}

impl ProtocolMessage {
    /// Serialize to JSON bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(ZkChatError::from)
    }

    /// Deserialize from JSON bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).map_err(ZkChatError::from)
    }

    /// Create an error message
    pub fn error(code: u32, message: impl Into<String>) -> Self {
        Self::Error {
            code,
            message: message.into(),
        }
    }
}

/// Error codes for protocol messages
pub mod error_codes {
    pub const INVALID_MESSAGE_HASH: u32 = 1001;
    pub const INVALID_TIMESTAMP: u32 = 1002;
    pub const INVALID_SENDER: u32 = 1003;
    pub const PROOF_VERIFICATION_FAILED: u32 = 1004;
    pub const UNAUTHORIZED: u32 = 1005;
    pub const RATE_LIMITED: u32 = 1006;
    pub const INTERNAL_ERROR: u32 = 5000;
}

/// Convert ZkChatError to protocol error message
impl From<ZkChatError> for ProtocolMessage {
    fn from(error: ZkChatError) -> Self {
        match error {
            ZkChatError::InvalidMessageHash => {
                Self::error(error_codes::INVALID_MESSAGE_HASH, "Invalid message hash")
            }
            ZkChatError::InvalidTimestamp => {
                Self::error(error_codes::INVALID_TIMESTAMP, "Invalid timestamp sequence")
            }
            ZkChatError::InvalidSender => {
                Self::error(error_codes::INVALID_SENDER, "Invalid sender ID")
            }
            ZkChatError::ProofVerificationFailed => {
                Self::error(error_codes::PROOF_VERIFICATION_FAILED, "Proof verification failed")
            }
            _ => Self::error(error_codes::INTERNAL_ERROR, "Internal server error"),
        }
    }
}