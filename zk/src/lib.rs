pub mod zk;
pub mod websocket;
pub mod test_harness;

use serde::{Deserialize, Serialize};
use std::fmt;

/// A message in the chat system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Message {
    pub id: u64,
    pub sender_id: u64,
    pub content: String,
    pub timestamp: u64,
    #[serde(with = "hex_serde")]
    pub hash: [u8; 32],
}

impl Message {
    /// Create a new message with hash
    pub fn new(id: u64, sender_id: u64, content: String, timestamp: u64) -> Self {
        let mut message = Self {
            id,
            sender_id,
            content,
            timestamp,
            hash: [0u8; 32],
        };
        // Use ZK-friendly hash for consistency with proof system
        message.hash = message.compute_zk_hash();
        message
    }
    
    /// Create a message with a pre-computed hash (for deserialization)
    pub fn with_hash(id: u64, sender_id: u64, content: String, timestamp: u64, hash: [u8; 32]) -> Self {
        Self {
            id,
            sender_id,
            content,
            timestamp,
            hash,
        }
    }

    /// Compute the cryptographic hash of this message (for external verification)
    pub fn compute_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let data = format!("{}-{}-{}-{}", self.id, self.sender_id, self.content, self.timestamp);
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hasher.finalize().into()
    }
    
    /// Compute ZK-friendly hash for STARK verification  
    /// INDUSTRY PRODUCTION STANDARD: Uses authentic Poseidon with cryptographically secure parameters
    /// Delegates to centralized zk::zk_hash for consistency across codebase
    pub fn compute_zk_hash(&self) -> [u8; 32] {
        use winterfell::math::fields::f128::BaseElement;
        
        // Convert message data to field elements
        let id = BaseElement::from(self.id);
        let sender = BaseElement::from(self.sender_id);
        let timestamp = BaseElement::from(self.timestamp);
        
        let content_elements = zk::hash::pack_content(&self.content);
        let mut all_inputs = vec![id, sender, timestamp];
        all_inputs.extend_from_slice(&content_elements);
        
        // Use centralized production ZK hash function
        let hash_result = zk::zk_hash(&all_inputs);
        
        // Convert to bytes
        zk::elements_to_hash(&hash_result)
    }
    
    // Removed unused alternative hash helpers; centralized hashing lives in `zk` module

    /// Verify the hash of this message using ZK-friendly hash
    pub fn verify_hash(&self) -> bool {
        // Compute ZK Poseidon hash and compare directly. No legacy SHA debug.
        self.compute_zk_hash() == self.hash
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Message {{ id: {}, sender: {}, content: \"{}\", timestamp: {}, hash: {} }}",
            self.id,
            self.sender_id,
            self.content,
            self.timestamp,
            hex::encode(self.hash)
        )
    }
}

/// Error types for the ZK chat system
#[derive(thiserror::Error, Debug)]
pub enum ZkChatError {
    #[error("Invalid message hash")]
    InvalidMessageHash,
    #[error("Invalid timestamp sequence")]
    InvalidTimestamp,
        #[error("Duplicate message ID - replay attack detected")]
        DuplicateMessageId,
    #[error("Invalid sender ID")]
    InvalidSender,
    #[error("Proof verification failed")]
    ProofVerificationFailed,
    #[error("Proof generation error: {0}")]
    ProofGeneration(String),
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tungstenite::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ZkChatError>;

// Helper module for hex serialization of byte arrays
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    
    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!("Expected 32 bytes, got {}", bytes.len())));
        }
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes);
        Ok(result)
    }
}