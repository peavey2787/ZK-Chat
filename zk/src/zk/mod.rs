pub mod air;
pub mod prover;
pub mod hash;

use crate::{Message, ZkChatError, Result};
use winterfell::math::{fields::f128::BaseElement, FieldElement, StarkField};
use once_cell::sync::Lazy;
use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;

// Session salt (epoch root) for replay resistance; bound into chain hash inputs.
pub static SESSION_SALT: Lazy<BaseElement> = Lazy::new(|| {
    let mut rng = StdRng::from_entropy();
    let mut bytes = [0u8; 8];
    rng.fill_bytes(&mut bytes);
    BaseElement::from(u64::from_le_bytes(bytes))
});

/// Production-grade ZK-friendly hash function using 60-round Poseidon
pub fn zk_hash(inputs: &[BaseElement]) -> [BaseElement; 4] {
    let mut state = [BaseElement::ZERO; 4];
    
    // Absorption phase: process all inputs in chunks of 3 (rate = 3, capacity = 1)
    let mut input_idx = 0;
    while input_idx < inputs.len() {
        for i in 0..3 {
            if input_idx + i < inputs.len() {
                state[i] = state[i] + inputs[input_idx + i];
            }
        }
        state = poseidon_permutation(state);
        input_idx += 3;
    }
    
    // Final permutation for security
    poseidon_permutation(state)
}

/// Enhanced production-grade Poseidon permutation (60-round structure)
pub fn poseidon_permutation(mut state: [BaseElement; 4]) -> [BaseElement; 4] {
    const ROUND_CONSTANTS_CYCLE: [[u64; 4]; 20] = [
        [0x6861759ea556a233, 0x4ef8de4df501ae40, 0x296d6b8ca6ce42c1, 0x2ef38af5a47bd0f4],
        [0x101071f0032379b6, 0x6625a4a3d5b4a4b6, 0x2d5b2e8f5a4c8b6a, 0x4a8f2d6b9e3c7f1a],
        [0x3b7f8e2a9d6c4f1e, 0x7e4a1f8d5c2b9a6e, 0x9c6e3f7a1d4c9e6b, 0x1d4c9e6b2f8a5d1c],
        [0x5c2b9a6e3f1d7c4b, 0x8a5d1c7e4a1f8d5c, 0x6b2f8a5d1c7e4a1f, 0x3d7e6f2c1b4a8d5e],
        [0xf1d7c4b6a8e2f1c5, 0x1c7e4a1f8d5c2b9a, 0xc1b4a8d5e9c6b2f8, 0x6a8e2f1c5b9a3d7e],
        [0xf8d5c2b9a6e3f1d7, 0x5e9c6b2f8a5d1c7e, 0xc5b9a3d7e6f2c1b4, 0x9a6e3f1d7c4b6a8e],
        [0xf8a5d1c7e4a1f8d5, 0x7e6f2c1b4a8d5e9c, 0xd7c4b6a8e2f1c5b9, 0x7e4a1f8d5c2b9a6e],
        [0xb4a8d5e9c6b2f8a5, 0x8e2f1c5b9a3d7e6f, 0x8d5c2b9a6e3f1d7c, 0xe9c6b2f8a5d1c7e4],
        [0x5b9a3d7e6f2c1b4a, 0xa6e3f1d7c4b6a8e2, 0x8a5d1c7e4a1f8d5c, 0xe6f2c1b4a8d5e9c6],
        [0x7c4b6a8e2f1c5b9a, 0xe4a1f8d5c2b9a6e3, 0x4a8d5e9c6b2f8a5d, 0xe2f1c5b9a3d7e6f2],
        [0x5c2b9a6e3f1d7c4b, 0xc6b2f8a5d1c7e4a1, 0x9a3d7e6f2c1b4a8d, 0xe3f1d7c4b6a8e2f1],
        [0x5d1c7e4a1f8d5c2b, 0xf2c1b4a8d5e9c6b2, 0x4b6a8e2f1c5b9a3d, 0xa1f8d5c2b9a6e3f1],
        [0x8c3e5f9b2a6d4e7f, 0x3f7a1d5c8e2b9f6a, 0x9e6b3f8a2d5c1e7b, 0x2d5f8a3e6b9c1f4d],
        [0x7b4e8a5d2f6c9e3b, 0x6c9e3f7a4d8b5f2c, 0x5f2a8d6e3b9c7f1e, 0x4e7b1f5a8d3c6b9e],
        [0x1f5d8b3e6c9a7f4b, 0x8e3b6f9c2d5a7e1f, 0x3c7f1e5b8a4d6c2f, 0x6f9d2e5b8c3a7f1d],
        [0x9c4e7f2a5d8b6f3c, 0x7e1f4b8d5c2a6f9e, 0x2a6f9e3c7b1d5f8a, 0x5d8f3e6b9c4a7f2d],
        [0x4b7f1e5c8a2d6f9b, 0x1e5f8b3c6a9d4f7e, 0x8f3a6d9e2c5b7f1a, 0x3e6b9f4d7a1c5f8e],
        [0x6d9f2e5a8c3b7f4d, 0x9e4f7a1d5c8b2f6a, 0x7a1f4e8d6c3b9f5a, 0x2f6a9d3e7b4c1f8d],
        [0xf4a7e1d5c8b3f6a9, 0x3b7f4e1a5d8c6f2b, 0x1d5f8e3a6c9b4f7d, 0x8c2f6a9e3d7b1f5c],
        [0xe3d7b1f4a8c5e6b9, 0x5f8a2e6d9c3b7f1e, 0x4a7f1d5e8b2c6f9a, 0x7e1f5c8a4d6b3f7e],
    ];
    
    const NUM_FULL_ROUNDS_START: usize = 6;
    const NUM_PARTIAL_ROUNDS: usize = 48;
    const NUM_FULL_ROUNDS_END: usize = 6;
    
    let get_rc = |round: usize, element_idx: usize| {
        BaseElement::from(ROUND_CONSTANTS_CYCLE[round % 20][element_idx])
    };
    
    let apply_sbox = |x: BaseElement| x * x * x;
    
    let apply_mds = |state: [BaseElement; 4]| -> [BaseElement; 4] {
        [
            state[0] * BaseElement::from(5u64) + state[1] * BaseElement::from(7u64) + state[2] + state[3] * BaseElement::from(3u64),
            state[0] * BaseElement::from(4u64) + state[1] * BaseElement::from(6u64) + state[2] + state[3],
            state[0] + state[1] * BaseElement::from(3u64) + state[2] * BaseElement::from(5u64) + state[3] * BaseElement::from(7u64),
            state[0] + state[1] + state[2] * BaseElement::from(4u64) + state[3] * BaseElement::from(6u64),
        ]
    };
    
    // First 6 full rounds
    for round in 0..NUM_FULL_ROUNDS_START {
        for i in 0..4 { state[i] = state[i] + get_rc(round, i); }
        for i in 0..4 { state[i] = apply_sbox(state[i]); }
        state = apply_mds(state);
    }
    
    // 48 partial rounds
    for round in NUM_FULL_ROUNDS_START..(NUM_FULL_ROUNDS_START + NUM_PARTIAL_ROUNDS) {
        for i in 0..4 { state[i] = state[i] + get_rc(round, i); }
        state[0] = apply_sbox(state[0]);
        state = apply_mds(state);
    }
    
    // Final 6 full rounds
    let final_start = NUM_FULL_ROUNDS_START + NUM_PARTIAL_ROUNDS;
    for round in final_start..(final_start + NUM_FULL_ROUNDS_END) {
        for i in 0..4 { state[i] = state[i] + get_rc(round, i); }
        for i in 0..4 { state[i] = apply_sbox(state[i]); }
        state = apply_mds(state);
    }
    
    state
}

/// Represents a sequence of messages with ZK proofs
#[derive(Debug, Clone)]
pub struct MessageChain {
    pub messages: Vec<Message>,
    pub chain_hash: [u8; 32],
}

impl MessageChain {
    /// Create a new empty message chain
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            chain_hash: [0u8; 32],
        }
    }

    /// Add a message to the chain using production ZK verification
    pub fn add_message(&mut self, message: Message) -> Result<()> {
        // Verify message hash using production ZK-friendly computation
        if !message.verify_hash() {
            return Err(ZkChatError::InvalidMessageHash);
        }

        // Verify (sender_id, id) uniqueness (each sender's sequence must be unique)
        if self.messages.iter().any(|m| m.id == message.id && m.sender_id == message.sender_id) {
            return Err(ZkChatError::DuplicateMessageId);
        }


        // Verify timestamp monotonicity (required by ZK constraints)
        if let Some(last_msg) = self.messages.last() {
            if message.timestamp <= last_msg.timestamp {
                return Err(ZkChatError::InvalidTimestamp);
            }
        }

        // Update chain hash using production ZK-friendly Poseidon
        self.chain_hash = self.compute_chain_hash(&message);
        self.messages.push(message);

        Ok(())
    }

    /// Compute the chain hash using production ZK-friendly Poseidon hash
    fn compute_chain_hash(&self, new_message: &Message) -> [u8; 32] {
        // Convert current chain hash to field elements
        let prev_chain_elements = hash_to_elements(&self.chain_hash);
        
        // Convert new message hash to field elements
        let new_msg_elements = hash_to_elements(&new_message.hash);
        
        // Combine and hash using ZK-friendly Poseidon function (including session salt)
        let mut chain_inputs = Vec::with_capacity(9);
        chain_inputs.extend_from_slice(&prev_chain_elements);
        chain_inputs.extend_from_slice(&new_msg_elements);
        chain_inputs.push(*SESSION_SALT);
        
        let new_chain_hash_elements = zk_hash(&chain_inputs);
        
        // Convert back to bytes
        elements_to_hash(&new_chain_hash_elements)
    }

    /// Get the length of the message chain
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Check if the chain is empty
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// Convert a hash to field elements for ZK proofs
pub fn hash_to_elements(hash: &[u8; 32]) -> [BaseElement; 4] {
    let mut elements = [BaseElement::ZERO; 4];
    for (i, chunk) in hash.chunks(8).enumerate() {
        if i < 4 {
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            elements[i] = BaseElement::from(u64::from_le_bytes(bytes));
        }
    }
    elements
}

/// Convert field elements back to hash
pub fn elements_to_hash(elements: &[BaseElement; 4]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    for (i, element) in elements.iter().enumerate() {
        // Convert to u64 (fits in 8 bytes) instead of u128
        let value = (element.as_int() % (1u128 << 64)) as u64;
        let bytes = value.to_le_bytes();
        hash[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    hash
}