use winterfell::math::fields::f128::BaseElement;
use winterfell::math::{FieldElement, StarkField};

/// Pack message content bytes into exactly 4 BaseElements (8 bytes per element, little-endian).
pub fn pack_content(content: &str) -> [BaseElement; 4] {
    let bytes = content.as_bytes();
    let mut elements = [BaseElement::ZERO; 4];
    for (chunk_index, chunk) in bytes.chunks(8).enumerate().take(4) {
        let mut value = 0u64;
        for (i, &b) in chunk.iter().enumerate() { value |= (b as u64) << (i * 8); }
        elements[chunk_index] = BaseElement::from(value);
    }
    elements
}

/// Convert a 32-byte hash (4 * 8 bytes) into 4 BaseElements (little-endian u64 chunks).
pub fn hash_bytes_to_elements(hash: &[u8;32]) -> [BaseElement;4] {
    let mut out = [BaseElement::ZERO;4];
    for (i, chunk) in hash.chunks(8).enumerate() { out[i] = BaseElement::from(u64::from_le_bytes(chunk.try_into().unwrap())); }
    out
}

/// Truncate field element to lower 64 bits (matching elements_to_hash encoding).
pub fn truncate_element(e: BaseElement) -> BaseElement { BaseElement::from((e.as_int() % (1u128 << 64)) as u64) }

/// Apply truncation to an array of 4 elements.
pub fn truncate_elements(arr: &[BaseElement;4]) -> [BaseElement;4] { [truncate_element(arr[0]), truncate_element(arr[1]), truncate_element(arr[2]), truncate_element(arr[3])] }

/// Build per-message hash elements from message fields (id, sender, timestamp, content[4]).
pub fn message_hash_inputs(id: u64, sender: u64, timestamp: u64, content: &str) -> Vec<BaseElement> {
    let mut v = Vec::with_capacity(7);
    v.push(BaseElement::from(id));
    v.push(BaseElement::from(sender));
    v.push(BaseElement::from(timestamp));
    v.extend_from_slice(&pack_content(content));
    v
}
