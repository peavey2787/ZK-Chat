use zk_chat::{Message, zk::air::{build_trace, PublicInputs}, zk::{elements_to_hash, hash_to_elements}};
use winterfell::math::fields::f128::BaseElement;
use winterfell::math::FieldElement;

fn main() {
    // Single message test
    let msg = Message::new(1, 42, "hello".to_string(), 1);
    let messages = vec![msg.clone()];
    let trace = build_trace(&messages);

    println!("Trace length: {} (cols: {})", trace[0].len(), trace.len());

    // Print first 8 columns for actual message step 0
    println!("Row 0 prev_chain_hash (0..3): {:?}", &trace[0..4].iter().map(|c| c[0]).collect::<Vec<_>>());
    println!("Row 0 chain_hash (4..7): {:?}", &trace[4..8].iter().map(|c| c[0]).collect::<Vec<_>>());

    // Derive expected final hash from trace row 0 columns 4..7
    let mut final_hash_elements = [BaseElement::ZERO; 4];
    for i in 0..4 { final_hash_elements[i] = trace[4 + i][0]; }
    let final_hash = elements_to_hash(&final_hash_elements);

    let _pub_inputs = PublicInputs { initial_hash: [0u8;32], final_hash, message_count: 1 };
    println!("PublicInputs final_hash bytes: {}", hex::encode(final_hash));
    println!("PublicInputs final_hash elements: {:?}", hash_to_elements(&final_hash));
}
