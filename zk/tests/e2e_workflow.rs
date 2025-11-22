use zk_chat::{Message, zk::{MessageChain, air::{PublicInputs, build_trace}, prover::{MessageProver, verify_proof}, elements_to_hash}};
use winterfell::math::{fields::f128::BaseElement, FieldElement};

#[test]
fn e2e_three_message_chain() {
    let mut chain = MessageChain::new();
    for i in 0..3 {
        chain.add_message(Message::new(i+1, 10+i as u64, format!("msg{i}"), 2000+i as u64)).unwrap();
    }
    assert_eq!(chain.len(), 3);

    // Prove last message standalone
    let last = chain.messages.last().unwrap().clone();
    let trace = build_trace(&[last.clone()]);
    let mut final_hash_elements = [BaseElement::ZERO; 4];
    for i in 0..4 { final_hash_elements[i] = trace[4 + i][0]; }
    let final_hash = elements_to_hash(&final_hash_elements);
    let pub_inputs = PublicInputs { initial_hash: [0u8;32], final_hash, message_count: 1 };
    let mut prover = MessageProver::new();
    let proof = prover.prove(&[last.clone()]).unwrap();
    verify_proof(&proof, pub_inputs).unwrap();
}
