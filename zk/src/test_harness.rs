use crate::{Message, zk::{MessageChain, air::{PublicInputs, build_trace, MessageAir}, prover::{MessageProver, verify_proof}, elements_to_hash}};
use serde::Serialize;
use std::time::Instant;
use winterfell::{math::{fields::f128::BaseElement, FieldElement}, Air};

#[derive(Debug, Serialize, Clone)]
pub struct TestResult {
    pub name: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub passed: bool,
    pub error: Option<String>,
    pub duration_ms: u128,
}

pub type TestFn = fn() -> Result<(), String>;

#[derive(Clone)]
pub struct TestCase {
    pub name: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub func: TestFn,
}

fn unit_zk_hash_deterministic() -> Result<(), String> {
    let inputs: Vec<BaseElement> = vec![1u64,2,3,4,5].into_iter().map(BaseElement::from).collect();
    let h1 = crate::zk::zk_hash(&inputs);
    let h2 = crate::zk::zk_hash(&inputs);
    if h1 != h2 { return Err("Poseidon hash not deterministic".into()); }
    Ok(())
}

fn unit_message_hash_consistency() -> Result<(), String> {
    let m = Message::new(1, 10, "hello".to_string(), 1000);
    if !m.verify_hash() { return Err("Message hash failed verification".into()); }
    Ok(())
}

fn unit_chain_updates() -> Result<(), String> {
    let mut chain = MessageChain::new();
    let m1 = Message::new(1, 10, "a".into(), 1000);
    chain.add_message(m1.clone()).map_err(|e| e.to_string())?;
    let prev_hash = chain.chain_hash;
    let m2 = Message::new(2, 11, "b".into(), 1001);
    chain.add_message(m2.clone()).map_err(|e| e.to_string())?;
    if chain.chain_hash == prev_hash { return Err("Chain hash did not change after second message".into()); }
    Ok(())
}

fn integration_prover_single_message() -> Result<(), String> {
    let m = Message::new(1, 42, "zk".into(), 1000);
    let trace = build_trace(&[m.clone()]);
    let mut final_hash_elements = [winterfell::math::fields::f128::BaseElement::ZERO; 4];
    for i in 0..4 { final_hash_elements[i] = trace[4 + i][0]; }
    let final_hash = elements_to_hash(&final_hash_elements);
    let pub_inputs = PublicInputs { initial_hash: [0u8;32], final_hash, message_count: 1 };
    let mut prover = MessageProver::new();
    let proof = prover.prove(&[m.clone()]).map_err(|e| format!("Proof generation failed: {e}"))?;
    verify_proof(&proof, pub_inputs).map_err(|e| format!("Proof verification failed: {e}"))?;
    Ok(())
}

fn integration_air_assertions() -> Result<(), String> {
    use winterfell::{ProofOptions, FieldExtension};
    use winterfell::TraceInfo;
    let m = Message::new(1, 1, "x".into(), 1000);
    let trace = build_trace(&[m.clone()]);
    let mut final_hash_elements = [BaseElement::ZERO; 4];
    for i in 0..4 { final_hash_elements[i] = trace[4 + i][0]; }
    let final_hash = elements_to_hash(&final_hash_elements);
    let pub_inputs = PublicInputs { initial_hash: [0u8;32], final_hash, message_count: 1 };
    let trace_info = TraceInfo::new(crate::zk::air::TRACE_WIDTH, 8);
    let options = ProofOptions::new(32,8,0, FieldExtension::None,8,31);
    let air = MessageAir::new(trace_info, pub_inputs.clone(), options);
    let assertions = air.get_assertions();
    if assertions.len() != 8 { return Err(format!("Expected 8 assertions, got {}", assertions.len())); }
    Ok(())
}

fn e2e_three_message_chain() -> Result<(), String> {
    let mut chain = MessageChain::new();
    for i in 0..3 { chain.add_message(Message::new(i+1, 50+i as u64, format!("msg{i}"), 2000+i as u64)).map_err(|e| e.to_string())?; }
    if chain.len() != 3 { return Err("Chain length mismatch".into()); }
    Ok(())
}

fn negative_duplicate_id_same_sender() -> Result<(), String> {
    // Expect rejection when same sender reuses the same local id
    let mut chain = MessageChain::new();
    let m1 = Message::new(1, 1, "a".into(), 1000);
    chain.add_message(m1.clone()).map_err(|e| e.to_string())?;
    let m2 = Message::new(1, 1, "b".into(), 1001);
    match chain.add_message(m2) { Ok(_) => Err("Duplicate (sender,id) accepted".into()), Err(_) => Ok(()) }
}

fn positive_same_id_different_senders_allowed() -> Result<(), String> {
    // Same numeric id but different senders should succeed
    let mut chain = MessageChain::new();
    let a1 = Message::new(1, 10, "u10 a".into(), 1000);
    chain.add_message(a1).map_err(|e| e.to_string())?;
    let b1 = Message::new(1, 20, "u20 b".into(), 1001);
    chain.add_message(b1).map_err(|e| e.to_string())?;
    Ok(())
}

fn negative_non_monotonic_timestamp() -> Result<(), String> {
    let mut chain = MessageChain::new();
    let m1 = Message::new(1, 1, "a".into(), 1000);
    chain.add_message(m1.clone()).map_err(|e| e.to_string())?;
    let m2 = Message::new(2, 1, "b".into(), 1000); // same timestamp
    match chain.add_message(m2) { Ok(_) => Err("Non-monotonic timestamp accepted".into()), Err(_) => Ok(()) }
}

fn negative_tampered_hash() -> Result<(), String> {
    let mut msg = Message::new(1, 1, "tamper".into(), 1000);
    msg.hash[0] ^= 0xFF; // corrupt
    if msg.verify_hash() { return Err("Tampered hash passed verification".into()); }
    Ok(())
}

pub fn all_tests() -> Vec<TestCase> {
    vec![
        TestCase { name: "unit_zk_hash_deterministic", category: "unit", description: "Poseidon hash produces deterministic output", func: unit_zk_hash_deterministic },
        TestCase { name: "unit_message_hash_consistency", category: "unit", description: "Message hash matches recomputation", func: unit_message_hash_consistency },
        TestCase { name: "unit_chain_updates", category: "unit", description: "Chain hash updates when adding messages", func: unit_chain_updates },
        TestCase { name: "integration_prover_single_message", category: "integration", description: "Prover generates & verifies proof for single message", func: integration_prover_single_message },
        TestCase { name: "integration_air_assertions", category: "integration", description: "AIR exposes correct number of boundary assertions", func: integration_air_assertions },
        TestCase { name: "e2e_three_message_chain", category: "e2e", description: "End-to-end adding three messages succeeds", func: e2e_three_message_chain },
        TestCase { name: "negative_duplicate_id_same_sender", category: "negative", description: "Duplicate (sender,id) pair rejected", func: negative_duplicate_id_same_sender },
        TestCase { name: "positive_same_id_different_senders_allowed", category: "negative", description: "Same id for different senders allowed", func: positive_same_id_different_senders_allowed },
        TestCase { name: "negative_non_monotonic_timestamp", category: "negative", description: "Non-increasing timestamp rejected", func: negative_non_monotonic_timestamp },
        TestCase { name: "negative_tampered_hash", category: "negative", description: "Tampered hash fails verification", func: negative_tampered_hash },
    ]
}

pub fn run_named(name: &str) -> Option<TestResult> {
    let test = all_tests().into_iter().find(|t| t.name == name)?;
    let start = Instant::now();
    let outcome = (test.func)();
    let duration = start.elapsed().as_millis();
    Some(TestResult {
        name: test.name,
        category: test.category,
        description: test.description,
        passed: outcome.is_ok(),
        error: outcome.err(),
        duration_ms: duration,
    })
}

pub fn run_all() -> Vec<TestResult> {
    all_tests().into_iter().map(|tc| run_named(tc.name).unwrap()).collect()
}
