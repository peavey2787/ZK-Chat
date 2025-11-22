use zk_chat::{Message, zk::MessageChain};

#[test]
fn integration_chain_updates() {
    let mut chain = MessageChain::new();
    let m1 = Message::new(1, 1, "a".into(), 1000);
    chain.add_message(m1).unwrap();
    let h1 = chain.chain_hash;
    let m2 = Message::new(2, 2, "b".into(), 1001);
    chain.add_message(m2).unwrap();
    let h2 = chain.chain_hash;
    assert_ne!(h1, h2, "Chain hash must update after second message");
    assert_eq!(chain.len(), 2);
}
