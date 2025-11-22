use zk_chat::Message;

#[test]
fn unit_message_hash_consistency() {
    let m = Message::new(1, 7, "hello".into(), 123456);
    assert!(m.verify_hash(), "Message hash should verify");
}
