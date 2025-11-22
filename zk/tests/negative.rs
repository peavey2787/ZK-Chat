use zk_chat::{Message, zk::MessageChain, ZkChatError};

#[test]
fn negative_duplicate_id_rejected_same_sender() {
    let mut chain = MessageChain::new();
    chain.add_message(Message::new(1, 1, "a".into(), 1000)).unwrap();
    let err = chain.add_message(Message::new(1, 1, "b".into(), 1001)).unwrap_err();
    assert!(matches!(err, ZkChatError::DuplicateMessageId));
}

#[test]
fn allow_same_id_different_senders() {
    let mut chain = MessageChain::new();
    chain.add_message(Message::new(1, 10, "u1 msg1".into(), 1000)).unwrap();
    // Different sender, same id should be allowed
    chain.add_message(Message::new(1, 20, "u2 msg1".into(), 1001)).unwrap();
}

#[test]
fn negative_non_monotonic_timestamp_rejected() {
    let mut chain = MessageChain::new();
    chain.add_message(Message::new(1, 1, "a".into(), 1000)).unwrap();
    let err = chain.add_message(Message::new(2, 2, "b".into(), 1000)).unwrap_err();
    assert!(matches!(err, ZkChatError::InvalidTimestamp));
}

#[test]
fn negative_tampered_hash_fails_verify() {
    let mut msg = Message::new(1, 1, "tamper".into(), 1000);
    msg.hash[0] ^= 0xFF; // corrupt a byte
    assert!(!msg.verify_hash(), "Tampered hash should fail verification");
}
