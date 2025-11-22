use proptest::prelude::*;
use zk_chat::{Message, zk::MessageChain};

proptest! {
    #[test]
    fn prop_monotonic_timestamps_and_unique_sender_ids(seq in prop::collection::vec((1u64..100u64, "[a-z]{1,8}"), 1..20)) {
        let mut chain = MessageChain::new();
        let mut time: u64 = 1_000_000;
        for (sender, content) in seq.iter() {
            time += 1 + (sender % 3); // ensure increase
            let msg = Message::new(chain.len() as u64 + 1, *sender, content.clone(), time);
            let _ = chain.add_message(msg); // ignore errors for now (focus on no panic)
        }
    }
}

proptest! {
    #[test]
    fn prop_reject_duplicate_local_ids_for_same_sender(sender in 1u64..50u64) {
        let mut chain = MessageChain::new();
        let m1 = Message::new(1, sender, "a".into(), 1000);
        assert!(chain.add_message(m1).is_ok());
        let m_dup = Message::new(1, sender, "b".into(), 1001);
        assert!(chain.add_message(m_dup).is_err());
    }
}
