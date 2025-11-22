use zk_chat::{Message, zk::MessageChain};

#[test]
fn interleaving_two_senders() {
    let mut chain = MessageChain::new();
    let mut ts = 10_000;
    for i in 0..10 {
        ts += 1;
        let a = Message::new(i + 1, 100, format!("A{i}"), ts);
        chain.add_message(a).unwrap();
        ts += 1;
        let b = Message::new(i + 1, 200, format!("B{i}"), ts);
        chain.add_message(b).unwrap();
    }
    assert_eq!(chain.len(), 20);
}
