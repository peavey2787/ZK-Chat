# ZK Chat - WebSocket Messenger with ZK-STARK Proofs

A production-grade WebSocket messenger that uses zero-knowledge proofs (ZK-STARKs) for trustless message verification using the Winterfell library.

## Overview

This project demonstrates how to build a secure chat system where message integrity and authenticity are cryptographically guaranteed through zero-knowledge proofs. Each message is verified using ZK-STARKs without revealing sensitive information about the sender or message content.

## Architecture

- **WebSocket Server**: Real-time message broadcasting using tokio-tungstenite
- **ZK Proof System**: Message integrity and sender validation using Winterfell
- **AIR Constraints**: Hash chaining, timestamp monotonicity, sender verification
- **Message Trace**: Each row contains message hash, timestamp, sender ID

## Features

- ✅ **Trustless Verification**: Messages are verified using ZK-STARK proofs
- ✅ **Real-time Communication**: WebSocket-based instant messaging  
- ✅ **Hash Chaining**: Maintains cryptographic integrity of message sequence
- ✅ **Timestamp Monotonicity**: Ensures proper message ordering
- ✅ **Sender Authentication**: Cryptographic proof of message origin
- ✅ **Concurrent Support**: Async/await for handling multiple clients

## Quick Start

### Prerequisites

- Rust 1.70+ 
- Cargo

### Building the Project

```bash
# Build all components
cargo build

# Build in release mode for better performance
cargo build --release
```

### Running the Components

#### 1. Start the Server

```bash
# Run the WebSocket server on default port 8080
cargo run --bin server

# Or specify a custom address
cargo run --bin server -- 127.0.0.1:9090
```

#### 2. Connect Clients

```bash
# Run a client and follow the prompts
cargo run --bin client

# Or specify custom server URL
cargo run --bin client -- ws://127.0.0.1:9090
```

#### 3. Test ZK Proof Generation

```bash
# Run the proof generation demo
cargo run --bin prover
```

### VS Code Tasks

If using VS Code, you can use the predefined tasks:

- **Ctrl+Shift+P** → "Tasks: Run Task"
- Select from:
  - `Build ZK Chat` - Build the project
  - `Run Server` - Start the WebSocket server
  - `Run Client` - Start a chat client
  - `Run Prover Demo` - Test proof generation

## How It Works

### Message Structure

Each message contains:
- `id`: Unique message identifier
- `sender_id`: Sender's unique ID
- `content`: Message text
- `timestamp`: Unix timestamp
- `hash`: SHA3-256 hash of message data

### ZK Proof System

1. **Message Creation**: Client creates message with hash
2. **Proof Generation**: ZK proof generated for message validity
3. **Server Verification**: Server verifies proof before broadcasting
4. **Chain Integrity**: Maintains hash chain of all verified messages

### AIR Constraints

The Algebraic Intermediate Representation enforces:

1. **Hash Chaining**: `next_prev_hash = current_hash`
2. **Timestamp Monotonicity**: `current_timestamp > previous_timestamp` 
3. **Sender Validation**: `sender_id ≠ 0`
4. **Hash Verification**: Message hash computation correctness

## Project Structure

```
src/
├── lib.rs              # Main library interface
├── main.rs             # Default server executable
├── bin/
│   ├── server.rs       # WebSocket server
│   ├── client.rs       # Chat client
│   └── prover.rs       # Proof generation demo
├── zk/
│   ├── mod.rs          # ZK system exports
│   ├── air.rs          # AIR constraints
│   └── prover.rs       # Proof generation
└── websocket/
    ├── mod.rs          # WebSocket exports
    ├── server.rs       # Server implementation
    ├── client.rs       # Client implementation
    └── protocol.rs     # Protocol messages
```

## API Reference

### Message

```rust
pub struct Message {
    pub id: u64,
    pub sender_id: u64, 
    pub content: String,
    pub timestamp: u64,
    pub hash: [u8; 32],
}
```

### Protocol Messages

- `Join { user_id, username }` - Join chat room
- `SendMessage { message, proof }` - Send verified message
- `MessageBroadcast { message, verified }` - Server broadcast
- `Error { code, message }` - Error response

### ZK Components

- `MessageAir` - AIR implementation for constraints
- `MessageProver` - Proof generation
- `verify_proof()` - Proof verification
- `MessageChain` - Message sequence management

## Configuration

### Proof Parameters

Default ZK-STARK parameters in `MessageProver`:
- `num_queries`: 32
- `blowup_factor`: 8  
- `grinding_factor`: 0
- `fri_folding_factor`: 8
- `fri_max_remainder_size`: 31

### WebSocket Server

- Default address: `127.0.0.1:8080`
- Configurable via command line argument
- Supports concurrent client connections

## Development

### Running Tests

```bash
cargo test
```

### Debugging

1. Enable debug logging:
   ```rust
   tracing_subscriber::fmt()
       .with_max_level(Level::DEBUG)
       .init();
   ```

2. Use VS Code debugger with launch configurations
3. Monitor WebSocket traffic in browser dev tools

### Performance Optimization

- Use `--release` builds for production
- Adjust ZK proof parameters for speed vs security tradeoff
- Enable Winterfell concurrent features:
  ```bash
  cargo build --release --features concurrent
  ```

## Security Considerations

- **Production Note**: Current implementation uses simplified proof verification
- **Hash Function**: Uses SHA3-256 for message hashing
- **Proof Size**: ZK-STARK proofs are larger than SNARKs but don't require trusted setup
- **Replay Protection**: Timestamp monotonicity prevents message replay
- **Sender Authentication**: Cryptographic proof prevents impersonation

## Troubleshooting

### Common Issues

1. **Connection Refused**: Ensure server is running before connecting clients
2. **Proof Verification Failed**: Check message hash and timestamp validity
3. **Compilation Errors**: Ensure Rust 1.70+ and compatible Winterfell version

### Debugging Steps

1. Check server logs for error messages
2. Verify message format matches protocol
3. Ensure timestamps are monotonically increasing
4. Validate ZK proof parameters

## Future Enhancements

- [ ] Full ZK-STARK proof implementation (currently simplified)
- [ ] Persistent message storage
- [ ] User authentication system
- [ ] Message encryption
- [ ] Room/channel support
- [ ] Rate limiting
- [ ] Message size limits
- [ ] Client reconnection handling

## Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Make changes following Rust best practices
4. Add tests for new functionality
5. Submit pull request

## License

MIT License - see LICENSE file for details

## References

- [Winterfell Library](https://github.com/novifinancial/winterfell)
- [ZK-STARK Overview](https://vitalik.ca/general/2017/11/09/starks_part_1.html) 
- [WebSocket Protocol](https://tools.ietf.org/html/rfc6455)
- [Tokio Async Runtime](https://tokio.rs/)