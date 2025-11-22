# Production Hardening Patches

## Fix 1: Add Timestamp Monotonicity Constraint to AIR

**File**: `src/zk/air.rs`

**Line ~115-120**: Replace the comment "Removed faulty monotonicity constraint" with:

```rust
        // Constraint 5: Timestamp monotonicity (CRITICAL SECURITY CONSTRAINT)
        // Ensures timestamps strictly increase: current_timestamp > prev_timestamp
        // This prevents time-travel attacks and enforces message ordering
        // Formula: (current[9] - current[8]) must be >= 1
        // We enforce: current[9] - current[8] - 1 >= 0
        result[5] = current[9] - current[8] - E::ONE;
```

**Line ~60-65**: Update the degrees vector from 5 to 6 constraints:

```rust
        let degrees = vec![
            TransitionConstraintDegree::new(1), // Hash chaining constraint 0
            TransitionConstraintDegree::new(1), // Hash chaining constraint 1
            TransitionConstraintDegree::new(1), // Hash chaining constraint 2
            TransitionConstraintDegree::new(1), // Hash chaining constraint 3
            TransitionConstraintDegree::new(1), // Timestamp chaining constraint 4
            TransitionConstraintDegree::new(1), // Timestamp monotonicity constraint 5
        ];
```

## Fix 2: Add Message ID Uniqueness Validation

**File**: `src/lib.rs`

**Line ~16**: Add new error variant:

```rust
    #[error("Duplicate message ID")]
    DuplicateMessageId,
```

**File**: `src/zk/mod.rs`

**Line ~118-120** (in `MessageChain::add_message`): Add after hash verification:

```rust
        // Verify message ID uniqueness (prevents replay attacks)
        if self.messages.iter().any(|m| m.id == message.id) {
            return Err(ZkChatError::DuplicateMessageId);
        }
```
