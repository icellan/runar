//! Code generation modules.
//!
//! - `stack`: ANF IR -> Stack IR lowering (Pass 5)
//! - `emit`: Stack IR -> Bitcoin Script bytes (Pass 6)
//! - `opcodes`: Complete BSV opcode table
//! - `optimizer`: Peephole optimizer for Stack IR

pub mod babybear;
pub mod blake3;
pub mod bn254;
pub mod ec;
pub mod emit;
pub mod p256_p384;
pub mod fiat_shamir_kb;
pub mod koalabear;
pub mod merkle;
pub mod opcodes;
pub mod optimizer;
pub mod poseidon2_koalabear;
pub mod poseidon2_merkle;
pub mod sha256;
pub mod slh_dsa;
pub mod stack;
