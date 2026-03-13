//! Code generation modules.
//!
//! - `stack`: ANF IR -> Stack IR lowering (Pass 5)
//! - `emit`: Stack IR -> Bitcoin Script bytes (Pass 6)
//! - `opcodes`: Complete BSV opcode table
//! - `optimizer`: Peephole optimizer for Stack IR

pub mod blake3;
pub mod ec;
pub mod emit;
pub mod opcodes;
pub mod optimizer;
pub mod sha256;
pub mod slh_dsa;
pub mod stack;
