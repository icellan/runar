//! Frontend passes for compiling `.tsop.ts` source files.
//!
//! Passes:
//!   1. Parse — SWC TypeScript parser -> TSOP AST
//!   2. Validate — structural/semantic validation
//!   3. Typecheck — type checking with builtins and subtyping
//!   4. ANF Lower — flatten to ANF IR consumed by the backend

pub mod anf_lower;
pub mod ast;
pub mod parser;
pub mod typecheck;
pub mod validator;
