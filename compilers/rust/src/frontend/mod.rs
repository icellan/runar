//! Frontend passes for compiling `.runar.ts` source files.
//!
//! Passes:
//!   1. Parse — SWC TypeScript parser -> Rúnar AST
//!   2. Validate — structural/semantic validation
//!   3. Typecheck — type checking with builtins and subtyping
//!   4. ANF Lower — flatten to ANF IR consumed by the backend

pub mod anf_lower;
pub mod anf_optimize;
pub mod constant_fold;
pub mod ast;
pub mod parser;
pub mod parser_gocontract;
pub mod parser_move;
pub mod parser_python;
pub mod parser_ruby;
pub mod parser_rustmacro;
pub mod parser_sol;
pub mod typecheck;
pub mod validator;
