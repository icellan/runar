//! F-387 (CL-GAP-065): `merkleRootPoseidon2KB` is a real Runar builtin —
//! `codegen/stack.rs`'s `is_merkle_builtin` and `ir/loader.rs` both know its
//! name, and `poseidon2_merkle::emit_poseidon2_merkle_root` exists to lower
//! it — but the typechecker's `builtin_functions()` table never gained an
//! entry for it. A source-level call therefore falls through
//! `check_call_expr`'s last branch and is reported exactly like a typo:
//!
//!     unknown function 'merkleRootPoseidon2KB' -- only Rúnar built-in
//!     functions and contract methods are allowed
//!
//! That message is actively misleading: `merkleRootPoseidon2KB` is not
//! unknown, it is a real Poseidon2 Merkle builtin that CLAUDE.md scopes to
//! the Go reference compiler by policy (see "EVM/STARK proof-system
//! primitives are scoped to the Go tier by project policy" and
//! `conformance/go-only-parity/`, R-037). Every other non-Go tier that has
//! made this call already says so instead of "unknown function" — the
//! Python tier's `GO_ONLY_BUILTINS` table (R-258/R-259, `compilers/python/
//! runar_compiler/frontend/typecheck.py`) is the precedent this test ports:
//! refuse the call (matching Go's acceptance surface, since `runar-lang`
//! does not even declare the symbol for the TS/ source frontend to see), but
//! name the builtin and the policy instead of calling it unknown.
//!
//! This test only checks the DIAGNOSTIC. It deliberately does not change
//! `codegen/stack.rs`'s `is_merkle_builtin` / `lower_merkle_root` dispatch
//! (the `--ir` path) — that dispatch has a separate, pre-existing bug
//! (`lower_merkle_root` assumes all three merkle builtins take exactly 4
//! arguments, which is wrong for `merkleRootPoseidon2KB`'s 8*depth+10 variadic
//! arity) that is out of scope for this item and is flagged separately for
//! the dispatcher.

use runar_compiler_rust::{compile_from_source_str_with_result, CompileOptions};

/// A minimal `.runar.ts` contract that calls `merkleRootPoseidon2KB` by name,
/// mirroring the shape of Python's `test_r258_go_only_builtin_diagnostics.py`
/// probe and the repo's own `conformance/go-only-parity/
/// GoOnlyPoseidon2Merkle.runar.ts` fixture (reduced to the two-argument shape
/// the other Go-only-builtin probes use, since arity is not what this test
/// is about).
const SOURCE: &str = r#"
import { SmartContract, assert, merkleRootPoseidon2KB } from 'runar-lang';

class Probe extends SmartContract {
  readonly limit: bigint;

  constructor(limit: bigint) {
    super(limit);
    this.limit = limit;
  }

  public unlock(a: bigint, b: bigint) {
    assert(merkleRootPoseidon2KB(a, b) === this.limit);
  }
}
"#;

fn diagnostics() -> String {
    let result = compile_from_source_str_with_result(SOURCE, Some("Probe.runar.ts"), &CompileOptions::default());
    assert!(
        !result.success,
        "merkleRootPoseidon2KB is Go-tier-only by policy; it must not typecheck in the Rust tier"
    );
    result
        .diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

/// RED: at HEAD, the Rust tier calls a real builtin "unknown function",
/// which is the defect — it sends the author looking for a typo or a missing
/// import, the one thing that is not wrong.
#[test]
fn merkle_root_poseidon2_kb_is_not_reported_as_unknown_function() {
    let msg = diagnostics();
    assert!(
        !msg.contains("unknown function"),
        "merkleRootPoseidon2KB is a real Runar builtin, scoped to the Go tier \
         by policy. Calling it 'unknown' sends the author looking for a typo: {msg}"
    );
}

/// The replacement diagnostic must name both the builtin and the fact that
/// it is Go-tier-only, so the author can tell "not implemented here, by
/// design" apart from "you made a typo".
#[test]
fn merkle_root_poseidon2_kb_diagnostic_names_the_builtin_and_the_go_only_policy() {
    let msg = diagnostics();
    assert!(
        msg.contains("merkleRootPoseidon2KB"),
        "diagnostic must name the builtin; got: {msg}"
    );
    assert!(
        msg.to_lowercase().contains("go tier") || msg.to_lowercase().contains("go-only"),
        "diagnostic must say this builtin is scoped to the Go tier; got: {msg}"
    );
}
