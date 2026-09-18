//! R-237 (CL-GAP-013): the DCE warning for a dropped readonly field never
//! reached this tier's CLI.
//!
//! The check exists in `lib.rs` and pushes a warning Diagnostic into the
//! `CompileResult`. The CLI called `compile_from_source_with_options`, whose
//! return type is `Result<RunarArtifact, String>` — one value, with nowhere to
//! put an advisory — so the notice was computed and discarded at the boundary.
//! An author whose field vanished from the locking script heard it from ts, go,
//! zig and java, and not from here. Same shape as R-162 in the Go tier.
//!
//! The CLI now goes through `compile_from_source_with_result` and prints every
//! warning-severity diagnostic. These tests pin the diagnostic itself, which is
//! what the CLI now forwards.

use runar_compiler_rust::frontend::diagnostic::Severity;
use runar_compiler_rust::{compile_from_source_str_with_result, CompileOptions};

const UNREAD: &str = r#"
import { SmartContract, assert } from 'runar-lang';

export class UnreadField extends SmartContract {
  readonly unused: bigint;
  readonly limit: bigint;

  constructor(unused: bigint, limit: bigint) {
    super(unused, limit);
    this.unused = unused;
    this.limit = limit;
  }

  public unlock(x: bigint): void {
    assert(x < this.limit);
  }
}
"#;

fn warnings_for(source: &str) -> Vec<String> {
    let result = compile_from_source_str_with_result(
        source,
        Some("UnreadField.runar.ts"),
        &CompileOptions::default(),
    );
    assert!(result.success, "probe failed to compile: {:?}", result.diagnostics);
    result
        .diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Warning)
        .map(|d| d.to_string())
        .collect()
}

#[test]
fn r237_warns_when_a_readonly_field_is_dropped() {
    let warnings = warnings_for(UNREAD);
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("readonly field 'unused'") && w.contains("eliminated by DCE")),
        "the dropped-field notice is missing: {:?}",
        warnings
    );
}

#[test]
fn r237_does_not_warn_when_the_field_is_read() {
    let read = UNREAD.replace(
        "assert(x < this.limit);",
        "assert(x < this.limit + this.unused);",
    );
    let warnings = warnings_for(&read);
    assert!(
        !warnings.iter().any(|w| w.contains("readonly field 'unused'")),
        "a referenced field must not warn: {:?}",
        warnings
    );
}

#[test]
fn r237_does_not_warn_for_a_field_that_is_used() {
    let warnings = warnings_for(UNREAD);
    assert!(
        !warnings.iter().any(|w| w.contains("readonly field 'limit'")),
        "'limit' is read by unlock and must not warn: {:?}",
        warnings
    );
}
