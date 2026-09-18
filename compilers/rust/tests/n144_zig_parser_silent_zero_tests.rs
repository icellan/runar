//! N-144 (found while measuring R-145 / CL-BUG-053): the Rust tier's
//! `.runar.zig` parser turns any token it does not recognise into the literal
//! `0`, emits no diagnostic, and compiles the result.
//!
//! `parser_zig.rs` ended `parse_primary` with
//!
//! ```text
//! // Fallback
//! self.advance();
//! Expression::BigIntLiteral { value: BigInt::from(0) }
//! ```
//!
//! — consume the offending token, substitute zero, say nothing. The sibling
//! `parser_ruby.rs` pushes "Unexpected token in expression" at the same
//! position, so this is not a house style; it is one parser missing its error
//! arm.
//!
//! Measured on `examples/zig/bounded-loop/BoundedLoop.runar.zig` with line 16
//! changed from `sum = sum + start + i;` to `sum = sum +++ ?? i;`:
//!
//! ```text
//! go      Compilation error: parse errors: line 16: unexpected token "+"
//! zig     parse error: BoundedLoop.runar.zig:16:24: unexpected token: '+'
//! python  type check errors: :16:13: right operand of '+' must be bigint
//! rust    0000007b7c937c9351007b7c937c93520...   <- compiled
//! ```
//!
//! and the bytes rust produced are not the bytes the CORRECT contract produces:
//!
//! ```text
//! rust, original file:  000052797b7c937c935152797b7c937c9352... (== go)
//! rust, broken  file:   0000007b7c937c9351007b7c937c9352...
//! ```
//!
//! So this is not "accepts junk and emits junk". It is: a contract with a typo
//! in it silently becomes a DIFFERENT, well-formed contract, deployable, with a
//! different locking script from the one the author read. That is the same
//! class as R-190 (`SigHash.<unknown>` lowering to 0) in the same tier — a
//! parser filling a hole with a plausible value instead of refusing.
//!
//! The fix is the error arm the ruby parser already has. A parse error makes
//! `parse_source` return errors, so nothing downstream sees the placeholder.

use runar_compiler_rust::compile_from_source_str;

/// The well-formed contract, verbatim from examples/zig/bounded-loop.
const GOOD: &str = r#"const runar = @import("runar");

pub const BoundedLoop = struct {
    pub const Contract = runar.SmartContract;

    expectedSum: i64,

    pub fn init(expectedSum: i64) BoundedLoop {
        return .{ .expectedSum = expectedSum };
    }

    pub fn verify(self: *const BoundedLoop, start: i64) void {
        var sum: i64 = 0;
        var i: i64 = 0;
        while (i < 5) : (i += 1) {
            sum = sum + start + i;
        }
        runar.assert(sum == self.expectedSum);
    }
};
"#;

fn with_body(line: &str) -> String {
    GOOD.replace("            sum = sum + start + i;", line)
}

/// Control: the untouched contract must still compile, and to the bytes the Go
/// tier produces for it. A fix that makes the parser refuse valid Zig would
/// pass every negative below.
#[test]
fn the_well_formed_contract_still_compiles_to_the_cross_tier_bytes() {
    let art = compile_from_source_str(GOOD, Some("BoundedLoop.runar.zig"))
        .expect("the example contract must compile");
    assert_eq!(
        art.script,
        "000052797b7c937c935152797b7c937c935252797b7c937c935352797b7c937c93547b7b7c937c93009c",
        "the Rust tier's bytes for the unmodified example moved; \
         this is the Go tier's hex, measured at the same commit",
    );
}

/// The finding. Each of these carries a token the Zig grammar cannot place.
///
/// `sum = ~~ i;` is NOT among them, though it looks like it should be: `~` is
/// unary bitwise-not and doubling it is legal Zig. All four tiers that were
/// asked compile it to the same 00008383518383528383538383548383009c777777777777.
/// It was in this list until that was measured.
#[test]
fn a_token_the_parser_cannot_place_is_refused_not_silently_zeroed() {
    for body in [
        "            sum = sum +++ ?? i;",
        "            sum = sum ?? i;",
        "            sum = sum + ;",
    ] {
        let out = compile_from_source_str(&with_body(body), Some("BoundedLoop.runar.zig"));
        match out {
            Ok(art) => panic!(
                "`{}` compiled to {} — the unparseable token was replaced by a \
                 literal instead of refused",
                body.trim(),
                art.script,
            ),
            Err(e) => {
                assert!(
                    e.to_lowercase().contains("token"),
                    "the diagnostic for `{}` must say which token it could not \
                     place; got: {}",
                    body.trim(),
                    e,
                );
            }
        }
    }
}

/// The consequence, stated as bytes: a typo must never become a DIFFERENT
/// contract that compiles. If the parser ever goes back to substituting a
/// value, this is the assertion that catches it even if a diagnostic is also
/// emitted.
#[test]
fn a_typo_never_compiles_to_a_different_script() {
    let good = compile_from_source_str(GOOD, Some("BoundedLoop.runar.zig"))
        .expect("control must compile");
    let broken = compile_from_source_str(
        &with_body("            sum = sum +++ ?? i;"),
        Some("BoundedLoop.runar.zig"),
    );
    if let Ok(art) = broken {
        panic!(
            "a source with a syntax error compiled. good={} broken={}",
            good.script, art.script
        );
    }
}
