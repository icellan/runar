//! R-190 (CL-BUG-152): `SigHash.<unknown>` silently became 0 in the Rust tier.
//!
//! `lower_member_expr` mapped the five real members and closed the match with
//! `_ => 0`, so a typo — `SigHash.All` for `SigHash.ALL`, or any member that
//! does not exist — lowered to `load_const 0`. Zero is not a valid sighash
//! flag, and nothing downstream rejects it, so the contract COMPILED and the
//! wrong constant went into the locking script.
//!
//! The other six tiers refuse the same source. Measured on
//! `assert(x === this.limit + SigHash.All)`:
//!
//!   ts      Stack lowering: method parameter 'SigHash' is not on the stack …
//!   go      stack lowering failed: method parameter 'SigHash' is not on the stack …
//!   python  stack lowering: 'NoneType' object is not iterable
//!   zig     error: StackLowerFailed
//!   ruby    Stack lowering: method parameter 'SigHash' is not on the stack …
//!   java    emit error: Stack lowering: …
//!   rust    009c            <- compiled, SigHash.All == 0
//!
//! Rust was the only tier that accepted it. The peers reject by ACCIDENT — they
//! fall through to general member access and then fail in pass 5 with a message
//! about a "method parameter 'SigHash'", which is not what the author wrote.
//! This tier refuses in pass 4, where the mistake actually is, and names the
//! members that do exist.

use runar_compiler_rust::compile_from_source_str;

fn source_with(member: &str) -> String {
    format!(
        r#"
import {{ SmartContract, assert, SigHash }} from 'runar-lang';

export class SigHashProbe extends SmartContract {{
  readonly limit: bigint;

  constructor(limit: bigint) {{
    super(limit);
    this.limit = limit;
  }}

  public unlock(x: bigint): void {{
    assert(x === this.limit + SigHash.{});
  }}
}}
"#,
        member
    )
}

#[test]
fn every_real_sighash_member_still_compiles() {
    for member in ["ALL", "NONE", "SINGLE", "FORKID", "ANYONECANPAY"] {
        let out = compile_from_source_str(&source_with(member), Some("SigHashProbe.runar.ts"));
        assert!(
            out.is_ok(),
            "SigHash.{} must still compile, got {:?}",
            member,
            out.err()
        );
    }
}

#[test]
fn the_five_members_lower_to_five_distinct_scripts() {
    // If an unknown member can collapse to a constant, so can a known one.
    // Distinct bytes per member is what proves each constant is really carried.
    let mut seen: Vec<(String, String)> = Vec::new();
    for member in ["ALL", "NONE", "SINGLE", "FORKID", "ANYONECANPAY"] {
        let art = compile_from_source_str(&source_with(member), Some("SigHashProbe.runar.ts"))
            .unwrap_or_else(|e| panic!("SigHash.{} failed to compile: {}", member, e));
        for (other, hex) in &seen {
            assert_ne!(
                *hex, art.script,
                "SigHash.{} and SigHash.{} emit identical bytes",
                other, member
            );
        }
        seen.push((member.to_string(), art.script.clone()));
    }
}

#[test]
fn an_unknown_sighash_member_is_refused_not_silently_zeroed() {
    for member in ["All", "all", "Alll", "NOPE", "TYPO"] {
        let out = compile_from_source_str(&source_with(member), Some("SigHashProbe.runar.ts"));
        let err = match out {
            Ok(artifact) => panic!(
                "SigHash.{} compiled to {} — the unknown member was silently \
                 lowered to a constant instead of refused",
                member, artifact.script
            ),
            Err(e) => e,
        };
        assert!(
            err.contains("SigHash"),
            "the diagnostic for SigHash.{} must name SigHash; got: {}",
            member,
            err
        );
        assert!(
            err.contains(member),
            "the diagnostic for SigHash.{} must quote what the author wrote; got: {}",
            member,
            err
        );
        assert!(
            err.contains("ALL"),
            "the diagnostic for SigHash.{} must list the members that do exist; got: {}",
            member,
            err
        );
    }
}

/// The case from the finding, spelled out: the typo differs from the real
/// member only in case, which is exactly the mistake a reader does not catch.
#[test]
fn sighash_all_lowercase_does_not_become_zero() {
    let typo = compile_from_source_str(&source_with("All"), Some("SigHashProbe.runar.ts"));
    assert!(typo.is_err(), "SigHash.All must not compile");

    let real = compile_from_source_str(&source_with("ALL"), Some("SigHashProbe.runar.ts"))
        .expect("SigHash.ALL must compile");
    assert!(!real.script.is_empty());
}
