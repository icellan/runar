//! N-311: measure (A) of MAX_SOURCE_NESTING counts intersection / union type
//! nesting (user decision R117).
//!
//! The shared rule (packages/runar-ir-schema/src/input-limits.ts) adds +1 per
//! operand of an intersection or union type. swc, like the TS reference, keeps
//! `A & B & C` as one flat list, so its operands share a level; a type
//! operator nested inside another (through parentheses) is one level deeper.
//!
//! Shape: `let q: (bigint & (bigint & … bigint)) = a;` with n parenthesised
//! levels -- the innermost operand sits at level n + 1.
//!
//! What these tests prove: on the .runar.ts surface, n = 127 is not refused
//! for nesting and n = 128 is refused with the shared diagnostic (for `&`, `|`
//! and an alternation of both), a flat 500-operand intersection is not
//! refused for nesting, and a 20,000-level annotation is refused with the
//! shared diagnostic by the CLI with an ordinary exit (no signal).
//!
//! What they do NOT prove: that no tier accepts such a type (none does -- no
//! Rúnar type is an intersection or union, so "within (A)" never means
//! "compiles"), nor anything about the other tiers
//! (conformance/negatives/n311-type-operator-nesting-parity.test.ts).

use std::process::Command;

use runar_compiler_rust::frontend::input_limits::MAX_SOURCE_NESTING;
use runar_compiler_rust::frontend::parser::parse_source;

const DIAG: &str = "source nesting depth exceeds MAX_SOURCE_NESTING (limit=128)";

const HEAD: &str = "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n public verify(a: bigint, b: bigint) {\n let q: {T} = a;\n assert(q == this.t);\n }\n}\n";

fn nested(n: usize, ops: &[&str]) -> String {
    let mut open = String::new();
    for i in 0..n {
        open.push_str(&format!("(bigint {} ", ops[i % ops.len()]));
    }
    HEAD.replace("{T}", &format!("{open}bigint{}", ")".repeat(n)))
}

fn has_diag(src: String) -> bool {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let res = parse_source(&src, Some("P.runar.ts"));
            res.errors.iter().any(|d| d.format_message().contains(DIAG))
        })
        .expect("spawn")
        .join()
        .expect("join")
}

#[test]
fn type_operator_nesting_boundary_matches_the_reference() {
    for ops in [&["&"][..], &["|"][..], &["&", "|"][..]] {
        assert!(
            !has_diag(nested(MAX_SOURCE_NESTING - 1, ops)),
            "{ops:?} n={}: refused for nesting, want within measure (A)",
            MAX_SOURCE_NESTING - 1
        );
        assert!(
            has_diag(nested(MAX_SOURCE_NESTING, ops)),
            "{ops:?} n={}: not refused with the shared diagnostic",
            MAX_SOURCE_NESTING
        );
    }
}

#[test]
fn flat_intersection_is_one_level() {
    let src = HEAD.replace("{T}", &vec!["bigint"; 500].join(" & "));
    assert!(!has_diag(src), "a flat 500-operand intersection was refused for nesting");
}

#[test]
fn deep_type_operator_nesting_is_refused_without_a_crash() {
    let dir = std::env::temp_dir().join(format!("n311-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("P.runar.ts");
    std::fs::write(&path, nested(20_000, &["&"])).expect("write source");
    let out = Command::new(env!("CARGO_BIN_EXE_runar-compiler-rust"))
        .arg("--source")
        .arg(&path)
        .arg("--hex")
        .output()
        .expect("run CLI");
    let _ = std::fs::remove_dir_all(&dir);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    match out.status.code() {
        Some(c) if c != 0 && text.contains(DIAG) => {}
        code => panic!("want an ordinary non-zero exit with the shared diagnostic, got {code:?}: {}", text.chars().take(200).collect::<String>()),
    }
}
