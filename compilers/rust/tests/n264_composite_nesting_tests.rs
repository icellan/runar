//! N-264: call depth x nesting must not overflow the host stack.
//!
//! Private methods are inlined at every call site, so F-213's per-method
//! nesting bound (128) and N-180's call-depth bound (128) compose
//! multiplicatively: a chain of D helpers that each call the next under K
//! nested ifs is D*K nested ifs after inlining. On a 2 MiB thread stack (Rust's
//! default for spawned threads, where `compile_check` may run) this tier
//! aborted the process at D=8 x 120; the CLI's 8 MiB main thread aborted at
//! D=32 x 120. User decision R106: lower iteratively, with an explicit work
//! stack.
//!
//! The source is remediation-logs/N-180/compgen.py's shape. The pinned digests
//! are sha256 of the script hex the UNMODIFIED Go compiler printed for the same
//! source (at 5b75534ec, before any N-264 change): goroutine stacks grow, so
//! Go compiled every depth, and its D=8 output was byte-identical to all six
//! other tiers'.
//!
//! What these tests prove: the library compiles D=32 x 120 (3,840 nested ifs)
//! and the deepest admissible chain D=127 x 120 on a 2 MiB thread stack,
//! byte-identical to Go. A stack overflow aborts this whole test binary rather
//! than failing one test, which is why the item has its own test file.
//!
//! What they do NOT prove: the other tiers (conformance/negatives/
//! n264-composite-nesting-parity.test.ts drives all seven CLIs), nor that Go's
//! deep output is right beyond agreeing with every tier at D=8.

use sha2::{Digest, Sha256};

/// remediation-logs/N-180/compgen.py, verbatim.
fn comp(d: usize, k: usize) -> String {
    let mut s = String::from("import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n");
    for i in 0..d {
        s.push_str(&format!(" private m{}(x: bigint): bigint {{\n", i));
        s.push_str("  let r: bigint = x;\n");
        for j in 0..k {
            s.push_str(&format!("  if (x > {}n) {{\n", j));
        }
        s.push_str(&format!("  r = this.m{}(x);\n", i + 1));
        for _ in 0..k {
            s.push_str("  }\n");
        }
        s.push_str("  return r;\n }\n");
    }
    s.push_str(&format!(" private m{}(x: bigint): bigint {{ return x; }}\n public verify(a: bigint) {{ assert(this.m0(a) == this.t); }}\n}}\n", d));
    s
}

fn digest_on_2mib_thread(d: usize) -> String {
    std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            let file = format!("comp{}k120.runar.ts", d);
            let artifact = runar_compiler_rust::compile_from_source_str(&comp(d, 120), Some(&file))
                .expect("composite chain compiles");
            hex::encode(Sha256::digest(artifact.script.as_bytes()))
        })
        .unwrap()
        .join()
        .unwrap()
}

#[test]
fn d32_x_120_compiles_byte_identical_to_go() {
    assert_eq!(
        digest_on_2mib_thread(32),
        "edf53286692322f6787832929bb6aaf18d2b686e9bef2ad4683cbaf3e8a25fc2"
    );
}

#[test]
fn d127_x_120_compiles_byte_identical_to_go() {
    assert_eq!(
        digest_on_2mib_thread(127),
        "d1a30af5609fe4b5704c58f518cb9bdd1f31fce14df88c650dcf33fe25153c53"
    );
}
