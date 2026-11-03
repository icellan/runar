//! N-028 (CL-BUG-198) — a plain `.runar.ts` number literal (no `n` suffix)
//! keeps its exact value.
//!
//! swc hands a non-bigint numeric literal over as a JS number (f64). This tier
//! converted that f64, so `9007199254740993` (2^53+1) became 2^53 and a 65-bit
//! binary literal became 2^64, while the TS reference (and Go, Python, Zig,
//! Ruby, Java) read the literal's source text exactly. The same f64 funnel fed
//! `push(<number>)` inside an `asm({ body: [...] })` array.
//!
//! The expected hex below is the TS reference's fold-OFF output for each probe;
//! Go, Python, Ruby and Java emit the same bytes (checked by hand at b1eeabd8).
//!
//! Proves: the expression path and the asm push path of the .runar.ts surface
//! emit the exact values, byte-identical to the reference, for > 2^53 decimal
//! and 65-bit binary plain literals. Does NOT prove: on-chain behaviour, or the
//! other surfaces (their values are covered by the F-026 table test).

use runar_compiler_rust::{compile_from_source_str_with_result, CompileOptions};

fn hex(src: &str, file: &str) -> String {
    let opts = CompileOptions { disable_constant_folding: true, ..CompileOptions::default() };
    let r = compile_from_source_str_with_result(src, Some(file), &opts);
    assert!(r.success, "{}: {:?}", file, r.diagnostics.iter().map(|d| d.message.clone()).collect::<Vec<_>>());
    r.script_hex.unwrap()
}

#[test]
fn n028_plain_literal_above_2_pow_53_is_exact() {
    let src = "import { SmartContract, assert } from 'runar-lang';\n\nclass Big extends SmartContract {\n  readonly target: bigint;\n\n  constructor(target: bigint) {\n    super(target);\n    this.target = target;\n  }\n\n  public verify(x: bigint, y: bigint): void {\n    assert(x === 9007199254740993);\n    assert(y === 0b10000000000000000000000000000000000000000000000000000000000000001);\n  }\n}\n";
    // push 2^53+1 (7 bytes LE), push 2^64+1 (9 bytes LE)
    assert_eq!(hex(src, "Big.runar.ts"), "7c07010000000000209d090100000000000000019c");
}

#[test]
fn n028_asm_push_plain_literal_is_exact() {
    let src = "import { UnsafeSmartContract, asm } from 'runar-lang';\n\nclass AsmBig extends UnsafeSmartContract {\n  constructor() { super(); }\n\n  public unlock() {\n    asm({ body: [push(9007199254740993), push(-36893488147419103231), OP_2DROP, OP_TRUE], in_arity: 0, out_arity: 1 });\n  }\n}\n";
    // push 2^53+1, push -(2^65-1), OP_2DROP, OP_TRUE
    assert_eq!(hex(src, "AsmBig.runar.ts"), "070100000000002009ffffffffffffffff816d51");
}
