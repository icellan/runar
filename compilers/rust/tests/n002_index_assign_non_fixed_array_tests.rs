//! N-002 (CL-BUG-214, the cross-tier half of F-013): an index assignment is
//! only a write when its root is a FixedArray contract property.
//!
//! expand_fixed_arrays rewrites `self.arr[i] = v` only when `arr` is a
//! FixedArray property. Every other index target (a ByteString property, a
//! local, a parameter, a member-chained root) survived to ANF lowering, which
//! lowered it as a READ and dropped the value: a deployable script, no
//! diagnostic, state that never changes. Pre-fix, F-013's Blob.runar.ts
//! compiled here to the same `61ab7676aa517f…` script as TS/Go/Zig, which
//! @bsv/sdk Spend.validate showed accepting a continuation with the UNCHANGED
//! blob (remediation-logs/N-002/exec-proof*.txt).
//!
//! What this proves: the Rust tier refuses every non-FixedArray index-write
//! shape below with F-013's shared diagnostic and a location, on the TS surface
//! and on the Rust surface, and still compiles FixedArray index writes
//! (literal, runtime, compound, ++, nested literal).
//! What it does NOT prove: the other tiers (their own suites and
//! conformance/negatives/N81-N94 cover that), or byte-identity of the
//! FixedArray goldens (the conformance golden + multi-format runs do).

use runar_compiler_rust::{compile_from_source_str_with_result, CompileOptions};

const NEEDLE: &str = "index assignment is only supported on FixedArray contract properties; \
                      the target here is not a FixedArray property";

fn blob(body: &str) -> String {
    format!(
        "import {{ StatefulSmartContract, ByteString, assert }} from 'runar-lang';\n\nclass Blob extends StatefulSmartContract {{\n  blob: ByteString;\n\n  constructor(blob: ByteString) {{\n    super(blob);\n    this.blob = blob;\n  }}\n\n  public poke(i: bigint) {{\n    {}\n    assert(true);\n  }}\n}}\n",
        body
    )
}

const TS_LOCAL: &str = "import { SmartContract, ByteString, assert } from 'runar-lang';\n\nclass Loc extends SmartContract {\n  readonly h: ByteString;\n\n  constructor(h: ByteString) {\n    super(h);\n    this.h = h;\n  }\n\n  public unlock(b: ByteString) {\n    let c: ByteString = b;\n    c[0n] = 7n;\n    assert(c == this.h);\n  }\n}\n";

const TS_PARAM: &str = "import { SmartContract, ByteString, assert } from 'runar-lang';\n\nclass Par extends SmartContract {\n  readonly h: ByteString;\n\n  constructor(h: ByteString) {\n    super(h);\n    this.h = h;\n  }\n\n  public unlock(b: ByteString) {\n    b[0n] = 7n;\n    assert(b == this.h);\n  }\n}\n";

const RS_PROP: &str = "use runar::prelude::*;\n\n#[runar::contract]\npub struct Blob {\n    pub blob: ByteString,\n}\n\nimpl Blob {\n    pub fn poke(&mut self) {\n        self.blob[0] = 7;\n        assert!(true);\n    }\n}\n";

const RS_LOCAL_PARAM: &str = "use runar::prelude::*;\n\n#[runar::contract]\npub struct Loc {\n    #[readonly]\n    pub h: ByteString,\n}\n\nimpl Loc {\n    pub fn unlock(&self, b: ByteString) {\n        let c = b;\n        c[0] = 7;\n        b[1] = 7;\n        assert!(c == self.h);\n    }\n}\n";

/// Returns a failure description instead of panicking: the compiler installs a
/// silent panic hook (guarded_pass), so an assert message raised here would be
/// swallowed and the failure would carry no reason.
fn refusal_failure(src: &str, file: &str, want: usize) -> Option<String> {
    let r = compile_from_source_str_with_result(src, Some(file), &CompileOptions::default());
    if r.success || r.script_hex.is_some() {
        return Some(format!("{}: compiled a script that silently drops the write", file));
    }
    let hits: Vec<_> = r.diagnostics.iter().filter(|d| d.message == NEEDLE).collect();
    if hits.len() != want {
        return Some(format!(
            "{}: expected {} '{}' diagnostic(s), got {}; diagnostics: {:?}",
            file,
            want,
            NEEDLE,
            hits.len(),
            r.diagnostics.iter().map(|d| d.message.clone()).collect::<Vec<_>>()
        ));
    }
    if let Some(h) = hits.iter().find(|h| h.loc.as_ref().map_or(true, |l| l.line == 0)) {
        return Some(format!("{}: diagnostic carries no location: {:?}", file, h));
    }
    None
}

#[test]
fn n002_non_fixed_array_index_assignment_is_refused() {
    let cases: Vec<(&str, String, &str, usize)> = vec![
        ("ts/bytestring-prop-literal", blob("this.blob[0n] = 7n;"), "Blob.runar.ts", 1),
        ("ts/bytestring-prop-runtime", blob("this.blob[i] = 7n;"), "Blob.runar.ts", 1),
        ("ts/bytestring-prop-plus-eq", blob("this.blob[0n] += 7n;"), "Blob.runar.ts", 1),
        ("ts/bytestring-prop-minus-eq", blob("this.blob[0n] -= 7n;"), "Blob.runar.ts", 1),
        ("ts/bytestring-prop-mul-eq", blob("this.blob[0n] *= 7n;"), "Blob.runar.ts", 1),
        ("ts/bytestring-prop-div-eq", blob("this.blob[0n] /= 7n;"), "Blob.runar.ts", 1),
        ("ts/bytestring-prop-mod-eq", blob("this.blob[0n] %= 7n;"), "Blob.runar.ts", 1),
        ("ts/bytestring-prop-nested", blob("this.blob[0n][1n] = 7n;"), "Blob.runar.ts", 1),
        ("ts/member-chained-root", blob("this.blob.x[0n] = 7n;"), "Blob.runar.ts", 1),
        ("ts/local", TS_LOCAL.to_string(), "Loc.runar.ts", 1),
        ("ts/param", TS_PARAM.to_string(), "Par.runar.ts", 1),
        ("rs/bytestring-prop", RS_PROP.to_string(), "Blob.runar.rs", 1),
        ("rs/local+param", RS_LOCAL_PARAM.to_string(), "Loc.runar.rs", 2),
    ];
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|(name, src, file, want)| refusal_failure(src, file, *want).map(|f| format!("[{}] {}", name, f)))
        .collect();
    for f in &failures {
        eprintln!("{}", f);
    }
    assert!(failures.is_empty(), "{} case(s) failed:\n{}", failures.len(), failures.join("\n"));
}

const FIXED_ARRAY_WRITES: &str = "import { StatefulSmartContract, FixedArray, assert } from 'runar-lang';\n\nclass Board extends StatefulSmartContract {\n  board: FixedArray<bigint, 3> = [0n, 0n, 0n];\n  grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];\n\n  constructor() {\n    super();\n  }\n\n  public set(i: bigint, v: bigint) {\n    this.board[i] = v;\n    this.board[0n] = v;\n    this.board[1n] += v;\n    this.board[2n]++;\n    this.grid[0n][1n] = v;\n    assert(true);\n  }\n}\n";

#[test]
fn n002_fixed_array_index_assignment_still_compiles() {
    let r = compile_from_source_str_with_result(FIXED_ARRAY_WRITES, Some("Board.runar.ts"), &CompileOptions::default());
    assert!(
        r.success && r.script_hex.is_some(),
        "FixedArray index writes must compile; diagnostics: {:?}",
        r.diagnostics.iter().map(|d| d.message.clone()).collect::<Vec<_>>()
    );
}
