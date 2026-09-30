//! N-005 — an assert that is not the method's last binding must be lowered
//! with OP_VERIFY. Port of the reference tier's case in
//! packages/runar-compiler/src/__tests__/asm-surface.test.ts.
//!
//! Stack lowering treated the LAST assert of a public method as terminal (its
//! value left as the script result) even when a terminal asm() followed it.
//! The asm pushed OP_1, the end-of-method cleanup NIPped the comparison away,
//! and the method compiled to 012a9c5177 (<42> OP_NUMEQUAL OP_1 OP_NIP):
//! spendable with ANY x. The hand-derived fixed script is 012a9d51
//! (<42> OP_NUMEQUALVERIFY OP_1).
//!
//! Proves: this tier's bytes for the shape in both fold modes, and that a
//! truly final assert still stays the method result. Does NOT prove on-chain
//! behaviour — the Spend-engine proof for all seven tiers is
//! packages/runar-testing/src/__tests__/n005-assert-then-asm-spend.test.ts.

use runar_compiler_rust::{compile_from_source_str_with_result, CompileOptions};

const ASSERT_THEN_ASM: &str = "import { UnsafeSmartContract, assert, asm } from 'runar-lang';

class AssertThenAsm extends UnsafeSmartContract {
  constructor() {
    super();
  }

  public unlock(x: bigint) {
    assert(x === 42n);
    asm({ body: '51', in_arity: 0, out_arity: 1 });
  }
}
";

const ASM_THEN_ASSERT: &str = "import { UnsafeSmartContract, assert, asm } from 'runar-lang';

class AsmThenAssert extends UnsafeSmartContract {
  constructor() {
    super();
  }

  public unlock(x: bigint) {
    asm({ body: '51', in_arity: 0, out_arity: 1 });
    assert(x === 42n);
  }
}
";

fn hex_of(source: &str, disable_fold: bool) -> String {
    let opts = CompileOptions {
        disable_constant_folding: disable_fold,
        ..CompileOptions::default()
    };
    let r = compile_from_source_str_with_result(source, Some("AssertThenAsm.runar.ts"), &opts);
    assert!(
        r.success,
        "compile failed: {:?}",
        r.diagnostics.iter().map(|d| d.message.clone()).collect::<Vec<_>>()
    );
    r.script_hex.expect("compiled script hex")
}

#[test]
fn n005_assert_before_terminal_asm_is_verified() {
    for disable_fold in [true, false] {
        let got = hex_of(ASSERT_THEN_ASM, disable_fold);
        assert_ne!(got, "012a9c5177", "fold-off={disable_fold}: assert left unenforced");
        assert_eq!(got, "012a9d51", "fold-off={disable_fold}: want <42> OP_NUMEQUALVERIFY OP_1");
    }
}

#[test]
fn n005_final_assert_stays_the_result() {
    // OP_1 OP_SWAP <42> OP_NUMEQUAL (terminal, no OP_VERIFY) OP_NIP
    assert_eq!(hex_of(ASM_THEN_ASSERT, true), "517c012a9c77");
}
