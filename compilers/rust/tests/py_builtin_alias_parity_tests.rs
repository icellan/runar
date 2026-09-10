//! R-039 — irregular Python builtin aliases must map identically in all 7 tiers.
//!
//! Python contracts are written in snake_case and every tier's `.runar.py`
//! parser rewrites the identifiers to the canonical Rúnar camelCase names. Most
//! names fall out of a mechanical snake→camel rule, but five do not and
//! therefore need an explicit entry in each tier's special-name table:
//!
//!   int_to_str           -> int2str            (digit: "to" collapses to "2")
//!   safe_div             -> safediv            (no interior capital)
//!   safe_mod             -> safemod            (no interior capital)
//!   div_mod              -> divmod             (no interior capital)
//!   require_output_p2pkh -> requireOutputP2PKH (all-caps PKH token)
//!
//! Before this test the Rust tier had none of them: the mechanical rule
//! produced `intToStr` / `safeDiv` / `safeMod` / `divMod` /
//! `requireOutputP2pkh`, all of which the type checker rejects as unknown
//! functions, while the Python and Java tiers compiled the very same source.
//! CLAUDE.md makes frontend parity a no-exceptions invariant, so that is a
//! parity break, not a nicety.
//!
//! The pinned hexes are the SEVEN-TIER agreed fold-OFF output.

use runar_compiler_rust::{compile_from_source_str_with_options, CompileOptions};

const INT2STR_SNAKE: &str = r#"
from runar import SmartContract, Bigint, ByteString, public, assert_, int_to_str, len_


class Encoder(SmartContract):
    n: Bigint

    def __init__(self, n: Bigint):
        super().__init__(n)
        self.n = n

    @public
    def unlock(self):
        out: ByteString = int_to_str(self.n, 4)
        assert_(len_(out) == 4)
"#;

const MATH_ALIASES: &str = r#"
from runar import SmartContract, Bigint, public, assert_


class Aliases(SmartContract):
    n: Bigint

    def __init__(self, n: Bigint):
        super().__init__(n)
        self.n = n

    @public
    def unlock(self):
        a: Bigint = safe_div(self.n, 3)
        b: Bigint = safe_mod(self.n, 3)
        c: Bigint = div_mod(self.n, 3)
        assert_(a + b + c > 0)
"#;

const INTENT_SNAKE: &str = r#"
from runar import (
    StatefulSmartContract, ByteString, Bigint, Readonly, public,
)


class Intent(StatefulSmartContract):
    bondPKH: Readonly[ByteString]
    bondAmount: Readonly[Bigint]
    count: Bigint

    def __init__(self, bondPKH: ByteString, bondAmount: Bigint, count: Bigint):
        super().__init__(bondPKH, bondAmount, count)
        self.bondPKH = bondPKH
        self.bondAmount = bondAmount
        self.count = count

    @public
    def payBond(self):
        require_output_p2pkh(0, self.bondPKH, self.bondAmount)
"#;

const UNKNOWN_BUILTIN: &str = r#"
from runar import SmartContract, Bigint, public, assert_


class Unknown(SmartContract):
    n: Bigint

    def __init__(self, n: Bigint):
        super().__init__(n)
        self.n = n

    @public
    def unlock(self):
        assert_(not_a_builtin(self.n) > 0)
"#;

fn compile_script_hex(source: &str, file_name: &str) -> String {
    let opts = CompileOptions {
        disable_constant_folding: true,
        ..CompileOptions::default()
    };
    match compile_from_source_str_with_options(source, Some(file_name), &opts) {
        Ok(artifact) => artifact.script,
        Err(e) => panic!("compilation of {} failed: {}", file_name, e),
    }
}

#[test]
fn int_to_str_lowers_to_the_seven_tier_script() {
    assert_eq!(
        compile_script_hex(INT2STR_SNAKE, "Encoder.runar.py"),
        "0054808277549c"
    );
}

#[test]
fn math_aliases_lower_to_the_seven_tier_script() {
    assert_eq!(
        compile_script_hex(MATH_ALIASES, "Aliases.runar.py"),
        "00537692699600537692699700536e967b7b97757b7b937c9300a0"
    );
}

#[test]
fn require_output_p2pkh_matches_camel_case() {
    let camel = INTENT_SNAKE.replace("require_output_p2pkh", "requireOutputP2PKH");
    assert_eq!(
        compile_script_hex(INTENT_SNAKE, "Intent.runar.py"),
        compile_script_hex(&camel, "Intent.runar.py")
    );
}

#[test]
fn unknown_snake_case_function_is_still_rejected() {
    // Guards against the lazy fix: a blanket pass-through that maps any
    // snake_case identifier onto a builtin name would let this compile.
    let opts = CompileOptions {
        disable_constant_folding: true,
        ..CompileOptions::default()
    };
    match compile_from_source_str_with_options(UNKNOWN_BUILTIN, Some("Unknown.runar.py"), &opts) {
        Ok(_) => panic!("expected not_a_builtin() to be rejected, but compilation succeeded"),
        Err(e) => assert!(
            e.to_string().contains("notABuiltin"),
            "expected an unknown-function diagnostic for notABuiltin, got: {}",
            e
        ),
    }
}
