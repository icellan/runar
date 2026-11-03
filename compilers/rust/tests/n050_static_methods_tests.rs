//! N-050 (external StaticSiphon) — a static / class-level method is not a
//! contract method and must never become a spending entry point.
//!
//! Before the fix this tier compiled `public static requirePositive(amount)`
//! on .runar.ts, `@Public static` on .runar.java and `@public @staticmethod`
//! on .runar.py into dispatch selectors (unsigned spend paths).
//!
//! The rule (TS reference, `staticMethodMessage` in errors.ts): every surface
//! that can spell a static method refuses it, public or private, with
//!
//!     static methods are not allowed in Rúnar contracts; method '<m>' is declared static
//!
//! (<m> as written in the source). On .runar.rs / .runar.zig the spelling is a
//! `pub fn` without a self receiver; a private receiver-less `fn` stays a
//! helper, like a Go free function (R9).
//!
//! What this proves: the Rust tier's frontend refuses every spelling with the
//! reference text, and the non-static spellings still parse with the same
//! method visibilities.
//! What it does NOT prove: the other tiers (their own suites, the runar-testing
//! n050 spend test and conformance/negatives/N104-N111), or anything on chain.

use runar_compiler_rust::frontend::ast::Visibility;
use runar_compiler_rust::frontend::parser::parse_source;

fn msg(name: &str) -> String {
    format!("static methods are not allowed in Rúnar contracts; method '{}' is declared static", name)
}

fn ts(decl: &str) -> String {
    format!(
        "import {{ SmartContract, Sig, PubKey, assert, checkSig }} from 'runar-lang';\nexport class Vault extends SmartContract {{\n  readonly owner: PubKey;\n  constructor(owner: PubKey) {{ super(owner); this.owner = owner; }}\n  {} requirePositive(amount: bigint) {{ assert(amount > 0n); }}\n  public withdraw(sig: Sig) {{ assert(checkSig(sig, this.owner)); }}\n}}\n",
        decl
    )
}

fn java(decl: &str) -> String {
    format!(
        "package x;\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\nimport runar.lang.annotations.Readonly;\nimport runar.lang.types.PubKey;\nimport runar.lang.types.Sig;\nimport java.math.BigInteger;\nimport static runar.lang.Builtins.assertThat;\nimport static runar.lang.Builtins.checkSig;\nclass Vault extends SmartContract {{\n    @Readonly PubKey owner;\n    Vault(PubKey owner) {{ super(owner); this.owner = owner; }}\n    {} void requirePositive(BigInteger amount) {{ assertThat(amount.compareTo(BigInteger.ZERO) > 0); }}\n    @Public\n    void withdraw(Sig sig) {{ assertThat(checkSig(sig, owner)); }}\n}}\n",
        decl
    )
}

fn py(decorators: &str, params: &str) -> String {
    format!(
        "from runar import SmartContract, Sig, PubKey, public, assert_, check_sig\n\nclass Vault(SmartContract):\n    owner: PubKey\n\n    def __init__(self, owner: PubKey):\n        super().__init__(owner)\n        self.owner = owner\n\n{}\n    def require_positive({}):\n        assert_(amount > 0)\n\n    @public\n    def withdraw(self, sig: Sig):\n        assert_(check_sig(sig, self.owner))\n",
        decorators, params
    )
}

fn rb(marker: &str, def: &str) -> String {
    format!(
        "require 'runar'\n\nclass Vault < Runar::SmartContract\n  prop :owner, PubKey\n\n  def initialize(owner)\n    super(owner)\n    @owner = owner\n  end\n{}\n  def {}(amount)\n    assert amount > 0\n  end\n\n  runar_public sig: Sig\n  def withdraw(sig)\n    assert check_sig(sig, @owner)\n  end\nend\n",
        marker, def
    )
}

fn rs(func: &str) -> String {
    format!(
        "use runar::prelude::*;\n\n#[runar::contract]\nstruct Vault {{\n    #[readonly]\n    owner: PubKey,\n}}\n\nimpl Vault {{\n    {}\n\n    pub fn withdraw(&self, sig: &Sig) {{\n        assert!(check_sig(sig, &self.owner));\n    }}\n}}\n",
        func
    )
}

fn zig(func: &str) -> String {
    format!(
        "const runar = @import(\"runar\");\n\npub const Vault = struct {{\n    pub const Contract = runar.SmartContract;\n\n    owner: runar.PubKey,\n\n    pub fn init(owner: runar.PubKey) Vault {{\n        return .{{ .owner = owner }};\n    }}\n\n    {}\n\n    pub fn withdraw(self: *const Vault, sig: runar.Sig) void {{\n        runar.assert(runar.checkSig(sig, self.owner));\n    }}\n}};\n",
        func
    )
}

const RS_NO_SELF: &str = "pub fn require_positive(amount: Int) {\n        assert!(amount > 0);\n    }";
const ZIG_NO_SELF: &str = "pub fn requirePositive(amount: i64) void {\n        runar.assert(amount > 0);\n    }";

#[test]
fn n050_every_static_spelling_is_refused_with_the_shared_diagnostic() {
    let cases: Vec<(&str, String, &str, &str)> = vec![
        ("ts public static", ts("public static"), "Vault.runar.ts", "requirePositive"),
        ("ts private static", ts("private static"), "Vault.runar.ts", "requirePositive"),
        ("ts static", ts("static"), "Vault.runar.ts", "requirePositive"),
        ("java @Public static", java("@Public static"), "Vault.runar.java", "requirePositive"),
        ("java @Public public static", java("@Public public static"), "Vault.runar.java", "requirePositive"),
        ("java static", java("static"), "Vault.runar.java", "requirePositive"),
        ("java private static", java("private static"), "Vault.runar.java", "requirePositive"),
        ("java @Public static final", java("@Public static final"), "Vault.runar.java", "requirePositive"),
        ("py @public @staticmethod", py("    @public\n    @staticmethod", "amount: int"), "Vault.runar.py", "require_positive"),
        ("py @staticmethod @public", py("    @staticmethod\n    @public", "amount: int"), "Vault.runar.py", "require_positive"),
        ("py @staticmethod", py("    @staticmethod", "amount: int"), "Vault.runar.py", "require_positive"),
        ("py @public @classmethod", py("    @public\n    @classmethod", "cls, amount: int"), "Vault.runar.py", "require_positive"),
        ("py @classmethod", py("    @classmethod", "cls, amount: int"), "Vault.runar.py", "require_positive"),
        ("rb runar_public def self.x", rb("  runar_public amount: Bigint", "self.require_positive"), "Vault.runar.rb", "require_positive"),
        ("rb params def self.x", rb("  params amount: Bigint", "self.require_positive"), "Vault.runar.rb", "require_positive"),
        ("rb def Vault.x", rb("  runar_public amount: Bigint", "Vault.require_positive"), "Vault.runar.rb", "require_positive"),
        ("rs pub fn without self", rs(RS_NO_SELF), "Vault.runar.rs", "require_positive"),
        ("zig pub fn without receiver", zig(ZIG_NO_SELF), "Vault.runar.zig", "requirePositive"),
    ];
    let mut failures = Vec::new();
    for (label, src, file, name) in &cases {
        let errs: Vec<String> = parse_source(src, Some(file)).errors.into_iter().map(|d| d.message).collect();
        if !errs.contains(&msg(name)) {
            failures.push(format!("{}: expected {:?}, got {:?}", label, msg(name), errs));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn n050_non_static_spellings_still_parse() {
    let cases: Vec<(&str, String, &str, [&str; 2])> = vec![
        ("ts public", ts("public"), "Vault.runar.ts", ["requirePositive:public", "withdraw:public"]),
        ("ts private", ts("private"), "Vault.runar.ts", ["requirePositive:private", "withdraw:public"]),
        ("java @Public", java("@Public"), "Vault.runar.java", ["requirePositive:public", "withdraw:public"]),
        ("java private", java("private"), "Vault.runar.java", ["requirePositive:private", "withdraw:public"]),
        ("py instance", py("    @public", "self, amount: int"), "Vault.runar.py", ["requirePositive:public", "withdraw:public"]),
        ("rb instance", rb("  runar_public amount: Bigint", "require_positive"), "Vault.runar.rb", ["requirePositive:public", "withdraw:public"]),
        ("rs pub fn &self", rs("pub fn require_positive(&self, amount: Int) {\n        assert!(amount > 0);\n    }"), "Vault.runar.rs", ["requirePositive:public", "withdraw:public"]),
        ("rs private helper without self", rs("fn require_positive(amount: Int) {\n        assert!(amount > 0);\n    }"), "Vault.runar.rs", ["requirePositive:private", "withdraw:public"]),
        ("zig pub fn with receiver", zig("pub fn requirePositive(self: *const Vault, amount: i64) void {\n        _ = self;\n        runar.assert(amount > 0);\n    }"), "Vault.runar.zig", ["requirePositive:public", "withdraw:public"]),
        ("zig private helper without receiver", zig("fn requirePositive(amount: i64) void {\n        runar.assert(amount > 0);\n    }"), "Vault.runar.zig", ["requirePositive:private", "withdraw:public"]),
    ];
    for (label, src, file, want) in &cases {
        let r = parse_source(src, Some(file));
        let errs: Vec<String> = r.errors.iter().map(|d| d.message.clone()).collect();
        assert!(errs.is_empty(), "{}: unexpected errors {:?}", label, errs);
        let got: Vec<String> = r
            .contract
            .expect("contract")
            .methods
            .iter()
            .map(|m| format!("{}:{}", m.name, if m.visibility == Visibility::Public { "public" } else { "private" }))
            .collect();
        assert_eq!(got, want.to_vec(), "{}", label);
    }
}
