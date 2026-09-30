"""N-050 (external StaticSiphon) — a static / class-level method is not a
contract method and must never become a spending entry point.

Before the fix this tier refused ``public static`` on .runar.ts only by
accident ("Contract has no public methods"), compiled ``@Public static`` on
.runar.java into a dispatch selector (an unsigned spend path), and refused
``@public @staticmethod`` on .runar.py with an unrelated parse error.

The rule (TS reference, ``staticMethodMessage`` in errors.ts): every surface
that can spell a static method refuses it, public or private, with

    static methods are not allowed in Rúnar contracts; method '<m>' is declared static

(<m> as written in the source). On .runar.rs / .runar.zig the spelling is a
``pub fn`` without a self receiver; a private receiver-less ``fn`` stays a
helper, like a Go free function (R9).

What this proves: the Python tier's frontend refuses every spelling with the
reference text, and the non-static spellings still parse with the same method
visibilities.
What it does NOT prove: the other tiers (their own suites, the runar-testing
n050 spend test and conformance/negatives/N104-N111), or anything on chain.
"""
from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source


def _msg(name: str) -> str:
    return f"static methods are not allowed in Rúnar contracts; method '{name}' is declared static"


def _ts(decl: str) -> str:
    return (
        "import { SmartContract, Sig, PubKey, assert, checkSig } from 'runar-lang';\n"
        "export class Vault extends SmartContract {\n"
        "  readonly owner: PubKey;\n"
        "  constructor(owner: PubKey) { super(owner); this.owner = owner; }\n"
        f"  {decl} requirePositive(amount: bigint) {{ assert(amount > 0n); }}\n"
        "  public withdraw(sig: Sig) { assert(checkSig(sig, this.owner)); }\n"
        "}\n"
    )


def _java(decl: str) -> str:
    return (
        "package x;\n"
        "import runar.lang.SmartContract;\n"
        "import runar.lang.annotations.Public;\n"
        "import runar.lang.annotations.Readonly;\n"
        "import runar.lang.types.PubKey;\n"
        "import runar.lang.types.Sig;\n"
        "import java.math.BigInteger;\n"
        "import static runar.lang.Builtins.assertThat;\n"
        "import static runar.lang.Builtins.checkSig;\n"
        "class Vault extends SmartContract {\n"
        "    @Readonly PubKey owner;\n"
        "    Vault(PubKey owner) { super(owner); this.owner = owner; }\n"
        f"    {decl} void requirePositive(BigInteger amount) {{ assertThat(amount.compareTo(BigInteger.ZERO) > 0); }}\n"
        "    @Public\n"
        "    void withdraw(Sig sig) { assertThat(checkSig(sig, owner)); }\n"
        "}\n"
    )


def _py(decorators: str, params: str) -> str:
    return (
        "from runar import SmartContract, Sig, PubKey, public, assert_, check_sig\n\n"
        "class Vault(SmartContract):\n"
        "    owner: PubKey\n\n"
        "    def __init__(self, owner: PubKey):\n"
        "        super().__init__(owner)\n"
        "        self.owner = owner\n\n"
        f"{decorators}\n"
        f"    def require_positive({params}):\n"
        "        assert_(amount > 0)\n\n"
        "    @public\n"
        "    def withdraw(self, sig: Sig):\n"
        "        assert_(check_sig(sig, self.owner))\n"
    )


def _rb(marker: str, name: str) -> str:
    return (
        "require 'runar'\n\n"
        "class Vault < Runar::SmartContract\n"
        "  prop :owner, PubKey\n\n"
        "  def initialize(owner)\n"
        "    super(owner)\n"
        "    @owner = owner\n"
        "  end\n"
        f"{marker}\n"
        f"  def {name}(amount)\n"
        "    assert amount > 0\n"
        "  end\n\n"
        "  runar_public sig: Sig\n"
        "  def withdraw(sig)\n"
        "    assert check_sig(sig, @owner)\n"
        "  end\n"
        "end\n"
    )


def _rs(fn: str) -> str:
    return (
        "use runar::prelude::*;\n\n"
        "#[runar::contract]\n"
        "struct Vault {\n"
        "    #[readonly]\n"
        "    owner: PubKey,\n"
        "}\n\n"
        "impl Vault {\n"
        f"    {fn}\n\n"
        "    pub fn withdraw(&self, sig: &Sig) {\n"
        "        assert!(check_sig(sig, &self.owner));\n"
        "    }\n"
        "}\n"
    )


def _zig(fn: str) -> str:
    return (
        'const runar = @import("runar");\n\n'
        "pub const Vault = struct {\n"
        "    pub const Contract = runar.SmartContract;\n\n"
        "    owner: runar.PubKey,\n\n"
        "    pub fn init(owner: runar.PubKey) Vault {\n"
        "        return .{ .owner = owner };\n"
        "    }\n\n"
        f"    {fn}\n\n"
        "    pub fn withdraw(self: *const Vault, sig: runar.Sig) void {\n"
        "        runar.assert(runar.checkSig(sig, self.owner));\n"
        "    }\n"
        "};\n"
    )


_REFUSED = [
    ("ts public static", _ts("public static"), "Vault.runar.ts", "requirePositive"),
    ("ts private static", _ts("private static"), "Vault.runar.ts", "requirePositive"),
    ("ts static", _ts("static"), "Vault.runar.ts", "requirePositive"),
    ("java @Public static", _java("@Public static"), "Vault.runar.java", "requirePositive"),
    ("java @Public public static", _java("@Public public static"), "Vault.runar.java", "requirePositive"),
    ("java static", _java("static"), "Vault.runar.java", "requirePositive"),
    ("java private static", _java("private static"), "Vault.runar.java", "requirePositive"),
    ("java @Public static final", _java("@Public static final"), "Vault.runar.java", "requirePositive"),
    ("py @public @staticmethod", _py("    @public\n    @staticmethod", "amount: int"), "Vault.runar.py", "require_positive"),
    ("py @staticmethod @public", _py("    @staticmethod\n    @public", "amount: int"), "Vault.runar.py", "require_positive"),
    ("py @staticmethod", _py("    @staticmethod", "amount: int"), "Vault.runar.py", "require_positive"),
    ("py @public @classmethod", _py("    @public\n    @classmethod", "cls, amount: int"), "Vault.runar.py", "require_positive"),
    ("py @classmethod", _py("    @classmethod", "cls, amount: int"), "Vault.runar.py", "require_positive"),
    ("rb runar_public def self.x", _rb("  runar_public amount: Bigint", "self.require_positive"), "Vault.runar.rb", "require_positive"),
    ("rb params def self.x", _rb("  params amount: Bigint", "self.require_positive"), "Vault.runar.rb", "require_positive"),
    ("rb def Vault.x", _rb("  runar_public amount: Bigint", "Vault.require_positive"), "Vault.runar.rb", "require_positive"),
    ("rs pub fn without self", _rs("pub fn require_positive(amount: Int) {\n        assert!(amount > 0);\n    }"), "Vault.runar.rs", "require_positive"),
    ("zig pub fn without receiver", _zig("pub fn requirePositive(amount: i64) void {\n        runar.assert(amount > 0);\n    }"), "Vault.runar.zig", "requirePositive"),
]


@pytest.mark.parametrize("label,src,file,name", _REFUSED, ids=[c[0] for c in _REFUSED])
def test_n050_static_spelling_is_refused(label, src, file, name):
    msgs = [e.message for e in parse_source(src, file).errors]
    assert _msg(name) in msgs, f"{label}: got {msgs}"


_KEPT = [
    ("ts public", _ts("public"), "Vault.runar.ts", ["requirePositive:public", "withdraw:public"]),
    ("ts private", _ts("private"), "Vault.runar.ts", ["requirePositive:private", "withdraw:public"]),
    ("java @Public", _java("@Public"), "Vault.runar.java", ["requirePositive:public", "withdraw:public"]),
    ("java private", _java("private"), "Vault.runar.java", ["requirePositive:private", "withdraw:public"]),
    ("py instance", _py("    @public", "self, amount: int"), "Vault.runar.py", ["requirePositive:public", "withdraw:public"]),
    ("rb instance", _rb("  runar_public amount: Bigint", "require_positive"), "Vault.runar.rb", ["requirePositive:public", "withdraw:public"]),
    ("rs pub fn &self", _rs("pub fn require_positive(&self, amount: Int) {\n        assert!(amount > 0);\n    }"), "Vault.runar.rs", ["requirePositive:public", "withdraw:public"]),
    ("rs private helper without self", _rs("fn require_positive(amount: Int) {\n        assert!(amount > 0);\n    }"), "Vault.runar.rs", ["requirePositive:private", "withdraw:public"]),
    ("zig pub fn with receiver", _zig("pub fn requirePositive(self: *const Vault, amount: i64) void {\n        _ = self;\n        runar.assert(amount > 0);\n    }"), "Vault.runar.zig", ["requirePositive:public", "withdraw:public"]),
    ("zig private helper without receiver", _zig("fn requirePositive(amount: i64) void {\n        runar.assert(amount > 0);\n    }"), "Vault.runar.zig", ["requirePositive:private", "withdraw:public"]),
]


@pytest.mark.parametrize("label,src,file,want", _KEPT, ids=[c[0] for c in _KEPT])
def test_n050_non_static_spelling_still_parses(label, src, file, want):
    r = parse_source(src, file)
    assert [e.message for e in r.errors] == [], label
    assert [f"{m.name}:{m.visibility}" for m in r.contract.methods] == want, label
