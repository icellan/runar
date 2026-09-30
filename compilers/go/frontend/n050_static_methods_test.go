package frontend

import (
	"strings"
	"testing"
)

// N-050 (external StaticSiphon) — a static / class-level method is not a
// contract method and must never become a spending entry point.
//
// Before the fix this tier compiled `public static requirePositive(amount)`
// on .runar.ts into a dispatch selector (an unsigned spend path), and refused
// `@Public static` on .runar.java and `@public @staticmethod` on .runar.py
// only with an unrelated parse error.
//
// The rule (TS reference, staticMethodMessage in errors.ts): every surface
// that can spell a static method refuses it, public or private, with
//
//	static methods are not allowed in Rúnar contracts; method '<m>' is declared static
//
// (<m> as written in the source). On .runar.rs / .runar.zig the spelling is a
// `pub fn` without a self receiver; a private receiver-less `fn` stays a
// helper, like a Go free function (R9).
//
// What this proves: the Go tier's frontend refuses every spelling with the
// reference text, and the non-static spellings still parse with the same
// method visibilities.
// What it does NOT prove: the other tiers (their own suites, the runar-testing
// n050 spend test and conformance/negatives/N104-N111), or anything on chain.

func n050Msg(name string) string {
	return "static methods are not allowed in Rúnar contracts; method '" + name + "' is declared static"
}

func n050Ts(decl string) string {
	return `import { SmartContract, Sig, PubKey, assert, checkSig } from 'runar-lang';
export class Vault extends SmartContract {
  readonly owner: PubKey;
  constructor(owner: PubKey) { super(owner); this.owner = owner; }
  ` + decl + ` requirePositive(amount: bigint) { assert(amount > 0n); }
  public withdraw(sig: Sig) { assert(checkSig(sig, this.owner)); }
}
`
}

func n050Java(decl string) string {
	return `package x;
import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;
import java.math.BigInteger;
import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
class Vault extends SmartContract {
    @Readonly PubKey owner;
    Vault(PubKey owner) { super(owner); this.owner = owner; }
    ` + decl + ` void requirePositive(BigInteger amount) { assertThat(amount.compareTo(BigInteger.ZERO) > 0); }
    @Public
    void withdraw(Sig sig) { assertThat(checkSig(sig, owner)); }
}
`
}

func n050Py(decorators, params string) string {
	return `from runar import SmartContract, Sig, PubKey, public, assert_, check_sig

class Vault(SmartContract):
    owner: PubKey

    def __init__(self, owner: PubKey):
        super().__init__(owner)
        self.owner = owner

` + decorators + `
    def require_positive(` + params + `):
        assert_(amount > 0)

    @public
    def withdraw(self, sig: Sig):
        assert_(check_sig(sig, self.owner))
`
}

func n050Rb(marker, def string) string {
	return `require 'runar'

class Vault < Runar::SmartContract
  prop :owner, PubKey

  def initialize(owner)
    super(owner)
    @owner = owner
  end
` + marker + `
  def ` + def + `(amount)
    assert amount > 0
  end

  runar_public sig: Sig
  def withdraw(sig)
    assert check_sig(sig, @owner)
  end
end
`
}

func n050Rs(fn string) string {
	return `use runar::prelude::*;

#[runar::contract]
struct Vault {
    #[readonly]
    owner: PubKey,
}

impl Vault {
    ` + fn + `

    pub fn withdraw(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.owner));
    }
}
`
}

func n050Zig(fn string) string {
	return `const runar = @import("runar");

pub const Vault = struct {
    pub const Contract = runar.SmartContract;

    owner: runar.PubKey,

    pub fn init(owner: runar.PubKey) Vault {
        return .{ .owner = owner };
    }

    ` + fn + `

    pub fn withdraw(self: *const Vault, sig: runar.Sig) void {
        runar.assert(runar.checkSig(sig, self.owner));
    }
};
`
}

func TestN050_StaticMethodsRefused(t *testing.T) {
	cases := []struct {
		label, file, src, name string
	}{
		{"ts public static", "Vault.runar.ts", n050Ts("public static"), "requirePositive"},
		{"ts private static", "Vault.runar.ts", n050Ts("private static"), "requirePositive"},
		{"ts static", "Vault.runar.ts", n050Ts("static"), "requirePositive"},
		{"java @Public static", "Vault.runar.java", n050Java("@Public static"), "requirePositive"},
		{"java @Public public static", "Vault.runar.java", n050Java("@Public public static"), "requirePositive"},
		{"java static", "Vault.runar.java", n050Java("static"), "requirePositive"},
		{"java private static", "Vault.runar.java", n050Java("private static"), "requirePositive"},
		{"java @Public static final", "Vault.runar.java", n050Java("@Public static final"), "requirePositive"},
		{"py @public @staticmethod", "Vault.runar.py", n050Py("    @public\n    @staticmethod", "amount: int"), "require_positive"},
		{"py @staticmethod @public", "Vault.runar.py", n050Py("    @staticmethod\n    @public", "amount: int"), "require_positive"},
		{"py @staticmethod", "Vault.runar.py", n050Py("    @staticmethod", "amount: int"), "require_positive"},
		{"py @public @classmethod", "Vault.runar.py", n050Py("    @public\n    @classmethod", "cls, amount: int"), "require_positive"},
		{"py @classmethod", "Vault.runar.py", n050Py("    @classmethod", "cls, amount: int"), "require_positive"},
		{"rb runar_public def self.x", "Vault.runar.rb", n050Rb("  runar_public amount: Bigint", "self.require_positive"), "require_positive"},
		{"rb params def self.x", "Vault.runar.rb", n050Rb("  params amount: Bigint", "self.require_positive"), "require_positive"},
		{"rb def Vault.x", "Vault.runar.rb", n050Rb("  runar_public amount: Bigint", "Vault.require_positive"), "require_positive"},
		{"rs pub fn without self", "Vault.runar.rs", n050Rs("pub fn require_positive(amount: Int) {\n        assert!(amount > 0);\n    }"), "require_positive"},
		{"zig pub fn without receiver", "Vault.runar.zig", n050Zig("pub fn requirePositive(amount: i64) void {\n        runar.assert(amount > 0);\n    }"), "requirePositive"},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			res := ParseSource([]byte(c.src), c.file)
			var msgs []string
			found := false
			for _, e := range res.Errors {
				msgs = append(msgs, e.Message)
				if e.Message == n050Msg(c.name) {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s: expected %q, got errors %q", c.label, n050Msg(c.name), msgs)
			}
		})
	}
}

func TestN050_NonStaticSpellingsStillParse(t *testing.T) {
	cases := []struct {
		label, file, src string
		want             []string
	}{
		{"ts public", "Vault.runar.ts", n050Ts("public"), []string{"requirePositive:public", "withdraw:public"}},
		{"ts private", "Vault.runar.ts", n050Ts("private"), []string{"requirePositive:private", "withdraw:public"}},
		{"java @Public", "Vault.runar.java", n050Java("@Public"), []string{"requirePositive:public", "withdraw:public"}},
		{"java private", "Vault.runar.java", n050Java("private"), []string{"requirePositive:private", "withdraw:public"}},
		{"py instance", "Vault.runar.py", n050Py("    @public", "self, amount: int"), []string{"requirePositive:public", "withdraw:public"}},
		{"rb instance", "Vault.runar.rb", n050Rb("  runar_public amount: Bigint", "require_positive"), []string{"requirePositive:public", "withdraw:public"}},
		{"rs pub fn &self", "Vault.runar.rs", n050Rs("pub fn require_positive(&self, amount: Int) {\n        assert!(amount > 0);\n    }"), []string{"requirePositive:public", "withdraw:public"}},
		{"rs private helper without self", "Vault.runar.rs", n050Rs("fn require_positive(amount: Int) {\n        assert!(amount > 0);\n    }"), []string{"requirePositive:private", "withdraw:public"}},
		{"zig pub fn with receiver", "Vault.runar.zig", n050Zig("pub fn requirePositive(self: *const Vault, amount: i64) void {\n        _ = self;\n        runar.assert(amount > 0);\n    }"), []string{"requirePositive:public", "withdraw:public"}},
		{"zig private helper without receiver", "Vault.runar.zig", n050Zig("fn requirePositive(amount: i64) void {\n        runar.assert(amount > 0);\n    }"), []string{"requirePositive:private", "withdraw:public"}},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			res := ParseSource([]byte(c.src), c.file)
			for _, e := range res.Errors {
				if e.Severity == SeverityError {
					t.Fatalf("%s: unexpected error %q", c.label, e.Message)
				}
			}
			if res.Contract == nil {
				t.Fatalf("%s: no contract", c.label)
			}
			var got []string
			for _, m := range res.Contract.Methods {
				got = append(got, m.Name+":"+m.Visibility)
			}
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Fatalf("%s: methods %v, want %v", c.label, got, c.want)
			}
		})
	}
}
