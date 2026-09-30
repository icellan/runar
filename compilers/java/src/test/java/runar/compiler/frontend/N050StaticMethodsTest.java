package runar.compiler.frontend;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.MethodNode;

/**
 * N-050 (external StaticSiphon) — a static / class-level method is not a
 * contract method and must never become a spending entry point.
 *
 * <p>Before the fix this tier refused {@code public static} on .runar.ts only
 * by accident ("Contract has no public methods"), and compiled
 * {@code @Public static} on .runar.java and a receiver-less {@code pub fn} on
 * .runar.rs / .runar.zig into dispatch selectors (unsigned spend paths).
 *
 * <p>The rule (TS reference, {@code staticMethodMessage} in errors.ts): every
 * surface that can spell a static method refuses it, public or private, with
 * {@code static methods are not allowed in Rúnar contracts; method '<m>' is
 * declared static} (&lt;m&gt; as written in the source). On .runar.rs /
 * .runar.zig the spelling is a {@code pub fn} without a self receiver; a
 * private receiver-less {@code fn} stays a helper, like a Go free function (R9).
 *
 * <p>What this proves: the Java tier's frontend refuses every spelling with the
 * reference text, and the non-static spellings still parse with the same
 * method visibilities.
 *
 * <p>What it does NOT prove: the other tiers (their own suites, the
 * runar-testing n050 spend test and conformance/negatives/N104-N111), or
 * anything on chain.
 */
class N050StaticMethodsTest {

    private static String msg(String name) {
        return "static methods are not allowed in Rúnar contracts; method '" + name + "' is declared static";
    }

    private static String ts(String decl) {
        return "import { SmartContract, Sig, PubKey, assert, checkSig } from 'runar-lang';\n"
            + "export class Vault extends SmartContract {\n"
            + "  readonly owner: PubKey;\n"
            + "  constructor(owner: PubKey) { super(owner); this.owner = owner; }\n"
            + "  " + decl + " requirePositive(amount: bigint) { assert(amount > 0n); }\n"
            + "  public withdraw(sig: Sig) { assert(checkSig(sig, this.owner)); }\n"
            + "}\n";
    }

    private static String java(String decl) {
        return "package x;\n"
            + "import runar.lang.SmartContract;\n"
            + "import runar.lang.annotations.Public;\n"
            + "import runar.lang.annotations.Readonly;\n"
            + "import runar.lang.types.PubKey;\n"
            + "import runar.lang.types.Sig;\n"
            + "import java.math.BigInteger;\n"
            + "import static runar.lang.Builtins.assertThat;\n"
            + "import static runar.lang.Builtins.checkSig;\n"
            + "class Vault extends SmartContract {\n"
            + "    @Readonly PubKey owner;\n"
            + "    Vault(PubKey owner) { super(owner); this.owner = owner; }\n"
            + "    " + decl + " void requirePositive(BigInteger amount) { assertThat(amount.compareTo(BigInteger.ZERO) > 0); }\n"
            + "    @Public\n"
            + "    void withdraw(Sig sig) { assertThat(checkSig(sig, owner)); }\n"
            + "}\n";
    }

    private static String py(String decorators, String params) {
        return "from runar import SmartContract, Sig, PubKey, public, assert_, check_sig\n\n"
            + "class Vault(SmartContract):\n"
            + "    owner: PubKey\n\n"
            + "    def __init__(self, owner: PubKey):\n"
            + "        super().__init__(owner)\n"
            + "        self.owner = owner\n\n"
            + decorators + "\n"
            + "    def require_positive(" + params + "):\n"
            + "        assert_(amount > 0)\n\n"
            + "    @public\n"
            + "    def withdraw(self, sig: Sig):\n"
            + "        assert_(check_sig(sig, self.owner))\n";
    }

    private static String rb(String marker, String def) {
        return "require 'runar'\n\n"
            + "class Vault < Runar::SmartContract\n"
            + "  prop :owner, PubKey\n\n"
            + "  def initialize(owner)\n"
            + "    super(owner)\n"
            + "    @owner = owner\n"
            + "  end\n"
            + marker + "\n"
            + "  def " + def + "(amount)\n"
            + "    assert amount > 0\n"
            + "  end\n\n"
            + "  runar_public sig: Sig\n"
            + "  def withdraw(sig)\n"
            + "    assert check_sig(sig, @owner)\n"
            + "  end\n"
            + "end\n";
    }

    private static String rs(String fn) {
        return "use runar::prelude::*;\n\n"
            + "#[runar::contract]\n"
            + "struct Vault {\n"
            + "    #[readonly]\n"
            + "    owner: PubKey,\n"
            + "}\n\n"
            + "impl Vault {\n"
            + "    " + fn + "\n\n"
            + "    pub fn withdraw(&self, sig: &Sig) {\n"
            + "        assert!(check_sig(sig, &self.owner));\n"
            + "    }\n"
            + "}\n";
    }

    private static String zig(String fn) {
        return "const runar = @import(\"runar\");\n\n"
            + "pub const Vault = struct {\n"
            + "    pub const Contract = runar.SmartContract;\n\n"
            + "    owner: runar.PubKey,\n\n"
            + "    pub fn init(owner: runar.PubKey) Vault {\n"
            + "        return .{ .owner = owner };\n"
            + "    }\n\n"
            + "    " + fn + "\n\n"
            + "    pub fn withdraw(self: *const Vault, sig: runar.Sig) void {\n"
            + "        runar.assert(runar.checkSig(sig, self.owner));\n"
            + "    }\n"
            + "};\n";
    }

    private static final String RS_NO_SELF = "pub fn require_positive(amount: Int) {\n        assert!(amount > 0);\n    }";
    private static final String ZIG_NO_SELF = "pub fn requirePositive(amount: i64) void {\n        runar.assert(amount > 0);\n    }";

    private static void assertRefused(String label, String source, String fileName, String name) {
        try {
            ParserDispatch.parse(source, fileName);
        } catch (ParserDispatch.ParseException e) {
            assertTrue(e.getMessage().contains(msg(name)),
                label + ": expected '" + msg(name) + "', got: " + e.getMessage());
            return;
        }
        fail(label + ": " + fileName + " was accepted; a static method must be refused");
    }

    private static void assertMethods(String label, String source, String fileName, List<String> expected) {
        ContractNode c;
        try {
            c = ParserDispatch.parse(source, fileName);
        } catch (ParserDispatch.ParseException e) {
            fail(label + ": unexpected refusal: " + e.getMessage());
            return;
        }
        List<String> got = new ArrayList<>();
        for (MethodNode m : c.methods()) got.add(m.name() + ":" + m.visibility().canonical());
        assertEquals(expected, got, label);
    }

    @Test
    void everyStaticSpellingIsRefusedWithTheSharedDiagnostic() {
        assertRefused("ts public static", ts("public static"), "Vault.runar.ts", "requirePositive");
        assertRefused("ts private static", ts("private static"), "Vault.runar.ts", "requirePositive");
        assertRefused("ts static", ts("static"), "Vault.runar.ts", "requirePositive");
        assertRefused("java @Public static", java("@Public static"), "Vault.runar.java", "requirePositive");
        assertRefused("java @Public public static", java("@Public public static"), "Vault.runar.java", "requirePositive");
        assertRefused("java static", java("static"), "Vault.runar.java", "requirePositive");
        assertRefused("java private static", java("private static"), "Vault.runar.java", "requirePositive");
        assertRefused("java @Public static final", java("@Public static final"), "Vault.runar.java", "requirePositive");
        assertRefused("py @public @staticmethod", py("    @public\n    @staticmethod", "amount: int"), "Vault.runar.py", "require_positive");
        assertRefused("py @staticmethod @public", py("    @staticmethod\n    @public", "amount: int"), "Vault.runar.py", "require_positive");
        assertRefused("py @staticmethod", py("    @staticmethod", "amount: int"), "Vault.runar.py", "require_positive");
        assertRefused("py @public @classmethod", py("    @public\n    @classmethod", "cls, amount: int"), "Vault.runar.py", "require_positive");
        assertRefused("py @classmethod", py("    @classmethod", "cls, amount: int"), "Vault.runar.py", "require_positive");
        assertRefused("rb runar_public def self.x", rb("  runar_public amount: Bigint", "self.require_positive"), "Vault.runar.rb", "require_positive");
        assertRefused("rb params def self.x", rb("  params amount: Bigint", "self.require_positive"), "Vault.runar.rb", "require_positive");
        assertRefused("rb def Vault.x", rb("  runar_public amount: Bigint", "Vault.require_positive"), "Vault.runar.rb", "require_positive");
        assertRefused("rs pub fn without self", rs(RS_NO_SELF), "Vault.runar.rs", "require_positive");
        assertRefused("zig pub fn without receiver", zig(ZIG_NO_SELF), "Vault.runar.zig", "requirePositive");
    }

    @Test
    void nonStaticSpellingsStillParse() {
        List<String> both = List.of("requirePositive:public", "withdraw:public");
        List<String> helper = List.of("requirePositive:private", "withdraw:public");
        assertMethods("ts public", ts("public"), "Vault.runar.ts", both);
        assertMethods("ts private", ts("private"), "Vault.runar.ts", helper);
        assertMethods("java @Public", java("@Public"), "Vault.runar.java", both);
        assertMethods("java private", java("private"), "Vault.runar.java", helper);
        assertMethods("py instance", py("    @public", "self, amount: int"), "Vault.runar.py", both);
        assertMethods("rb instance", rb("  runar_public amount: Bigint", "require_positive"), "Vault.runar.rb", both);
        assertMethods("rs pub fn &self", rs("pub fn require_positive(&self, amount: Int) {\n        assert!(amount > 0);\n    }"), "Vault.runar.rs", both);
        assertMethods("rs private helper without self", rs("fn require_positive(amount: Int) {\n        assert!(amount > 0);\n    }"), "Vault.runar.rs", helper);
        assertMethods("zig pub fn with receiver", zig("pub fn requirePositive(self: *const Vault, amount: i64) void {\n        _ = self;\n        runar.assert(amount > 0);\n    }"), "Vault.runar.zig", both);
        assertMethods("zig private helper without receiver", zig("fn requirePositive(amount: i64) void {\n        runar.assert(amount > 0);\n    }"), "Vault.runar.zig", helper);
    }
}
