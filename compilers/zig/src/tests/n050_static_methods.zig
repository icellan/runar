//! N-050 (external StaticSiphon) — a static / class-level method is not a
//! contract method and must never become a spending entry point.
//!
//! Before the fix this tier refused `public static` on .runar.ts only by
//! accident ("Contract has no public methods"), and compiled `@Public static`
//! on .runar.java and a receiver-less `pub fn` on .runar.rs / .runar.zig into
//! dispatch selectors (unsigned spend paths).
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
//! What this proves: the Zig tier's frontend refuses every spelling with the
//! reference text, and the non-static spellings still parse with the same
//! method visibilities.
//! What it does NOT prove: the other tiers (their own suites, the
//! runar-testing n050 spend test and conformance/negatives/N104-N111), or
//! anything on chain.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

fn msg(comptime name: []const u8) []const u8 {
    return "static methods are not allowed in Rúnar contracts; method '" ++ name ++ "' is declared static";
}

fn ts(comptime decl: []const u8) []const u8 {
    return "import { SmartContract, Sig, PubKey, assert, checkSig } from 'runar-lang';\n" ++
        "export class Vault extends SmartContract {\n" ++
        "  readonly owner: PubKey;\n" ++
        "  constructor(owner: PubKey) { super(owner); this.owner = owner; }\n" ++
        "  " ++ decl ++ " requirePositive(amount: bigint) { assert(amount > 0n); }\n" ++
        "  public withdraw(sig: Sig) { assert(checkSig(sig, this.owner)); }\n" ++
        "}\n";
}

fn java(comptime decl: []const u8) []const u8 {
    return "package x;\n" ++
        "import runar.lang.SmartContract;\n" ++
        "import runar.lang.annotations.Public;\n" ++
        "import runar.lang.annotations.Readonly;\n" ++
        "import runar.lang.types.PubKey;\n" ++
        "import runar.lang.types.Sig;\n" ++
        "import java.math.BigInteger;\n" ++
        "import static runar.lang.Builtins.assertThat;\n" ++
        "import static runar.lang.Builtins.checkSig;\n" ++
        "class Vault extends SmartContract {\n" ++
        "    @Readonly PubKey owner;\n" ++
        "    Vault(PubKey owner) { super(owner); this.owner = owner; }\n" ++
        "    " ++ decl ++ " void requirePositive(BigInteger amount) { assertThat(amount.compareTo(BigInteger.ZERO) > 0); }\n" ++
        "    @Public\n" ++
        "    void withdraw(Sig sig) { assertThat(checkSig(sig, owner)); }\n" ++
        "}\n";
}

fn py(comptime decorators: []const u8, comptime params: []const u8) []const u8 {
    return "from runar import SmartContract, Sig, PubKey, public, assert_, check_sig\n\n" ++
        "class Vault(SmartContract):\n" ++
        "    owner: PubKey\n\n" ++
        "    def __init__(self, owner: PubKey):\n" ++
        "        super().__init__(owner)\n" ++
        "        self.owner = owner\n\n" ++
        decorators ++ "\n" ++
        "    def require_positive(" ++ params ++ "):\n" ++
        "        assert_(amount > 0)\n\n" ++
        "    @public\n" ++
        "    def withdraw(self, sig: Sig):\n" ++
        "        assert_(check_sig(sig, self.owner))\n";
}

fn rb(comptime marker: []const u8, comptime def: []const u8) []const u8 {
    return "require 'runar'\n\n" ++
        "class Vault < Runar::SmartContract\n" ++
        "  prop :owner, PubKey\n\n" ++
        "  def initialize(owner)\n" ++
        "    super(owner)\n" ++
        "    @owner = owner\n" ++
        "  end\n" ++
        marker ++ "\n" ++
        "  def " ++ def ++ "(amount)\n" ++
        "    assert amount > 0\n" ++
        "  end\n\n" ++
        "  runar_public sig: Sig\n" ++
        "  def withdraw(sig)\n" ++
        "    assert check_sig(sig, @owner)\n" ++
        "  end\n" ++
        "end\n";
}

fn rs(comptime func: []const u8) []const u8 {
    return "use runar::prelude::*;\n\n" ++
        "#[runar::contract]\n" ++
        "struct Vault {\n" ++
        "    #[readonly]\n" ++
        "    owner: PubKey,\n" ++
        "}\n\n" ++
        "impl Vault {\n" ++
        "    " ++ func ++ "\n\n" ++
        "    pub fn withdraw(&self, sig: &Sig) {\n" ++
        "        assert!(check_sig(sig, &self.owner));\n" ++
        "    }\n" ++
        "}\n";
}

fn zig(comptime func: []const u8) []const u8 {
    return "const runar = @import(\"runar\");\n\n" ++
        "pub const Vault = struct {\n" ++
        "    pub const Contract = runar.SmartContract;\n\n" ++
        "    owner: runar.PubKey,\n\n" ++
        "    pub fn init(owner: runar.PubKey) Vault {\n" ++
        "        return .{ .owner = owner };\n" ++
        "    }\n\n" ++
        "    " ++ func ++ "\n\n" ++
        "    pub fn withdraw(self: *const Vault, sig: runar.Sig) void {\n" ++
        "        runar.assert(runar.checkSig(sig, self.owner));\n" ++
        "    }\n" ++
        "};\n";
}

const RS_NO_SELF = "pub fn require_positive(amount: Int) {\n        assert!(amount > 0);\n    }";
const ZIG_NO_SELF = "pub fn requirePositive(amount: i64) void {\n        runar.assert(amount > 0);\n    }";

/// A frontend diagnostic ends with the shared text (tiers may prefix
/// `file:line:col: `).
fn expectRefused(source: []const u8, file_name: []const u8, expected: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const r = compiler_api.parseSource(arena_state.allocator(), source, file_name);
    for (r.errors) |e| {
        if (std.mem.endsWith(u8, e, expected)) return;
    }
    std.debug.print("{s}: expected '{s}', got {d} error(s):\n", .{ file_name, expected, r.errors.len });
    for (r.errors) |e| std.debug.print("  {s}\n", .{e});
    return error.TestExpectedRefusal;
}

fn expectMethods(source: []const u8, file_name: []const u8, expected: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const r = compiler_api.parseSource(arena, source, file_name);
    for (r.errors) |e| std.debug.print("unexpected: {s}\n", .{e});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    var out: std.ArrayListUnmanaged(u8) = .empty;
    for (r.contract.?.methods, 0..) |m, i| {
        if (i > 0) try out.append(arena, ',');
        try out.appendSlice(arena, m.name);
        try out.appendSlice(arena, if (m.is_public) ":public" else ":private");
    }
    try std.testing.expectEqualStrings(expected, out.items);
}

test "N-050 .runar.ts refuses static methods" {
    try expectRefused(ts("public static"), "Vault.runar.ts", msg("requirePositive"));
    try expectRefused(ts("private static"), "Vault.runar.ts", msg("requirePositive"));
    try expectRefused(ts("static"), "Vault.runar.ts", msg("requirePositive"));
}

test "N-050 .runar.java refuses static methods" {
    try expectRefused(java("@Public static"), "Vault.runar.java", msg("requirePositive"));
    try expectRefused(java("@Public public static"), "Vault.runar.java", msg("requirePositive"));
    try expectRefused(java("static"), "Vault.runar.java", msg("requirePositive"));
    try expectRefused(java("private static"), "Vault.runar.java", msg("requirePositive"));
    try expectRefused(java("@Public static final"), "Vault.runar.java", msg("requirePositive"));
}

test "N-050 .runar.py refuses @staticmethod and @classmethod" {
    try expectRefused(py("    @public\n    @staticmethod", "amount: int"), "Vault.runar.py", msg("require_positive"));
    try expectRefused(py("    @staticmethod\n    @public", "amount: int"), "Vault.runar.py", msg("require_positive"));
    try expectRefused(py("    @staticmethod", "amount: int"), "Vault.runar.py", msg("require_positive"));
    try expectRefused(py("    @public\n    @classmethod", "cls, amount: int"), "Vault.runar.py", msg("require_positive"));
    try expectRefused(py("    @classmethod", "cls, amount: int"), "Vault.runar.py", msg("require_positive"));
}

test "N-050 .runar.rb refuses def self.m and def Vault.m" {
    try expectRefused(rb("  runar_public amount: Bigint", "self.require_positive"), "Vault.runar.rb", msg("require_positive"));
    try expectRefused(rb("  params amount: Bigint", "self.require_positive"), "Vault.runar.rb", msg("require_positive"));
    try expectRefused(rb("  runar_public amount: Bigint", "Vault.require_positive"), "Vault.runar.rb", msg("require_positive"));
}

test "N-050 .runar.rs / .runar.zig refuse a pub fn without a receiver" {
    try expectRefused(rs(RS_NO_SELF), "Vault.runar.rs", msg("require_positive"));
    try expectRefused(zig(ZIG_NO_SELF), "Vault.runar.zig", msg("requirePositive"));
}

test "N-050 the non-static spellings still parse" {
    try expectMethods(ts("public"), "Vault.runar.ts", "requirePositive:public,withdraw:public");
    try expectMethods(ts("private"), "Vault.runar.ts", "requirePositive:private,withdraw:public");
    try expectMethods(java("@Public"), "Vault.runar.java", "requirePositive:public,withdraw:public");
    try expectMethods(java("private"), "Vault.runar.java", "requirePositive:private,withdraw:public");
    try expectMethods(py("    @public", "self, amount: int"), "Vault.runar.py", "requirePositive:public,withdraw:public");
    try expectMethods(rb("  runar_public amount: Bigint", "require_positive"), "Vault.runar.rb", "requirePositive:public,withdraw:public");
    try expectMethods(rs("pub fn require_positive(&self, amount: Int) {\n        assert!(amount > 0);\n    }"), "Vault.runar.rs", "requirePositive:public,withdraw:public");
    try expectMethods(rs("fn require_positive(amount: Int) {\n        assert!(amount > 0);\n    }"), "Vault.runar.rs", "requirePositive:private,withdraw:public");
    try expectMethods(zig("pub fn requirePositive(self: *const Vault, amount: i64) void {\n        _ = self;\n        runar.assert(amount > 0);\n    }"), "Vault.runar.zig", "requirePositive:public,withdraw:public");
    try expectMethods(zig("fn requirePositive(amount: i64) void {\n        runar.assert(amount > 0);\n    }"), "Vault.runar.zig", "requirePositive:private,withdraw:public");
}
