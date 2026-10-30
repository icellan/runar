//! N-303 — a decorated `def __init__` in .runar.py is the constructor.
//!
//! The TS reference (`parseMethodDef` in 01-parse-python.ts) decides "this is
//! the constructor" from the method NAME alone, whatever decorators precede
//! it: `@public def __init__` and `@foo def __init__` both yield the ordinary
//! constructor and add no method. Before the fix this tier sent every
//! decorated `def` down the method path, so the constructor became a method
//! named `constructor` next to an auto-generated constructor.
//!
//! What this proves: the Zig tier's .runar.py frontend produces the same AST
//! shape as the undecorated control for a decorated __init__ (one constructor
//! with the declared params, only `unlock` in the method list, no errors).
//! What it does NOT prove: the other tiers (their own suites / the matrix in
//! the N-303 log), or the compiled hex.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

fn py(comptime decorator: []const u8) []const u8 {
    return "from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig\n\n" ++
        "class P2PKH(SmartContract):\n" ++
        "    pub_key_hash: Addr\n\n" ++
        decorator ++
        "    def __init__(self, pub_key_hash: Addr):\n" ++
        "        super().__init__(pub_key_hash)\n" ++
        "        self.pub_key_hash = pub_key_hash\n\n" ++
        "    @public\n" ++
        "    def unlock(self, sig: Sig, pub_key: PubKey):\n" ++
        "        assert_(hash160(pub_key) == self.pub_key_hash)\n" ++
        "        assert_(check_sig(sig, pub_key))\n";
}

fn expectConstructor(source: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const r = compiler_api.parseSource(arena_state.allocator(), source, "P2PKH.runar.py");
    for (r.errors) |e| std.debug.print("unexpected: {s}\n", .{e});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    try std.testing.expectEqualStrings("unlock", c.methods[0].name);
    try std.testing.expectEqual(@as(usize, 1), c.constructor.params.len);
    try std.testing.expectEqualStrings("pubKeyHash", c.constructor.params[0].name);
}

test "N-303 a decorated __init__ is the constructor, as in the undecorated control" {
    try expectConstructor(py(""));
    try expectConstructor(py("    @public\n"));
    try expectConstructor(py("    @foo\n"));
}
