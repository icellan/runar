//! N-004 (CL-BUG-257) — stray class-level tokens in .runar.rb.
//!
//! The parser skipped any class-body token it did not recognise and ignored
//! everything after the class's `end`. An INDENTED `=begin` is not a comment
//! in Ruby: it lexes as `=` then `begin`, both were skipped, the
//! "commented-out" `drain` became a method, the block's `end` closed the
//! class, and the real guarded `unlock` was dropped with no diagnostic,
//! leaving `drain` (assert true) as the only spend path.
//!
//! The rule is the TS reference's: a class-body token other than `prop`,
//! `runar_public`, `params`, `def` or a bare `private` / `public` marker is
//! refused with "Unexpected token in class body: '<tok>'", and the first token
//! after the class's `end` with "Unexpected token after class end: '<tok>'".
//! Diagnostics here are `file:line:col: message` strings.
//!
//! What this proves: the indented backdoor, stray class-body tokens and
//! trailing code after the class are parse errors whose first diagnostic is
//! the shared text at the offending token's line; bare `private` / `public`
//! markers and trailing blank lines and comments still parse cleanly.
//! What it does NOT prove: emitted bytes, other tiers (see
//! conformance/negatives/n004-rb-stray-token-parity.test.ts), characters the
//! tokenizer drops, or a class with no closing `end`.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const FILE = "P2PKH.runar.rb";

fn p2pkh(comptime body: []const u8, comptime tail: []const u8) []const u8 {
    return "require 'runar'\n" ++
        "\n" ++
        "class P2PKH < Runar::SmartContract\n" ++
        "  prop :pub_key_hash, Addr\n" ++
        "\n" ++
        "  def initialize(pub_key_hash)\n" ++
        "    super(pub_key_hash)\n" ++
        "    @pub_key_hash = pub_key_hash\n" ++
        "  end\n" ++
        body ++ "\n" ++
        "  runar_public sig: Sig, pub_key: PubKey\n" ++
        "  def unlock(sig, pub_key)\n" ++
        "    assert hash160(pub_key) == @pub_key_hash\n" ++
        "    assert check_sig(sig, pub_key)\n" ++
        "  end\n" ++
        "end\n" ++
        tail;
}

const INDENTED = p2pkh(
    "\n" ++
        "  =begin\n" ++
        "  Old debugging entry point, disabled:\n" ++
        "  runar_public sig: Sig, pk: PubKey\n" ++
        "  def drain(sig, pk)\n" ++
        "    assert true\n" ++
        "  end\n" ++
        "end\n" ++
        "  =end\n",
    "",
);

fn bodyMsg(comptime tok: []const u8) []const u8 {
    return "Unexpected token in class body: '" ++ tok ++ "'";
}

fn afterMsg(comptime tok: []const u8) []const u8 {
    return "Unexpected token after class end: '" ++ tok ++ "'";
}

const Case = struct { src: []const u8, line: []const u8, want: []const u8 };

const REFUSED = [_]Case{
    .{ .src = INDENTED, .line = ":11:", .want = bodyMsg("=") },
    .{ .src = p2pkh("\n  42 + ?\n", ""), .line = ":11:", .want = bodyMsg("42") },
    .{ .src = p2pkh("\n  = end\n", ""), .line = ":11:", .want = bodyMsg("=") },
    .{ .src = p2pkh("\n  foo\n", ""), .line = ":11:", .want = bodyMsg("foo") },
    .{ .src = p2pkh("", "foo\n"), .line = ":17:", .want = afterMsg("foo") },
    .{ .src = p2pkh("", "end\n"), .line = ":17:", .want = afterMsg("end") },
    .{ .src = p2pkh("", "def drain(sig)\n  assert true\nend\n"), .line = ":17:", .want = afterMsg("def") },
    .{ .src = p2pkh("", "class Other < Runar::SmartContract\nend\n"), .line = ":17:", .want = afterMsg("class") },
};

test "N-004 stray class-level tokens are refused with the shared text" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    for (REFUSED) |c| {
        const r = compiler_api.parseSource(a, c.src, FILE);
        if (r.errors.len == 0) {
            std.debug.print("want \"{s}\"; parsed with no errors\n", .{c.want});
            return error.NotRefused;
        }
        const first = r.errors[0];
        if (!std.mem.endsWith(u8, first, c.want) or !std.mem.startsWith(u8, first, FILE) or
            std.mem.indexOf(u8, first, c.line) == null)
        {
            std.debug.print("want \"{s}\" at {s}; got \"{s}\"\n", .{ c.want, c.line, first });
            return error.WrongDiagnostic;
        }
    }
}

test "N-004 bare private / public markers and trailing blanks still parse" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    for ([_][]const u8{
        p2pkh("", ""),
        p2pkh("\n  private\n\n  public\n", ""),
        p2pkh("", "\n# trailing note\n\n"),
    }) |src| {
        const r = compiler_api.parseSource(a, src, FILE);
        for (r.errors) |e| std.debug.print("unexpected error: {s}\n", .{e});
        try std.testing.expectEqual(@as(usize, 0), r.errors.len);
        try std.testing.expect(r.contract != null);
    }
}
