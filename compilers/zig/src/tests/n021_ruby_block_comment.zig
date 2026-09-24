//! N-021 (CL-BUG-197) — `=begin` ... `=end` embedded documents in .runar.rb.
//!
//! Pre-fix this tier's Ruby-surface tokenizer knew only `#` comments. In a
//! column-0 `=begin` ... `=end` block every line was lexed as code: the
//! "commented-out" `drain` became a live spend path, the `=` of `=end` was
//! skipped as an unknown class-body token and its `end` closed the class
//! early, dropping the guarded `unlock`. The crafted contract below compiled
//! to 517777 (OP_TRUE OP_NIP OP_NIP, anyone-can-spend) with ABI [drain].
//!
//! The rule (user decision R11) is the Ruby tier's F-018 rule, ported to Go by
//! F-012, which is Ruby's own: `=begin` / `=end` open and close a block
//! comment only at column 0 and only as a whole word (followed by whitespace
//! or end of line); every line from `=begin` through `=end` is a comment; an
//! unterminated `=begin` is refused with
//! "unterminated '=begin' block comment starting at line N: missing '=end'".
//! Diagnostics here are strings; this one is `file:N: message` (no column),
//! the text the Go tier prints for its column-0 location.
//!
//! What this proves: this tier parses the crafted contract to exactly
//! `unlock` (LF, CRLF, text or a tab after the markers) and compiles it
//! (fold OFF) to the basic-p2pkh golden with only `unlock` in the ABI; an
//! unterminated `=begin` (also one "closed" only by `=endx`) is refused with
//! the shared text at its line; an indented `=begin` and `=beginx` are not
//! openers.
//! What it does NOT prove: other tiers; the parser's separate silent skip of
//! unknown class-body tokens (N-004); `__END__` or other Ruby lexical forms.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const FILE = "P2PKH.runar.rb";

const ATTACK =
    "require 'runar'\n" ++
    "\n" ++
    "class P2PKH < Runar::SmartContract\n" ++
    "  prop :pub_key_hash, Addr\n" ++
    "\n" ++
    "  def initialize(pub_key_hash)\n" ++
    "    super(pub_key_hash)\n" ++
    "    @pub_key_hash = pub_key_hash\n" ++
    "  end\n" ++
    "\n" ++
    "=begin\n" ++
    "  Old debugging entry point, disabled:\n" ++
    "  runar_public sig: Sig, pk: PubKey\n" ++
    "  def drain(sig, pk)\n" ++
    "    assert true\n" ++
    "  end\n" ++
    "end\n" ++
    "=end\n" ++
    "\n" ++
    "  runar_public sig: Sig, pub_key: PubKey\n" ++
    "  def unlock(sig, pub_key)\n" ++
    "    assert hash160(pub_key) == @pub_key_hash\n" ++
    "    assert check_sig(sig, pub_key)\n" ++
    "  end\n" ++
    "end\n";

const UNTERMINATED_11 = FILE ++ ":11: unterminated '=begin' block comment starting at line 11: missing '=end'";

fn replace(a: std.mem.Allocator, src: []const u8, needle: []const u8, repl: []const u8) ![]u8 {
    return std.mem.replaceOwned(u8, a, src, needle, repl);
}

fn variants(a: std.mem.Allocator) ![4][]const u8 {
    const text1 = try replace(a, ATTACK, "\n=begin\n", "\n=begin legacy notes\n");
    const tab1 = try replace(a, ATTACK, "\n=begin\n", "\n=begin\tx\n");
    return .{
        ATTACK,
        try replace(a, ATTACK, "\n", "\r\n"),
        try replace(a, text1, "\n=end\n", "\n=end trailing words\n"),
        try replace(a, tab1, "\n=end\n", "\n=end\tx\n"),
    };
}

fn hasMethod(src: []const u8, name: []const u8) !bool {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const r = compiler_api.parseSource(arena_state.allocator(), src, FILE);
    const c = r.contract orelse return false;
    for (c.methods) |m| if (std.mem.eql(u8, m.name, name)) return true;
    return false;
}

fn hasError(src: []const u8, want: []const u8) !bool {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const r = compiler_api.parseSource(arena_state.allocator(), src, FILE);
    for (r.errors) |e| if (std.mem.eql(u8, e, want)) return true;
    std.debug.print("want \"{s}\"; got:\n", .{want});
    for (r.errors) |e| std.debug.print("  {s}\n", .{e});
    return false;
}

test "N-021 the commented-out backdoor is not a spend path; unlock survives" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    for (try variants(a)) |src| {
        const r = compiler_api.parseSource(a, src, FILE);
        for (r.errors) |e| std.debug.print("unexpected error: {s}\n", .{e});
        try std.testing.expectEqual(@as(usize, 0), r.errors.len);
        const c = r.contract orelse return error.NoContract;
        try std.testing.expectEqual(@as(usize, 1), c.methods.len);
        try std.testing.expectEqualStrings("unlock", c.methods[0].name);
        try std.testing.expectEqual(@as(usize, 1), c.properties.len);
        try std.testing.expectEqualStrings("pubKeyHash", c.properties[0].name);
    }
}

test "N-021 the backdoor shape compiles to the basic-p2pkh golden" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const golden_raw = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "../../conformance/tests/basic-p2pkh/expected-script.hex", a, .limited(1024));
    const golden = std.mem.trim(u8, golden_raw, " \r\n\t");
    for (try variants(a)) |src| {
        const res = try compiler_api.compileSourceWithOptions(std.testing.allocator, src, FILE, true);
        defer res.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings(golden, res.script_hex);
        const json = res.artifact_json orelse return error.NoArtifact;
        try std.testing.expect(std.mem.indexOf(u8, json, "\"unlock\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, json, "drain") == null);
    }
}

test "N-021 an unterminated =begin is refused at its line" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try std.testing.expect(try hasError(try replace(a, ATTACK, "\n=end\n", "\n"), UNTERMINATED_11));
    // `=endx` is not a whole-word `=end`, so it does not close the block.
    try std.testing.expect(try hasError(try replace(a, ATTACK, "\n=end\n", "\n=endx\n"), UNTERMINATED_11));
    try std.testing.expect(try hasError("require 'runar'\n=begin", FILE ++ ":2: unterminated '=begin' block comment starting at line 2: missing '=end'"));
}

// Boundary controls: only a column-0 whole-word `=begin` opens a comment, so
// the lines after these are still lexed as code (`drain` is parsed).
test "N-021 an indented =begin and =beginx are not comment openers" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const indented = try replace(a, try replace(a, ATTACK, "\n=begin\n", "\n  =begin\n"), "\n=end\n", "\n  =end\n");
    try std.testing.expect(try hasMethod(indented, "drain"));
    try std.testing.expect(try hasMethod(try replace(a, ATTACK, "\n=begin\n", "\n=beginx\n"), "drain"));
}
