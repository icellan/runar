//! F-265 -- substr() literal negative start is a compile-time error.
//!
//! substr(witness, start, len) lowers to a raw OP_SPLIT argument. No pass
//! enforced start >= 0: a literal negative start (`substr(a, -5n, 3n)`)
//! type-checked as plain 'bigint' (the standard subtype loop never inspects a
//! literal's VALUE) and compiled to a script that aborts at runtime -- `-5n`
//! minimal-encodes to `<85>`, which OP_SPLIT rejects as out of range.
//!
//! Mirrors the existing extractPrevOutputScript/requireOutputP2PKH
//! "must be >= 0" literal-bound pattern in `typecheck.zig`.
//!
//! Proves: a literal (bare or unary-negated literal_int) negative start is
//! now a typecheck-time diagnostic. Does not prove: anything about a
//! NON-literal negative start (a variable or computed expression) -- that
//! remains a runtime abort, unchanged, because the stack model has no static
//! value range for a non-literal.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const typecheck = @import("../passes/typecheck.zig");

fn typecheckSource(allocator: std.mem.Allocator, src: []const u8) !typecheck.TypeCheckResult {
    const parsed = parse_ts.parseTs(allocator, src, "F265.runar.ts");
    if (parsed.errors.len > 0) {
        for (parsed.errors) |e| std.debug.print("  unexpected parse error: {s}\n", .{e});
        return error.TestFixtureDidNotParse;
    }
    return try typecheck.typeCheck(allocator, parsed.contract orelse return error.TestFixtureDidNotParse);
}

test "F-265: substr() literal negative start is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const w = arena.allocator();

    const src =
        \\class C extends SmartContract {
        \\  readonly a: ByteString;
        \\  constructor(a: ByteString) { super(a); this.a = a; }
        \\  public unlock() {
        \\    assert(substr(this.a, -5n, 3n) === this.a);
        \\  }
        \\}
    ;
    const result = try typecheckSource(w, src);
    var found = false;
    for (result.errors) |msg| {
        if (std.mem.indexOf(u8, msg, "substr() argument 2 (start) must be >= 0; got -5") != null) found = true;
    }
    if (!found) {
        for (result.errors) |msg| std.debug.print("  F-265 got: {s}\n", .{msg});
        return error.SubstrNegativeStartAccepted;
    }
}

test "F-265: substr() literal non-negative start is accepted" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const w = arena.allocator();

    const src =
        \\class C extends SmartContract {
        \\  readonly a: ByteString;
        \\  constructor(a: ByteString) { super(a); this.a = a; }
        \\  public unlock() {
        \\    assert(substr(this.a, 0n, 3n) === this.a);
        \\  }
        \\}
    ;
    const result = try typecheckSource(w, src);
    if (result.errors.len != 0) {
        for (result.errors) |msg| std.debug.print("  F-265 unexpected error: {s}\n", .{msg});
        return error.SubstrNonNegativeStartRefused;
    }
}

test "F-265: substr() non-literal start is unchanged" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const w = arena.allocator();

    const src =
        \\class C extends SmartContract {
        \\  readonly a: ByteString;
        \\  constructor(a: ByteString) { super(a); this.a = a; }
        \\  public unlock(n: bigint) {
        \\    assert(substr(this.a, n, 3n) === this.a);
        \\  }
        \\}
    ;
    const result = try typecheckSource(w, src);
    if (result.errors.len != 0) {
        for (result.errors) |msg| std.debug.print("  F-265 unexpected error: {s}\n", .{msg});
        return error.SubstrNonLiteralStartRefused;
    }
}
