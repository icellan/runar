//! Issue #123 field-usage validation (security core) — one rejection per
//! unsound case, ported from sighash-validate.test.ts (incl. the e88f202c
//! security fixes) and the Go peer sighash_validate_test.go.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const validate = @import("../passes/validate.zig");

/// Parse + validate a .runar.ts source, returning whether any ERROR diagnostic
/// (parse-level or validation-level) contains `needle`. Uses an internal arena
/// so the frontend's allocations are freed (`a` is the leak-checking allocator).
fn hasError(a: std.mem.Allocator, src: []const u8, needle: []const u8) !bool {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const w = arena.allocator();
    const parsed = parse_ts.parseTs(w, src, "X.runar.ts");
    // Parse-level errors (e.g. the FORKID guard) count.
    for (parsed.errors) |e| {
        if (std.mem.indexOf(u8, e, needle) != null) return true;
    }
    if (parsed.contract == null) return false;
    const res = try validate.validate(w, parsed.contract.?);
    for (res.errors) |d| {
        if (std.mem.indexOf(u8, d.message, needle) != null) return true;
    }
    return false;
}

fn hasWarning(a: std.mem.Allocator, src: []const u8, needle: []const u8) !bool {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const w = arena.allocator();
    const parsed = parse_ts.parseTs(w, src, "X.runar.ts");
    if (parsed.contract == null) return false;
    const res = try validate.validate(w, parsed.contract.?);
    for (res.warnings) |d| {
        if (std.mem.indexOf(u8, d.message, needle) != null) return true;
    }
    return false;
}

fn errorCount(a: std.mem.Allocator, src: []const u8) !usize {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const w = arena.allocator();
    const parsed = parse_ts.parseTs(w, src, "X.runar.ts");
    if (parsed.errors.len > 0) return parsed.errors.len;
    if (parsed.contract == null) return 0;
    const res = try validate.validate(w, parsed.contract.?);
    return res.errors.len;
}

// ---- Rule 1: ANYONECANPAY -------------------------------------------------

test "sighash-validate: ANYONECANPAY rejects extractHashPrevouts" {
    const a = std.testing.allocator;
    const src =
        \\class Guard extends SmartContract {
        \\  readonly expected: ByteString;
        \\  constructor(expected: ByteString) { super(expected); this.expected = expected; }
        \\  /** @sighash ALL|ANYONECANPAY|FORKID */
        \\  public spend(pre: SigHashPreimage): void {
        \\    assert(checkPreimage(pre));
        \\    assert(extractHashPrevouts(pre) === this.expected);
        \\  }
        \\}
    ;
    try std.testing.expect(try hasError(a, src, "hashPrevouts"));
}

test "sighash-validate: ANYONECANPAY rejects extractPrevOutputScript" {
    const a = std.testing.allocator;
    const src =
        \\class Co extends StatefulSmartContract {
        \\  readonly h0: ByteString;
        \\  n: bigint;
        \\  constructor(h0: ByteString, n: bigint) { super(h0, n); this.h0 = h0; this.n = n; }
        \\  /** @sighash ALL|ANYONECANPAY|FORKID */
        \\  public coSpend(): void {
        \\    const s = extractPrevOutputScript(1n, this.h0);
        \\    assert(len(s) > 0n);
        \\  }
        \\}
    ;
    try std.testing.expect(try hasError(a, src, "prevout script") or try hasError(a, src, "companion input"));
}

test "sighash-validate: ANYONECANPAY accepted under default ALL" {
    const a = std.testing.allocator;
    const src =
        \\class Guard extends SmartContract {
        \\  readonly expected: ByteString;
        \\  constructor(expected: ByteString) { super(expected); this.expected = expected; }
        \\  public spend(pre: SigHashPreimage): void {
        \\    assert(checkPreimage(pre));
        \\    assert(extractHashPrevouts(pre) === this.expected);
        \\  }
        \\}
    ;
    try std.testing.expectEqual(@as(usize, 0), try errorCount(a, src));
}

// ---- Rule 2: hashSequence -------------------------------------------------

test "sighash-validate: non-pure-ALL rejects extractHashSequence" {
    const a = std.testing.allocator;
    const src =
        \\class Seq extends SmartContract {
        \\  readonly expected: ByteString;
        \\  constructor(expected: ByteString) { super(expected); this.expected = expected; }
        \\  /** @sighash NONE|FORKID */
        \\  public spend(pre: SigHashPreimage): void {
        \\    assert(checkPreimage(pre));
        \\    assert(extractHashSequence(pre) === this.expected);
        \\  }
        \\}
    ;
    try std.testing.expect(try hasError(a, src, "hashSequence"));
}

// ---- Rule 3: NONE ---------------------------------------------------------

test "sighash-validate: NONE rejects state continuation" {
    const a = std.testing.allocator;
    const src =
        \\class Counter extends StatefulSmartContract {
        \\  n: bigint;
        \\  constructor(n: bigint) { super(n); this.n = n; }
        \\  /** @sighash NONE|FORKID */
        \\  public bump(): void { this.n = this.n + 1n; }
        \\}
    ;
    try std.testing.expect(try hasError(a, src, "NONE commits to NO outputs") or try hasError(a, src, "continuation"));
}

// ---- Rule 4: SINGLE -------------------------------------------------------

// D25: the #123 (F1) refusal predated the F-024 `_newAmount` floor and N-038;
// SINGLE hashes the whole same-index output, value included, so a mutate-only
// SINGLE continuation is sound (and the default for a contract whose
// continuation methods are all mutate-only).
test "sighash-validate: SINGLE accepts a mutate-only continuation (the F-024 floor pins its value)" {
    const a = std.testing.allocator;
    const src =
        \\class Counter extends StatefulSmartContract {
        \\  n: bigint;
        \\  constructor(n: bigint) { super(n); this.n = n; }
        \\  /** @sighash SINGLE|FORKID */
        \\  public bump(): void { this.n = this.n + 1n; }
        \\}
    ;
    // An empty needle matches any error: there must be none.
    try std.testing.expect(!try hasError(a, src, ""));
}

test "sighash-validate: SINGLE rejects >1 committed output" {
    const a = std.testing.allocator;
    const src =
        \\class Multi extends StatefulSmartContract {
        \\  count: bigint;
        \\  constructor(count: bigint) { super(count); this.count = count; }
        \\  /** @sighash SINGLE|FORKID */
        \\  public split(): void {
        \\    this.addOutput(1000n, this.count);
        \\    this.addOutput(2000n, this.count);
        \\  }
        \\}
    ;
    try std.testing.expect(try hasError(a, src, "SINGLE commits ONLY to the output at this input"));
}

// F1: explicit single addOutput is ALLOWED but warns.
test "sighash-validate: SINGLE accepts explicit single addOutput with warning" {
    const a = std.testing.allocator;
    const src =
        \\class Pay extends StatefulSmartContract {
        \\  n: bigint;
        \\  constructor(n: bigint) { super(n); this.n = n; }
        \\  /** @sighash SINGLE|FORKID */
        \\  public settle(): void { this.addOutput(1000n, this.n); }
        \\}
    ;
    try std.testing.expectEqual(@as(usize, 0), try errorCount(a, src));
    try std.testing.expect(try hasWarning(a, src, "carries the FULL protected value") or
        try hasWarning(a, src, "SINGLE commits ONLY to the output at this input"));
}

// F4: requireOutputP2PKH under SINGLE is rejected.
test "sighash-validate: SINGLE rejects requireOutputP2PKH (F4)" {
    const a = std.testing.allocator;
    const src =
        \\class Cov extends StatefulSmartContract {
        \\  readonly bondPKH: ByteString;
        \\  readonly bond: bigint;
        \\  constructor(bondPKH: ByteString, bond: bigint) { super(bondPKH, bond); this.bondPKH = bondPKH; this.bond = bond; }
        \\  /** @sighash SINGLE|FORKID */
        \\  public payBond() { requireOutputP2PKH(0n, this.bondPKH, this.bond); }
        \\}
    ;
    try std.testing.expect(try hasError(a, src, "'requireOutputP2PKH' asserts an output at a fixed index"));
}

// ---- Rule 5: default (no directive) is never flagged; F2 FORKID mandatory --

test "sighash-validate: default mode is never flagged" {
    const a = std.testing.allocator;
    const src =
        \\class Counter extends StatefulSmartContract {
        \\  n: bigint;
        \\  constructor(n: bigint) { super(n); this.n = n; }
        \\  public bump(): void { this.n = this.n + 1n; }
        \\}
    ;
    try std.testing.expectEqual(@as(usize, 0), try errorCount(a, src));
}

test "sighash-validate: FORKID-less flag set rejected (F2, parse-level)" {
    const a = std.testing.allocator;
    const src =
        \\class Counter extends StatefulSmartContract {
        \\  n: bigint;
        \\  constructor(n: bigint) { super(n); this.n = n; }
        \\  /** @sighash SINGLE */
        \\  public bump(): void { this.addOutput(1000n, this.n); }
        \\}
    ;
    try std.testing.expect(try hasError(a, src, "FORKID is mandatory on BSV"));
}

// F3: forbidden read hidden in a private helper surfaces transitively.
test "sighash-validate: NONE rejects hashOutputs read inside a private helper (F3)" {
    const a = std.testing.allocator;
    const src =
        \\class C extends SmartContract {
        \\  readonly expected: ByteString;
        \\  constructor(expected: ByteString) { super(expected); this.expected = expected; }
        \\  private peek(pre: SigHashPreimage): ByteString { return extractOutputHash(pre); }
        \\  /** @sighash NONE|FORKID */
        \\  public spend(pre: SigHashPreimage): void {
        \\    assert(checkPreimage(pre));
        \\    assert(this.peek(pre) === this.expected);
        \\  }
        \\}
    ;
    try std.testing.expect(try hasError(a, src, "hashOutputs"));
}
