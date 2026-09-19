//! A terminal read of a FIXED-SIZE state field goes stale when a SIBLING field
//! is variable-length. R-074, the third member of the issue-#100 family.
//!
//! `lowerDeserializeState` picks its extraction strategy from a CONTRACT-level
//! fact — `has_variable_length`, i.e. "does ANY mutable property carry a
//! push-data length prefix". When that is true the state section can only be
//! located through the `_codePart`-relative offset, so the WHOLE
//! deserialization is gated on `sm.has("_codePart")`; without it the pass takes
//! its `OP_SPLIT`/`OP_2DROP` shortcut, pushes NO mutable property at all, and
//! every later `load_prop` silently resolves to the DEPLOY-TIME constructor
//! placeholder baked into the locking script.
//!
//! `methodUsesCodePartFull`, which decides whether `_codePart` is on the stack,
//! asked a strictly NARROWER, METHOD-level question: "does THIS method read a
//! var-length property". A terminal method that reads only the `bigint`
//! sibling answered no, so `_codePart` was never provisioned and the
//! contract's own live state became invisible to it.
//!
//! The two questions must agree. `6dc1979b` (R-015 / CL-BUG-138) fixed a
//! different divergence in this same predicate — which TYPES count as
//! variable-length — and left this one live: there the method read the
//! var-length field itself, here it merely shares a contract with one.
//!
//! Executed harm, proven on the real `@bsv/sdk` VM: deploy `count=1`, call
//! `bump(7)`, then terminal `check`. Pre-fix `check(7)` is REJECTED and
//! `check(1)` VALIDATES — the stale deploy-time value authorises a real spend.
//!
//! The matched control is the same contract with `tag: bigint`: no var-length
//! property, `has_variable_length` false, the fixed-width split path, and a
//! correct live-state read all along. It must stay BYTE-IDENTICAL — the fix is
//! confined to contracts that actually declare var-length state.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const FILE_NAME = "StaleStateProbe.runar.ts";

/// `count` is fixed-size and IS read by the terminal method; `tag` is
/// variable-length and is NOT touched by it.
const PROBE_SRC =
    \\class StaleStateProbe extends StatefulSmartContract {
    \\  count: bigint;
    \\  tag: ByteString;
    \\  constructor(count: bigint, tag: ByteString) {
    \\    super(count, tag);
    \\    this.count = count;
    \\    this.tag = tag;
    \\  }
    \\  public check(expected: bigint) {
    \\    assert(this.count == expected);
    \\  }
    \\}
;

/// Matched control: identical in every respect except `tag`'s type, which is
/// the single input to `has_variable_length`.
const CONTROL_SRC =
    \\class StaleStateProbe extends StatefulSmartContract {
    \\  count: bigint;
    \\  tag: bigint;
    \\  constructor(count: bigint, tag: bigint) {
    \\    super(count, tag);
    \\    this.count = count;
    \\    this.tag = tag;
    \\  }
    \\  public check(expected: bigint) {
    \\    assert(this.count == expected);
    \\  }
    \\}
;

/// Same shape, reached through a private helper. Private methods are INLINED
/// into the caller's stack context (deep-review finding C18), so the recursion
/// `methodReadsVarLenStateRec` already performs must keep working once the
/// property set it is handed is widened.
const PRIVATE_HELPER_SRC =
    \\class StaleStateProbe extends StatefulSmartContract {
    \\  count: bigint;
    \\  tag: ByteString;
    \\  constructor(count: bigint, tag: ByteString) {
    \\    super(count, tag);
    \\    this.count = count;
    \\    this.tag = tag;
    \\  }
    \\  private current(): bigint {
    \\    return this.count;
    \\  }
    \\  public check(expected: bigint) {
    \\    assert(this.current() == expected);
    \\  }
    \\}
;

/// A terminal method that reads NO mutable state at all. `has_variable_length`
/// is true, but there is nothing to deserialize, so `_codePart` must stay off
/// the stack — the fix must not provision it unconditionally.
const NO_STATE_READ_SRC =
    \\class StaleStateProbe extends StatefulSmartContract {
    \\  count: bigint;
    \\  tag: ByteString;
    \\  constructor(count: bigint, tag: ByteString) {
    \\    super(count, tag);
    \\    this.count = count;
    \\    this.tag = tag;
    \\  }
    \\  public check(expected: bigint) {
    \\    assert(expected > 0);
    \\  }
    \\}
;

/// Cross-tier pins, captured from the five tiers that already carry the fix
/// (TypeScript, Go, Rust, Python, Ruby). sha256 is taken over the ASCII hex
/// string, exactly as the sibling Python test does.
const PROBE_FIXED_LEN: usize = 1268;
const PROBE_FIXED_SHA256 =
    "a7966788abe3a2b5eeedccc5a1430b14fa51d55ef7a44c705ed98cbd5a887ae0";

/// The broken script this finding is about. Pinned as a MUST-NOT-EQUAL so a
/// future regression cannot quietly restore it. NOTE: this digest is of the
/// PRE-W1 broken bytes; W1's zero-pad moved every stateful script by 3 bytes
/// per 32-bit-extractor call site, so the inequality is now trivially true and
/// the live guard is the PROBE_FIXED_SHA256 equality above.
const PROBE_BROKEN_SHA256 =
    "150cb2a01cca2eb26bbbe02e2c090aa5d0c33957b07a7e385d951ec6452e0fb8";

/// Outside the fix's blast radius — must not move.
const CONTROL_FIXED_LEN: usize = 940;
const CONTROL_SHA256 =
    "4832543947423af01033fb80269f838e04a3b9da95634ec038e704239e37e935";

/// The BIP-143 scriptCode varint-strip cascade (`<fd00> OP_LESSTHAN OP_IF`)
/// emitted ONLY on the `_codePart`-relative live-state path — never on the
/// fixed-width path and never on the discard shortcut. Its presence is a
/// structural proof that the method reads the state section rather than the
/// constructor placeholder.
const LIVE_STATE_MARKER_HEX = "02fd009f63";

fn artifactField(json: []const u8, marker: []const u8) ![]const u8 {
    const idx = std.mem.indexOf(u8, json, marker) orelse return error.MissingField;
    const after = idx + marker.len;
    const end = std.mem.indexOfPos(u8, json, after, "\"") orelse return error.MissingField;
    return json[after..end];
}

/// Fold-OFF compile — the pins were stamped under `--disable-constant-folding`.
fn scriptHexOf(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
    const result = try compiler_api.compileSourceWithOptions(allocator, src, FILE_NAME, true);
    defer result.deinit(allocator);
    const json = result.artifact_json orelse return error.MissingArtifact;
    return allocator.dupe(u8, try artifactField(json, "\"script\":\""));
}

fn usesCodePart(allocator: std.mem.Allocator, src: []const u8) !bool {
    const result = try compiler_api.compileSourceWithOptions(allocator, src, FILE_NAME, true);
    defer result.deinit(allocator);
    const json = result.artifact_json orelse return error.MissingArtifact;
    return std.mem.indexOf(u8, json, "\"usesCodePart\":true") != null;
}

fn sha256Hex(input: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(input, &digest, .{});
    var out: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "{x}", .{&digest}) catch unreachable;
    return out;
}

test "a terminal read beside a var-length sibling reads live state, not the deploy placeholder" {
    const allocator = std.testing.allocator;

    const hex = try scriptHexOf(allocator, PROBE_SRC);
    defer allocator.free(hex);

    try std.testing.expect(std.mem.indexOf(u8, hex, LIVE_STATE_MARKER_HEX) != null);
    try std.testing.expectEqual(PROBE_FIXED_LEN, hex.len);

    const got = sha256Hex(hex);
    try std.testing.expect(!std.mem.eql(u8, &got, PROBE_BROKEN_SHA256));
    try std.testing.expectEqualStrings(PROBE_FIXED_SHA256, &got);
}

test "the probe's terminal method advertises usesCodePart" {
    // The ABI shape, not just the byte count: the SDK reads this flag to decide
    // whether to push `_codePart` into the unlocking script.
    try std.testing.expect(try usesCodePart(std.testing.allocator, PROBE_SRC));
}

test "reaching the read through a private helper compiles identically" {
    const allocator = std.testing.allocator;

    const direct = try scriptHexOf(allocator, PROBE_SRC);
    defer allocator.free(direct);
    const via_helper = try scriptHexOf(allocator, PRIVATE_HELPER_SRC);
    defer allocator.free(via_helper);

    try std.testing.expectEqualStrings(direct, via_helper);
}

test "the control without a var-length sibling is byte-unchanged" {
    const allocator = std.testing.allocator;

    const hex = try scriptHexOf(allocator, CONTROL_SRC);
    defer allocator.free(hex);

    try std.testing.expectEqual(CONTROL_FIXED_LEN, hex.len);
    try std.testing.expectEqualStrings(CONTROL_SHA256, &sha256Hex(hex));
    try std.testing.expect(!try usesCodePart(allocator, CONTROL_SRC));
}

test "a terminal method reading no mutable state does not provision _codePart" {
    try std.testing.expect(!try usesCodePart(std.testing.allocator, NO_STATE_READ_SRC));
}
