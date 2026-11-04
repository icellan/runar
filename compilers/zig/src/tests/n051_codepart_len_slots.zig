//! N-051 (TaffyTail) — the `SIZE(_codePart)` pin is ALWAYS an equality.
//!
//! A stateful contract with a variable-length state section authenticates the
//! spender-supplied `_codePart` witness and pins its length with
//!
//!     OP_DUP <04 LL LL LL LL> OP_BIN2NUM OP_NUMEQUAL OP_VERIFY
//!
//! When a readonly constructor arg of variable width (ByteString, bigint) is
//! baked into the code, the compiler cannot know the deployed length. It used
//! to degrade the comparison to OP_GREATERTHANOREQUAL (a lower bound), which
//! let a stranger claim a TRUNCATED `_codePart` ending at a 0x6a byte inside
//! the baked value and plant attacker code in the continuation.
//!
//! The fix: the comparison is OP_NUMEQUAL (0x9c) in every case, and a pin whose
//! value is not exact at compile time is recorded in the artifact's
//! `codePartLenSlots` so the SDK writes the deployed length at deploy time.
//! Byte-identical with the TypeScript reference tier.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const FILE_NAME = "TaffyTailVault.runar.ts";

/// The TaffyTail vault: `tag` is a READONLY variable-width ByteString baked
/// into the code part, `message` is variable-length mutable state.
const TAFFY_SRC =
    \\import { StatefulSmartContract, assert, extractAmount, checkSig } from 'runar-lang';
    \\import type { ByteString, PubKey, Sig } from 'runar-lang';
    \\
    \\class TaffyTailVault extends StatefulSmartContract {
    \\  message: ByteString;
    \\  readonly tag: ByteString;
    \\  readonly owner: PubKey;
    \\
    \\  constructor(message: ByteString, tag: ByteString, owner: PubKey) {
    \\    super(message, tag, owner);
    \\    this.message = message;
    \\    this.tag = tag;
    \\    this.owner = owner;
    \\  }
    \\
    \\  public burn(sig: Sig) {
    \\    assert(checkSig(sig, this.owner));
    \\  }
    \\
    \\  public post(next: ByteString, claimedTag: ByteString) {
    \\    assert(claimedTag === this.tag);
    \\    this.addOutput(extractAmount(this.txPreimage), next);
    \\  }
    \\}
;

/// Control: the readonly `tag` is a FIXED-width Sha256, so every placeholder's
/// growth is type-determined and the pin is exact at compile time.
const FIXED_SRC =
    \\import { StatefulSmartContract, assert, extractAmount, checkSig } from 'runar-lang';
    \\import type { ByteString, PubKey, Sig, Sha256 } from 'runar-lang';
    \\
    \\class TaffyTailVault extends StatefulSmartContract {
    \\  message: ByteString;
    \\  readonly tag: Sha256;
    \\  readonly owner: PubKey;
    \\
    \\  constructor(message: ByteString, tag: Sha256, owner: PubKey) {
    \\    super(message, tag, owner);
    \\    this.message = message;
    \\    this.tag = tag;
    \\    this.owner = owner;
    \\  }
    \\
    \\  public burn(sig: Sig) {
    \\    assert(checkSig(sig, this.owner));
    \\  }
    \\
    \\  public post(next: ByteString, claimedTag: Sha256) {
    \\    assert(claimedTag === this.tag);
    \\    this.addOutput(extractAmount(this.txPreimage), next);
    \\  }
    \\}
;

/// Pins taken from the TypeScript reference artifact (fold OFF).
const TS_SCRIPT_LEN_BYTES: usize = 1305;
const TS_SCRIPT_SHA256 = "738869ba6eed4d229d0d30f0b91b6fe98addff349a4f0fe0dee3ca3ffb656e45";
const TS_SLOT_BYTE_OFFSET: usize = 947;

fn compileJson(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
    const result = try compiler_api.compileSourceWithOptions(allocator, src, FILE_NAME, true);
    defer result.deinit(allocator);
    const json = result.artifact_json orelse return error.MissingArtifact;
    return allocator.dupe(u8, json);
}

fn sha256Hex(input: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(input, &digest, .{});
    var out: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "{x}", .{&digest}) catch unreachable;
    return out;
}

test "N-051: a variable-width readonly arg yields an equality pin and a codePartLenSlots entry" {
    const allocator = std.testing.allocator;
    const json = try compileJson(allocator, TAFFY_SRC);
    defer allocator.free(json);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    const script = root.get("script").?.string;

    // The pin is an equality; the old lower-bound tail is gone.
    try std.testing.expect(std.mem.indexOf(u8, script, "81a269") == null);

    // codePartLenSlots = [{"byteOffset": 947}] — exactly one key per entry.
    const slots_val = root.get("codePartLenSlots") orelse return error.MissingCodePartLenSlots;
    const slots = slots_val.array.items;
    try std.testing.expectEqual(@as(usize, 1), slots.len);
    try std.testing.expectEqual(@as(usize, 1), slots[0].object.count());
    const off: usize = @intCast(slots[0].object.get("byteOffset").?.integer);
    try std.testing.expectEqual(TS_SLOT_BYTE_OFFSET, off);

    // The slot points at the value bytes of `76 04 LL LL LL LL 81 9c 69`.
    try std.testing.expectEqualStrings("7604", script[(off - 2) * 2 .. off * 2]);
    try std.testing.expectEqualStrings("819c69", script[(off + 4) * 2 .. (off + 7) * 2]);

    // Byte-identical to the TypeScript reference.
    try std.testing.expectEqual(TS_SCRIPT_LEN_BYTES * 2, script.len);
    try std.testing.expectEqualStrings(TS_SCRIPT_SHA256, &sha256Hex(script));

    // Key order: codePartLenSlots immediately after codeSepIndexSlots.
    const csis = std.mem.indexOf(u8, json, "\"codeSepIndexSlots\":[") orelse return error.MissingCodeSepIndexSlots;
    const close = std.mem.indexOfPos(u8, json, csis, "],") orelse return error.Malformed;
    try std.testing.expect(std.mem.startsWith(u8, json[close + 2 ..], "\"codePartLenSlots\":[{\"byteOffset\":947}]"));
}

test "N-051: a fully fixed-width contract keeps an equality pin and records no slot" {
    const allocator = std.testing.allocator;
    const json = try compileJson(allocator, FIXED_SRC);
    defer allocator.free(json);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    const script = root.get("script").?.string;

    try std.testing.expect(root.get("codePartLenSlots") == null);
    try std.testing.expect(std.mem.indexOf(u8, script, "819c69") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "81a269") == null);
}
