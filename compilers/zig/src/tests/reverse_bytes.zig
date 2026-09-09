//! `reverseBytes` codegen tests (R-022).
//!
//! The Zig tier used to lower `reverseBytes` to *nothing at all*: the lowering
//! brought the argument to the top of the stack, renamed the stack slot and
//! returned without emitting a single opcode. That made the endianness
//! primitive a silent identity — `assert(reverseBytes(a) === b)` passed
//! exactly when `a === b` — while the other six tiers emitted a 520-iteration
//! unrolled reversal. For the probe contract below the Go tier emitted 11450
//! hex chars and the Zig tier emitted 4 (`0087`).
//!
//! Two independent guards live here:
//!
//!   1. `expectedReversalPrefix` reproduces, byte for byte, the sequence the
//!      other tiers emit (`compilers/go/codegen/stack.go#lowerReverseBytes`,
//!      `compilers/ruby/lib/runar_compiler/codegen/stack.rb#_lower_reverse_bytes`):
//!
//!          OP_0 OP_SWAP
//!          520x [ OP_DUP OP_SIZE OP_NIP
//!                 OP_IF OP_1 OP_SPLIT OP_SWAP OP_ROT OP_CAT OP_SWAP OP_ENDIF ]
//!          OP_DROP
//!
//!      Byte-identity with the peer tiers is the requirement, not merely "some
//!      correct reversal" — a different-but-correct sequence fails conformance.
//!
//!   2. A miniature stack machine executes the emitted opcodes on `0x0102` and
//!      asserts the result is `0x0201`. Structural equality alone would also be
//!      satisfied by a sequence that is byte-identical to a *wrong* reference,
//!      so the semantics are checked separately from the shape.
//!
//! The control against the old behaviour is explicit: `PRE_FIX_HEX` is the
//! literal hex the tier produced before the fix, and the first test asserts the
//! output differs from it and is materially longer than the identity.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

/// The complete script the Zig tier emitted for `revProbe` before R-022:
/// the constructor-slot placeholder plus OP_EQUAL, with no reversal at all.
const PRE_FIX_HEX = "0087";

/// One unrolled iteration of the reversal loop, as emitted by every other tier.
/// OP_DUP OP_SIZE OP_NIP OP_IF OP_1 OP_SPLIT OP_SWAP OP_ROT OP_CAT OP_SWAP OP_ENDIF
const ITERATION_HEX = "76827763517f7c7b7e7c68";

/// Iteration count: 520 = the maximum BSV stack-element size, so the unrolled
/// loop can reverse any legal ByteString.
const ITERATIONS = 520;

/// Build the exact opcode prefix the reversal must emit:
/// OP_0 OP_SWAP, 520 unrolled iterations, OP_DROP.
fn expectedReversalPrefix(allocator: std.mem.Allocator) ![]u8 {
    const len = 4 + ITERATIONS * ITERATION_HEX.len + 2;
    const buf = try allocator.alloc(u8, len);
    var i: usize = 0;
    @memcpy(buf[i..][0..4], "007c"); // OP_0 OP_SWAP
    i += 4;
    var n: usize = 0;
    while (n < ITERATIONS) : (n += 1) {
        @memcpy(buf[i..][0..ITERATION_HEX.len], ITERATION_HEX);
        i += ITERATION_HEX.len;
    }
    @memcpy(buf[i..][0..2], "75"); // OP_DROP
    i += 2;
    std.debug.assert(i == len);
    return buf;
}

/// Compile a stateless contract whose only method asserts
/// `reverseBytes(data) === self.expected`. The reversal therefore sits at the
/// very start of the method script, which lets the interpreter test below run
/// the emitted prefix directly.
fn compileReverseProbe(allocator: std.mem.Allocator) ![]const u8 {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const RevProbe = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    expected: runar.ByteString,
        \\
        \\    pub fn init(expected: runar.ByteString) RevProbe {
        \\        return .{ .expected = expected };
        \\    }
        \\
        \\    pub fn check(self: *const RevProbe, data: runar.ByteString) void {
        \\        runar.assert(runar.reverseBytes(data) == self.expected);
        \\    }
        \\};
    ;
    return compiler_api.compileSourceToHex(allocator, source, "RevProbe.runar.zig");
}

test "reverseBytes emits the peer tiers' unrolled reversal, not the identity" {
    const allocator = std.testing.allocator;

    const hex = try compileReverseProbe(allocator);
    defer allocator.free(hex);

    // Control: the pre-fix tier emitted exactly this, and nothing else.
    try std.testing.expect(!std.mem.eql(u8, hex, PRE_FIX_HEX));
    try std.testing.expect(hex.len > 10_000);

    const expected_prefix = try expectedReversalPrefix(allocator);
    defer allocator.free(expected_prefix);

    try std.testing.expect(hex.len >= expected_prefix.len);
    try std.testing.expectEqualStrings(expected_prefix, hex[0..expected_prefix.len]);
}

// ---------------------------------------------------------------------------
// Semantic check: run the emitted opcodes and confirm the bytes are reversed.
// ---------------------------------------------------------------------------

const MiniVmError = error{ StackUnderflow, StackOverflow, UnsupportedOpcode, UnbalancedIf };

/// Minimal Bitcoin-Script stack machine covering exactly the opcodes the
/// reversal emits. Deliberately tiny: it exists to prove the emitted sequence
/// actually reverses, not to be a general interpreter.
const MiniVm = struct {
    allocator: std.mem.Allocator,
    items: [16][]u8 = undefined,
    sp: usize = 0,

    fn push(self: *MiniVm, bytes: []const u8) !void {
        if (self.sp == self.items.len) return MiniVmError.StackOverflow;
        self.items[self.sp] = try self.allocator.dupe(u8, bytes);
        self.sp += 1;
    }

    fn pop(self: *MiniVm) ![]u8 {
        if (self.sp == 0) return MiniVmError.StackUnderflow;
        self.sp -= 1;
        return self.items[self.sp];
    }

    /// Script-number truthiness: empty, all-zero, and negative-zero are false.
    fn isTruthy(bytes: []const u8) bool {
        for (bytes, 0..) |b, i| {
            if (b == 0) continue;
            if (i == bytes.len - 1 and b == 0x80) continue;
            return true;
        }
        return false;
    }

    /// Minimal little-endian script-number encoding (values here are 0..520).
    fn encodeNum(self: *MiniVm, value: usize) ![]u8 {
        if (value == 0) return self.allocator.alloc(u8, 0);
        var v = value;
        var tmp: [8]u8 = undefined;
        var n: usize = 0;
        while (v > 0) : (v >>= 8) {
            tmp[n] = @truncate(v & 0xff);
            n += 1;
        }
        if (tmp[n - 1] & 0x80 != 0) {
            tmp[n] = 0;
            n += 1;
        }
        return self.allocator.dupe(u8, tmp[0..n]);
    }

    fn decodeNum(bytes: []const u8) usize {
        var v: usize = 0;
        var i: usize = bytes.len;
        while (i > 0) {
            i -= 1;
            v = (v << 8) | bytes[i];
        }
        return v;
    }

    fn run(self: *MiniVm, script: []const u8) !void {
        var pc: usize = 0;
        while (pc < script.len) : (pc += 1) {
            switch (script[pc]) {
                0x00 => try self.push(&[_]u8{}), // OP_0
                0x51 => try self.push(&[_]u8{1}), // OP_1
                0x75 => _ = try self.pop(), // OP_DROP
                0x76 => { // OP_DUP
                    const top = self.items[self.sp - 1];
                    try self.push(top);
                },
                0x77 => { // OP_NIP
                    const top = try self.pop();
                    _ = try self.pop();
                    self.items[self.sp] = top;
                    self.sp += 1;
                },
                0x7b => { // OP_ROT
                    const a = try self.pop();
                    const b = try self.pop();
                    const c = try self.pop();
                    try self.push(b);
                    try self.push(a);
                    try self.push(c);
                },
                0x7c => { // OP_SWAP
                    const a = try self.pop();
                    const b = try self.pop();
                    try self.push(a);
                    try self.push(b);
                },
                0x7e => { // OP_CAT
                    const b = try self.pop();
                    const a = try self.pop();
                    const joined = try self.allocator.alloc(u8, a.len + b.len);
                    @memcpy(joined[0..a.len], a);
                    @memcpy(joined[a.len..], b);
                    if (self.sp == self.items.len) return MiniVmError.StackOverflow;
                    self.items[self.sp] = joined;
                    self.sp += 1;
                },
                0x7f => { // OP_SPLIT
                    const n_bytes = try self.pop();
                    const data = try self.pop();
                    const n = decodeNum(n_bytes);
                    try self.push(data[0..n]);
                    try self.push(data[n..]);
                },
                0x82 => { // OP_SIZE
                    const size = self.items[self.sp - 1].len;
                    const encoded = try self.encodeNum(size);
                    if (self.sp == self.items.len) return MiniVmError.StackOverflow;
                    self.items[self.sp] = encoded;
                    self.sp += 1;
                },
                0x63 => { // OP_IF — no ELSE and no nesting in this sequence
                    const cond = try self.pop();
                    if (!isTruthy(cond)) {
                        while (pc < script.len and script[pc] != 0x68) pc += 1;
                        if (pc == script.len) return MiniVmError.UnbalancedIf;
                    }
                },
                0x68 => {}, // OP_ENDIF
                else => return MiniVmError.UnsupportedOpcode,
            }
        }
    }
};

test "the emitted reverseBytes sequence actually reverses 0x0102 to 0x0201" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const hex = try compileReverseProbe(allocator);

    const prefix_hex = try expectedReversalPrefix(allocator);
    try std.testing.expect(hex.len >= prefix_hex.len);

    const script = try allocator.alloc(u8, prefix_hex.len / 2);
    _ = try std.fmt.hexToBytes(script, hex[0..prefix_hex.len]);

    var vm = MiniVm{ .allocator = allocator };
    try vm.push(&[_]u8{ 0x01, 0x02 });
    try vm.run(script);

    try std.testing.expectEqual(@as(usize, 1), vm.sp);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x01 }, vm.items[0]);
}
