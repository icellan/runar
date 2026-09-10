//! R-069: seven-tier builtin-coverage parity for the Zig tier.
//!
//! CLAUDE.md makes frontend parity an invariant with "no exceptions": a
//! contract that compiles in six tiers must compile in the seventh, to the
//! same bytes. A seven-tier probe sweep over every entry of
//! `BUILTIN_FUNCTIONS` (packages/runar-compiler/src/passes/03-typecheck.ts)
//! found eleven builtins that the TypeScript, Go, Rust, Python and Ruby tiers
//! all lower, and that the Zig tier rejected outright at stack lowering with
//! `InvalidBuiltin`:
//!
//!     exit  pack  toByteString  right
//!     extractVersion  extractHashSequence  extractInputIndex
//!     extractScriptCode  extractAmount  extractSequence  extractOutputs
//!
//! Each `EXPECTED_*` constant below is the hex the peer tiers emit for the
//! probe source next to it — captured by compiling that exact source through
//! `compilers/go/runar-go --source <probe> --hex --disable-constant-folding`
//! and cross-checked against ts / rust / python / ruby, which agree byte for
//! byte. Byte-identity with the peers is the requirement; "some correct
//! lowering" is not, because a divergent-but-plausible sequence still breaks
//! cross-tier hex parity.
//!
//! The probes deliberately consume the extracted numeric fields with `> 0n`
//! rather than `=== expected`: the `===` route exposes an unrelated,
//! pre-existing ts/rust-vs-rest disagreement over whether a preimage
//! extractor's result compares with OP_EQUAL or OP_NUMEQUAL, which would
//! smuggle a second variable into these fixtures.
//!
//! `EXPECTED_*` values are self-contained here on purpose: they are NOT read
//! from conformance goldens, so this file can never be "fixed" by moving a
//! golden.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

/// Compile a `.runar.ts` probe through the Zig tier and return its script hex.
/// `.runar.ts` (rather than the Zig DSL) keeps the source byte-identical to
/// what the reference hex was captured from.
fn compileProbe(allocator: std.mem.Allocator, source: []const u8) ![]const u8 {
    return compiler_api.compileSourceToHex(allocator, source, "Probe.runar.ts");
}

fn expectProbeHex(source: []const u8, expected: []const u8) !void {
    const allocator = std.testing.allocator;
    const hex = try compileProbe(allocator, source);
    defer allocator.free(hex);
    try std.testing.expectEqualStrings(expected, hex);
}

// ---------------------------------------------------------------------------
// exit(cond) — identical lowering to assert(): OP_VERIFY.
// ---------------------------------------------------------------------------

const SRC_EXIT =
    \\import { SmartContract, assert, exit } from 'runar-lang';
    \\
    \\class Probe extends SmartContract {
    \\  readonly seed: bigint;
    \\
    \\  constructor(seed: bigint) {
    \\    super(seed);
    \\    this.seed = seed;
    \\  }
    \\
    \\  public run(c: boolean) {
    \\    assert(this.seed === this.seed);
    \\    exit(c);
    \\    assert(this.seed === this.seed);
    \\  }
    \\}
;
const EXPECTED_EXIT = "00009d6900009c77";

test "R-069: exit() lowers to OP_VERIFY, byte-identical to the peer tiers" {
    try expectProbeHex(SRC_EXIT, EXPECTED_EXIT);
}

// ---------------------------------------------------------------------------
// pack(v) / toByteString(v) — type-level casts, no opcodes of their own.
// ---------------------------------------------------------------------------

const SRC_PACK =
    \\import { SmartContract, assert, pack } from 'runar-lang';
    \\
    \\class Probe extends SmartContract {
    \\  readonly seed: bigint;
    \\
    \\  constructor(seed: bigint) {
    \\    super(seed);
    \\    this.seed = seed;
    \\  }
    \\
    \\  public run(v: bigint, expected: ByteString) {
    \\    assert(this.seed === this.seed);
    \\    assert(pack(v) === expected);
    \\  }
    \\}
;
const EXPECTED_PACK = "00009d87";

test "R-069: pack() is a no-op cast, byte-identical to the peer tiers" {
    try expectProbeHex(SRC_PACK, EXPECTED_PACK);
}

const SRC_TO_BYTE_STRING =
    \\import { SmartContract, assert, toByteString } from 'runar-lang';
    \\
    \\class Probe extends SmartContract {
    \\  readonly seed: bigint;
    \\
    \\  constructor(seed: bigint) {
    \\    super(seed);
    \\    this.seed = seed;
    \\  }
    \\
    \\  public run(v: ByteString, expected: ByteString) {
    \\    assert(this.seed === this.seed);
    \\    assert(toByteString(v) === expected);
    \\  }
    \\}
;
const EXPECTED_TO_BYTE_STRING = "00009d87";

test "R-069: toByteString() is a no-op cast, byte-identical to the peer tiers" {
    try expectProbeHex(SRC_TO_BYTE_STRING, EXPECTED_TO_BYTE_STRING);
}

// ---------------------------------------------------------------------------
// right(data, n) — OP_SWAP OP_SIZE OP_ROT OP_SUB OP_SPLIT OP_NIP.
// ---------------------------------------------------------------------------

const SRC_RIGHT =
    \\import { SmartContract, assert, right } from 'runar-lang';
    \\
    \\class Probe extends SmartContract {
    \\  readonly seed: bigint;
    \\
    \\  constructor(seed: bigint) {
    \\    super(seed);
    \\    this.seed = seed;
    \\  }
    \\
    \\  public run(data: ByteString, n: bigint, expected: ByteString) {
    \\    assert(this.seed === this.seed);
    \\    assert(right(data, n) === expected);
    \\  }
    \\}
;
const EXPECTED_RIGHT = "00009d7b7b7c827b947f777c87";

test "R-069: right() lowers to the peer tiers' end-relative split" {
    try expectProbeHex(SRC_RIGHT, EXPECTED_RIGHT);
}

// ---------------------------------------------------------------------------
// Preimage field extractors.
// ---------------------------------------------------------------------------

/// Numeric extractor probe: `assert(<fn>(p) > 0n)`.
fn numericExtractorSource(comptime fn_name: []const u8) []const u8 {
    return "import { SmartContract, assert, " ++ fn_name ++ " } from 'runar-lang';\n" ++
        "import type { SigHashPreimage } from 'runar-lang';\n" ++
        "\n" ++
        "class Probe extends SmartContract {\n" ++
        "  readonly seed: bigint;\n" ++
        "\n" ++
        "  constructor(seed: bigint) {\n" ++
        "    super(seed);\n" ++
        "    this.seed = seed;\n" ++
        "  }\n" ++
        "\n" ++
        "  public run(p: SigHashPreimage) {\n" ++
        "    assert(this.seed === this.seed);\n" ++
        "    assert(" ++ fn_name ++ "(p) > 0n);\n" ++
        "  }\n" ++
        "}\n";
}

/// Byte-string extractor probe: `assert(<fn>(p) === expected)`.
fn bytesExtractorSource(comptime fn_name: []const u8) []const u8 {
    return "import { SmartContract, assert, " ++ fn_name ++ " } from 'runar-lang';\n" ++
        "import type { SigHashPreimage } from 'runar-lang';\n" ++
        "\n" ++
        "class Probe extends SmartContract {\n" ++
        "  readonly seed: bigint;\n" ++
        "\n" ++
        "  constructor(seed: bigint) {\n" ++
        "    super(seed);\n" ++
        "    this.seed = seed;\n" ++
        "  }\n" ++
        "\n" ++
        "  public run(p: SigHashPreimage, expected: ByteString) {\n" ++
        "    assert(this.seed === this.seed);\n" ++
        "    assert(" ++ fn_name ++ "(p) === expected);\n" ++
        "  }\n" ++
        "}\n";
}

test "R-069: extractVersion lowers to <4> OP_SPLIT OP_DROP OP_BIN2NUM" {
    try expectProbeHex(numericExtractorSource("extractVersion"), "00009d547f758100a0");
}

test "R-069: extractInputIndex lowers to the peer tiers' vout slice" {
    try expectProbeHex(numericExtractorSource("extractInputIndex"), "00009d01647f77547f758100a0");
}

test "R-069: extractAmount lowers to the peer tiers' end-relative 8-byte slice" {
    try expectProbeHex(numericExtractorSource("extractAmount"), "00009d820134947f77587f758100a0");
}

test "R-069: extractSequence lowers to the peer tiers' end-relative 4-byte slice" {
    try expectProbeHex(numericExtractorSource("extractSequence"), "00009d82012c947f77547f758100a0");
}

test "R-069: extractHashSequence lowers to the peer tiers' 36/32 absolute slice" {
    try expectProbeHex(bytesExtractorSource("extractHashSequence"), "00009d7c01247f7701207f757c87");
}

test "R-069: extractOutputs lowers to the peer tiers' end-relative 32-byte slice" {
    try expectProbeHex(bytesExtractorSource("extractOutputs"), "00009d7c820128947f7701207f757c87");
}

test "R-069: extractScriptCode lowers to the peer tiers' variable-length slice" {
    try expectProbeHex(bytesExtractorSource("extractScriptCode"), "00009d7c01687f77820134947f757c87");
}

// ---------------------------------------------------------------------------
// Control: the fix must not turn the builtin table into a blanket pass-through.
// ---------------------------------------------------------------------------

const SRC_UNKNOWN_BUILTIN =
    \\import { SmartContract, assert } from 'runar-lang';
    \\
    \\class Probe extends SmartContract {
    \\  readonly seed: bigint;
    \\
    \\  constructor(seed: bigint) {
    \\    super(seed);
    \\    this.seed = seed;
    \\  }
    \\
    \\  public run(v: bigint) {
    \\    assert(this.seed === this.seed);
    \\    assert(definitelyNotARunarBuiltin(v) > 0n);
    \\  }
    \\}
;

test "R-069 control: an unknown builtin name is still rejected" {
    const allocator = std.testing.allocator;
    const result = compileProbe(allocator, SRC_UNKNOWN_BUILTIN);
    if (result) |hex| {
        allocator.free(hex);
        return error.UnknownBuiltinWasAccepted;
    } else |_| {
        // Any compile error is acceptable; acceptance is not.
    }
}

// ---------------------------------------------------------------------------
// Semantics.
//
// Byte-identity with the peer tiers proves agreement, not correctness — a
// sequence identical to a WRONG reference still passes every assertion above.
// The tests below therefore EXECUTE the opcodes the tier just emitted against
// a synthetic BIP-143 preimage and check the field values that come back.
//
// The Zig tier ships no ScriptVM (CLAUDE.md: no usable upstream BSV script
// interpreter for this toolchain), so this is a deliberately minimal machine
// covering exactly the opcodes these lowerings emit.
// ---------------------------------------------------------------------------

const VmError = error{ StackUnderflow, StackOverflow, UnsupportedOpcode, OutOfMemory, TruncatedPush };

const Vm = struct {
    allocator: std.mem.Allocator,
    items: [16][]u8 = undefined,
    sp: usize = 0,

    fn deinit(self: *Vm) void {
        while (self.sp > 0) {
            self.sp -= 1;
            self.allocator.free(self.items[self.sp]);
        }
    }

    fn push(self: *Vm, bytes: []const u8) !void {
        if (self.sp == self.items.len) return VmError.StackOverflow;
        self.items[self.sp] = try self.allocator.dupe(u8, bytes);
        self.sp += 1;
    }

    fn pop(self: *Vm) ![]u8 {
        if (self.sp == 0) return VmError.StackUnderflow;
        self.sp -= 1;
        return self.items[self.sp];
    }

    fn top(self: *Vm) ![]const u8 {
        if (self.sp == 0) return VmError.StackUnderflow;
        return self.items[self.sp - 1];
    }

    fn encodeNum(allocator: std.mem.Allocator, value: i64) ![]u8 {
        if (value == 0) return allocator.alloc(u8, 0);
        var v: u64 = @intCast(value);
        var tmp: [9]u8 = undefined;
        var n: usize = 0;
        while (v > 0) : (v >>= 8) {
            tmp[n] = @truncate(v & 0xff);
            n += 1;
        }
        if (tmp[n - 1] & 0x80 != 0) {
            tmp[n] = 0;
            n += 1;
        }
        return allocator.dupe(u8, tmp[0..n]);
    }

    fn decodeNum(bytes: []const u8) i64 {
        var v: u64 = 0;
        var i: usize = bytes.len;
        while (i > 0) {
            i -= 1;
            v = (v << 8) | bytes[i];
        }
        return @intCast(v);
    }

    /// Drop leading zero bytes so the value matches OP_BIN2NUM's minimal encoding.
    fn minimalEncode(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
        var end = bytes.len;
        while (end > 0 and bytes[end - 1] == 0) end -= 1;
        return allocator.dupe(u8, bytes[0..end]);
    }

    fn run(self: *Vm, script: []const u8) !void {
        var pc: usize = 0;
        while (pc < script.len) {
            const op = script[pc];
            pc += 1;
            switch (op) {
                0x01...0x4b => { // direct push of `op` bytes
                    const n: usize = op;
                    if (pc + n > script.len) return VmError.TruncatedPush;
                    try self.push(script[pc .. pc + n]);
                    pc += n;
                },
                0x51...0x60 => { // OP_1 .. OP_16
                    const v: i64 = @intCast(op - 0x50);
                    const bytes = try encodeNum(self.allocator, v);
                    defer self.allocator.free(bytes);
                    try self.push(bytes);
                },
                0x75 => self.allocator.free(try self.pop()), // OP_DROP
                0x77 => { // OP_NIP
                    const a = try self.pop();
                    const b = try self.pop();
                    self.allocator.free(b);
                    self.items[self.sp] = a;
                    self.sp += 1;
                },
                0x7b => { // OP_ROT
                    const a = try self.pop();
                    const b = try self.pop();
                    const c = try self.pop();
                    defer self.allocator.free(a);
                    defer self.allocator.free(b);
                    defer self.allocator.free(c);
                    try self.push(b);
                    try self.push(a);
                    try self.push(c);
                },
                0x7c => { // OP_SWAP
                    const a = try self.pop();
                    const b = try self.pop();
                    defer self.allocator.free(a);
                    defer self.allocator.free(b);
                    try self.push(a);
                    try self.push(b);
                },
                0x7f => { // OP_SPLIT
                    const pos_bytes = try self.pop();
                    defer self.allocator.free(pos_bytes);
                    const data = try self.pop();
                    defer self.allocator.free(data);
                    const at: usize = @intCast(decodeNum(pos_bytes));
                    try self.push(data[0..at]);
                    try self.push(data[at..]);
                },
                0x81 => { // OP_BIN2NUM
                    const a = try self.pop();
                    defer self.allocator.free(a);
                    const m = try minimalEncode(self.allocator, a);
                    defer self.allocator.free(m);
                    try self.push(m);
                },
                0x82 => { // OP_SIZE
                    const n: i64 = @intCast((try self.top()).len);
                    const bytes = try encodeNum(self.allocator, n);
                    defer self.allocator.free(bytes);
                    try self.push(bytes);
                },
                0x94 => { // OP_SUB
                    const b = try self.pop();
                    defer self.allocator.free(b);
                    const a = try self.pop();
                    defer self.allocator.free(a);
                    const bytes = try encodeNum(self.allocator, decodeNum(a) - decodeNum(b));
                    defer self.allocator.free(bytes);
                    try self.push(bytes);
                },
                else => return VmError.UnsupportedOpcode,
            }
        }
    }
};

fn hexToBytes(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        out[i] = try std.fmt.parseInt(u8, hex[i * 2 .. i * 2 + 2], 16);
    }
    return out;
}

fn bytesToHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |b, i| {
        _ = try std.fmt.bufPrint(out[i * 2 ..][0..2], "{x:0>2}", .{b});
    }
    return out;
}

/// A synthetic BIP-143 sighash preimage, 161 bytes:
///   nVersion      4  = 2
///   hashPrevouts 32  = 0x11 * 32
///   hashSequence 32  = 0x22 * 32
///   outpoint     36  = 0x33 * 32 || vout(4) = 7
///   scriptCode    5  = aabbccddee
///   amount        8  = 100000
///   nSequence     4  = 10
///   hashOutputs  32  = 0x44 * 32
///   nLocktime     4  = 5
///   sighashType   4  = 65
const PREIMAGE_HEX =
    "02000000" ++
    ("11" ** 32) ++
    ("22" ** 32) ++
    ("33" ** 32) ++ "07000000" ++
    "aabbccddee" ++
    "a086010000000000" ++
    "0a000000" ++
    ("44" ** 32) ++
    "05000000" ++
    "41000000";

/// Run `core_hex` with the synthetic preimage on the stack; return the top
/// item as hex. The caller owns the result.
fn runExtractorCore(allocator: std.mem.Allocator, core_hex: []const u8) ![]u8 {
    const preimage = try hexToBytes(allocator, PREIMAGE_HEX);
    defer allocator.free(preimage);
    const script = try hexToBytes(allocator, core_hex);
    defer allocator.free(script);

    var vm = Vm{ .allocator = allocator };
    defer vm.deinit();
    try vm.push(preimage);
    try vm.run(script);
    return bytesToHex(allocator, try vm.top());
}

/// Assert `core_hex` is the sequence the tier actually emitted for `source`
/// (so the semantic check cannot drift away from the codegen), then run it.
fn expectExtractorValue(source: []const u8, core_hex: []const u8, expected_hex: []const u8) !void {
    const allocator = std.testing.allocator;

    const emitted = try compileProbe(allocator, source);
    defer allocator.free(emitted);
    try std.testing.expect(std.mem.indexOf(u8, emitted, core_hex) != null);

    const got = try runExtractorCore(allocator, core_hex);
    defer allocator.free(got);
    try std.testing.expectEqualStrings(expected_hex, got);
}

test "R-069 semantics: the synthetic preimage is the length the layout implies" {
    try std.testing.expectEqual(@as(usize, 161 * 2), PREIMAGE_HEX.len);
}

test "R-069 semantics: extractVersion yields nVersion (2)" {
    // <4> OP_SPLIT OP_DROP OP_BIN2NUM
    try expectExtractorValue(numericExtractorSource("extractVersion"), "547f7581", "02");
}

test "R-069 semantics: extractInputIndex yields the outpoint vout (7)" {
    // <100> OP_SPLIT OP_NIP <4> OP_SPLIT OP_DROP OP_BIN2NUM
    try expectExtractorValue(numericExtractorSource("extractInputIndex"), "01647f77547f7581", "07");
}

test "R-069 semantics: extractAmount yields the satoshi amount (100000)" {
    // OP_SIZE <52> OP_SUB OP_SPLIT OP_NIP <8> OP_SPLIT OP_DROP OP_BIN2NUM
    try expectExtractorValue(numericExtractorSource("extractAmount"), "820134947f77587f7581", "a08601");
}

test "R-069 semantics: extractSequence yields nSequence (10)" {
    try expectExtractorValue(numericExtractorSource("extractSequence"), "82012c947f77547f7581", "0a");
}

test "R-069 semantics: extractHashSequence yields the 32-byte hashSequence" {
    try expectExtractorValue(
        bytesExtractorSource("extractHashSequence"),
        "01247f7701207f75",
        "22" ** 32,
    );
}

test "R-069 semantics: extractOutputs yields the 32-byte hashOutputs" {
    try expectExtractorValue(
        bytesExtractorSource("extractOutputs"),
        "820128947f7701207f75",
        "44" ** 32,
    );
}

test "R-069 semantics: extractScriptCode yields the variable-length scriptCode" {
    try expectExtractorValue(
        bytesExtractorSource("extractScriptCode"),
        "01687f77820134947f75",
        "aabbccddee",
    );
}

test "R-069 semantics: right() returns the LAST n bytes, not the first" {
    const allocator = std.testing.allocator;

    const emitted = try compileProbe(allocator, SRC_RIGHT);
    defer allocator.free(emitted);
    // OP_SWAP OP_SIZE OP_ROT OP_SUB OP_SPLIT OP_NIP
    const core = "7c827b947f77";
    try std.testing.expect(std.mem.indexOf(u8, emitted, core) != null);

    const data = try hexToBytes(allocator, "aabbccddee");
    defer allocator.free(data);
    const script = try hexToBytes(allocator, core);
    defer allocator.free(script);

    var vm = Vm{ .allocator = allocator };
    defer vm.deinit();
    try vm.push(data);
    const two = try Vm.encodeNum(allocator, 2);
    defer allocator.free(two);
    try vm.push(two);
    try vm.run(script);

    const got = try bytesToHex(allocator, try vm.top());
    defer allocator.free(got);
    // "ddee" — the last two bytes. A left()-shaped bug would return "aabb".
    try std.testing.expectEqualStrings("ddee", got);
}
