//! Codegen op-shape tests for the language-construct rows the Zig tier
//! previously exercised only through the cross-tier conformance suite
//! (GAP-m9 / audit section 4 follow-up).
//!
//! The pipeline passes (validate / typecheck / ANF / constant-fold /
//! expand-fixed-arrays) and the type-system rows (bigint / bool /
//! ByteString / Point / fixed arrays / assert / if-else / for-loops)
//! already carry assertion-grade inline `test` blocks in their respective
//! `passes/*.zig` source files. The genuine remaining gaps were the
//! *codegen* rows with no dedicated per-tier probe:
//!
//!   C3  addOutput            — multi-output state continuation
//!   C4  addRawOutput         — caller-specified script bytes output
//!   D8  if-without-else      — control-flow merge
//!   D10 bitwise on bigint    — & | ^ ~
//!   D11 bitwise on ByteString
//!   D12 shift << >>
//!
//! Each test compiles a minimal contract exercising the construct and
//! asserts the compiled hex contains the construct's load-bearing opcodes.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

fn hexHasOpcode(hex: []const u8, opcode: []const u8) bool {
    std.debug.assert(opcode.len == 2);
    var i: usize = 0;
    while (i + 1 < hex.len) : (i += 2) {
        if (hex[i] == opcode[0] and hex[i + 1] == opcode[1]) return true;
    }
    return false;
}

fn compile(comptime source: []const u8, file_name: []const u8) ![]const u8 {
    return compiler_api.compileSourceToHex(std.testing.allocator, source, file_name);
}

// C3 — addOutput (multi-output state continuation).
test "addOutput emits the BIP-143 output serialization opcodes" {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const OutputProbe = struct {
        \\    pub const Contract = runar.StatefulSmartContract;
        \\
        \\    count: i64 = 0,
        \\
        \\    pub fn init(count: i64) OutputProbe {
        \\        return .{ .count = count };
        \\    }
        \\
        \\    pub fn bump(self: *OutputProbe) void {
        \\        self.count = self.count + 1;
        \\        self.addOutput(1000, self.count);
        \\    }
        \\};
    ;
    const hex = try compile(source, "OutputProbe.runar.zig");
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hexHasOpcode(hex, "82")); // OP_SIZE — script-len prefix
    try std.testing.expect(hexHasOpcode(hex, "7e")); // OP_CAT — output assembly
    try std.testing.expect(hexHasOpcode(hex, "80")); // OP_NUM2BIN — 8-byte LE satoshis
}

// C4 — addRawOutput (caller-specified script bytes).
test "addRawOutput emits the BIP-143 output serialization opcodes" {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const RawProbe = struct {
        \\    pub const Contract = runar.StatefulSmartContract;
        \\
        \\    count: i64 = 0,
        \\
        \\    pub fn init(count: i64) RawProbe {
        \\        return .{ .count = count };
        \\    }
        \\
        \\    pub fn sendToScript(self: *RawProbe, scriptBytes: runar.ByteString) void {
        \\        self.addRawOutput(1000, scriptBytes);
        \\        self.count = self.count + 1;
        \\        self.addOutput(0, self.count);
        \\    }
        \\};
    ;
    const hex = try compile(source, "RawProbe.runar.zig");
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hexHasOpcode(hex, "82")); // OP_SIZE
    try std.testing.expect(hexHasOpcode(hex, "7e")); // OP_CAT
    try std.testing.expect(hexHasOpcode(hex, "80")); // OP_NUM2BIN
}

// D8 — if without else (control-flow merge).
test "if without else emits OP_IF / OP_ENDIF" {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const IfProbe = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    threshold: i64,
        \\
        \\    pub fn init(threshold: i64) IfProbe {
        \\        return .{ .threshold = threshold };
        \\    }
        \\
        \\    pub fn check(self: *const IfProbe, a: i64) void {
        \\        var x: i64 = a;
        \\        if (a > self.threshold) {
        \\            x = a - self.threshold;
        \\        }
        \\        runar.assert(x >= 0 or x < 0);
        \\    }
        \\};
    ;
    const hex = try compile(source, "IfProbe.runar.zig");
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hexHasOpcode(hex, "63")); // OP_IF
    try std.testing.expect(hexHasOpcode(hex, "68")); // OP_ENDIF
}

// #121 — a countdown for-loop (`i > 0`, from 3; unrolled as i = 3,2,1). The
// expected hex is byte-identical to the TypeScript reference compiler's output
// for the same contract, pinning cross-tier parity for issue #121.
test "countdown for-loop matches the TS reference hex (#121)" {
    const source =
        \\import { SmartContract, assert } from 'runar-lang';
        \\
        \\class Down1 extends SmartContract {
        \\  readonly expectedSum: bigint;
        \\
        \\  constructor(expectedSum: bigint) {
        \\    super(expectedSum);
        \\    this.expectedSum = expectedSum;
        \\  }
        \\
        \\  public verify(base: bigint): void {
        \\    let sum: bigint = 0n;
        \\    for (let i: bigint = 3n; i > 0n; i--) {
        \\      sum = sum + base + i;
        \\    }
        \\    assert(sum === this.expectedSum);
        \\  }
        \\}
    ;
    const hex = try compile(source, "Down1.runar.ts");
    defer std.testing.allocator.free(hex);
    try std.testing.expectEqualStrings(
        "005352797b7c937c935252797b7c937c93517b7b7c937c93009c",
        hex,
    );
}

// #121 — a non-zero-start ascending for-loop (`j < 5`, from 2; unrolled as
// j = 2,3,4). Byte-identical to the TypeScript reference compiler output.
test "non-zero-start for-loop matches the TS reference hex (#121)" {
    const source =
        \\import { SmartContract, assert } from 'runar-lang';
        \\
        \\class Up1 extends SmartContract {
        \\  readonly expectedSum: bigint;
        \\
        \\  constructor(expectedSum: bigint) {
        \\    super(expectedSum);
        \\    this.expectedSum = expectedSum;
        \\  }
        \\
        \\  public verify(base: bigint): void {
        \\    let sum: bigint = 0n;
        \\    for (let j: bigint = 2n; j < 5n; j++) {
        \\      sum = sum + base + j;
        \\    }
        \\    assert(sum === this.expectedSum);
        \\  }
        \\}
    ;
    const hex = try compile(source, "Up1.runar.ts");
    defer std.testing.allocator.free(hex);
    try std.testing.expectEqualStrings(
        "005252797b7c937c935352797b7c937c93547b7b7c937c93009c",
        hex,
    );
}

// A loop-carried local REASSIGNED and then READ AGAIN in the same iteration.
// The rebinding shadows the incoming slot under the same name; the later read
// was its last body use, so it consumed the UPDATED value and left the dead
// incoming one for the next iteration to resolve. `wacc` came out as `step*N`
// instead of `step*N*(N+1)/2` — silently in a stateless contract, and as a
// permanently unspendable UTXO in a stateful one. The expected hex is
// byte-identical to the TypeScript reference compiler's output. Real-VM proof:
// packages/runar-testing/src/__tests__/loop-carried-local-read-after-reassign-vm.test.ts
test "loop-carried local read after reassignment matches the TS reference hex" {
    const source =
        \\import { SmartContract, assert } from 'runar-lang';
        \\
        \\class LoopCarriedRebind extends SmartContract {
        \\  readonly expected: bigint;
        \\
        \\  constructor(expected: bigint) {
        \\    super(expected);
        \\    this.expected = expected;
        \\  }
        \\
        \\  public verify(step: bigint) {
        \\    let acc = 0n;
        \\    let wacc = 0n;
        \\    for (let i = 0n; i < 2n; i++) {
        \\      acc = acc + step;
        \\      wacc = wacc + acc;
        \\    }
        \\    assert(wacc === this.expected);
        \\  }
        \\}
    ;
    const hex = try compile(source, "LoopCarriedRebind.runar.ts");
    defer std.testing.allocator.free(hex);
    try std.testing.expectEqualStrings(
        "000000537953797c937b78937b7551547a53797c937b7c9377009c7777",
        hex,
    );
}

// Control for the test above: the same loop with a single self-accumulating
// carrier — no read after the rebinding. Its bytes must NOT move, or the
// carried-rebind fix has been written too wide and every shipped
// BoundedLoop-shaped contract pays.
// R-186 / R-292 re-stamped this pin on 2026-09-14: the accumulator body leaves
// the carried local on top, so the iteration variable sat one slot down and
// `lowerLoop`'s `depth == 0` cleanup never fired. The control still says what it
// was written to say about the carried-rebind fix; it no longer pins the bytes
// that predate it.
test "plain accumulator loop is untouched by the carried-rebind fix" {
    const source =
        \\import { SmartContract, assert } from 'runar-lang';
        \\
        \\class LoopPlainAccumulator extends SmartContract {
        \\  readonly expected: bigint;
        \\
        \\  constructor(expected: bigint) {
        \\    super(expected);
        \\    this.expected = expected;
        \\  }
        \\
        \\  public verify(step: bigint) {
        \\    let acc = 0n;
        \\    for (let i = 0n; i < 2n; i++) {
        \\      acc = acc + step;
        \\    }
        \\    assert(acc === this.expected);
        \\  }
        \\}
    ;
    const hex = try compile(source, "LoopPlainAccumulator.runar.ts");
    defer std.testing.allocator.free(hex);
    try std.testing.expectEqualStrings(
        "000052797b7c9377517b7b7c9377009c",
        hex,
    );
}

// The same cross-read one loop deeper. The predicate keys on the body's
// TOP-LEVEL binding names, and at the OUTER level `acc` is bound only inside
// the nested loop — so it was neither an outer ref nor a carried rebind, and
// every outer iteration restarted from the slot the previous one left behind.
// `wacc` came out 24 where the source says 30 (step = 3). The expected hex is
// byte-identical to the TypeScript reference compiler's output. Real-VM proof:
// packages/runar-testing/src/__tests__/nested-loop-carried-local-vm.test.ts
test "nested loop-carried local read after reassignment matches the TS reference hex" {
    const source =
        \\import { SmartContract, assert } from 'runar-lang';
        \\
        \\class LoopNestedCarriedRebind extends SmartContract {
        \\  readonly expected: bigint;
        \\
        \\  constructor(expected: bigint) {
        \\    super(expected);
        \\    this.expected = expected;
        \\  }
        \\
        \\  public verify(step: bigint) {
        \\    let acc = 0n;
        \\    let wacc = 0n;
        \\    for (let i = 0n; i < 2n; i++) {
        \\      for (let j = 0n; j < 2n; j++) {
        \\        acc = acc + step;
        \\        wacc = wacc + acc;
        \\      }
        \\    }
        \\    assert(wacc === this.expected);
        \\  }
        \\}
    ;
    const hex = try compile(source, "LoopNestedCarriedRebind.runar.ts");
    defer std.testing.allocator.free(hex);
    try std.testing.expectEqualStrings(
        "00000000547954797c93537a78937b7551557953797c937b78937b75537a755100567954797c93537a78937b7551577a53797c937b7c93777b75009c77777777",
        hex,
    );
}

// Control for the test above: NESTED loops with a single self-accumulating
// carrier. The flatten step fires here (the body does contain a nested loop)
// but the predicate still says "not carried", so the bytes must NOT move —
// that is what keeps nesting itself from costing anything.
// R-186 / R-292 re-stamped this pin on 2026-09-14 as well. Nesting still costs
// nothing — the single-level accumulator moved by exactly the same change.
test "nested plain accumulator loop is untouched by the nested carried-rebind fix" {
    const source =
        \\import { SmartContract, assert } from 'runar-lang';
        \\
        \\class LoopNestedPlainAccumulator extends SmartContract {
        \\  readonly expected: bigint;
        \\
        \\  constructor(expected: bigint) {
        \\    super(expected);
        \\    this.expected = expected;
        \\  }
        \\
        \\  public verify(step: bigint) {
        \\    let acc = 0n;
        \\    for (let i = 0n; i < 2n; i++) {
        \\      for (let j = 0n; j < 2n; j++) {
        \\        acc = acc + step;
        \\      }
        \\    }
        \\    assert(acc === this.expected);
        \\  }
        \\}
    ;
    const hex = try compile(source, "LoopNestedPlainAccumulator.runar.ts");
    defer std.testing.allocator.free(hex);
    try std.testing.expectEqualStrings(
        "0000005379537a7c93775153797b7c93777751005379537a7c937751537a7b7c937777009c",
        hex,
    );
}

// D10 — bitwise & | ^ ~ on bigint.
test "bitwise operators on bigint emit OP_AND / OP_OR / OP_XOR / OP_INVERT" {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const BitProbe = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    a: i64,
        \\    b: i64,
        \\
        \\    pub fn init(a: i64, b: i64) BitProbe {
        \\        return .{ .a = a, .b = b };
        \\    }
        \\
        \\    pub fn check(self: *const BitProbe) void {
        \\        const andResult = self.a & self.b;
        \\        const orResult = self.a | self.b;
        \\        const xorResult = self.a ^ self.b;
        \\        const notResult = ~self.a;
        \\        runar.assert(andResult >= 0 or andResult < 0);
        \\        runar.assert(orResult >= 0 or orResult < 0);
        \\        runar.assert(xorResult >= 0 or xorResult < 0);
        \\        runar.assert(notResult >= 0 or notResult < 0);
        \\    }
        \\};
    ;
    const hex = try compile(source, "BitProbe.runar.zig");
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hexHasOpcode(hex, "84")); // OP_AND
    try std.testing.expect(hexHasOpcode(hex, "85")); // OP_OR
    try std.testing.expect(hexHasOpcode(hex, "86")); // OP_XOR
    try std.testing.expect(hexHasOpcode(hex, "83")); // OP_INVERT
}

// D11 — bitwise on ByteString.
test "bitwise operators on ByteString emit OP_AND" {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const ByteBitProbe = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    mask: runar.ByteString,
        \\
        \\    pub fn init(mask: runar.ByteString) ByteBitProbe {
        \\        return .{ .mask = mask };
        \\    }
        \\
        \\    pub fn check(self: *const ByteBitProbe, data: runar.ByteString) void {
        \\        const masked = data & self.mask;
        \\        runar.assert(masked == self.mask);
        \\    }
        \\};
    ;
    const hex = try compile(source, "ByteBitProbe.runar.zig");
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hexHasOpcode(hex, "84")); // OP_AND
}

// D12 — shift << >>.
test "shift operators emit OP_LSHIFT / OP_RSHIFT" {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const ShiftProbe = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    a: i64,
        \\
        \\    pub fn init(a: i64) ShiftProbe {
        \\        return .{ .a = a };
        \\    }
        \\
        \\    pub fn check(self: *const ShiftProbe) void {
        \\        const left = self.a << 3;
        \\        const right = self.a >> 2;
        \\        runar.assert(left >= 0 or left < 0);
        \\        runar.assert(right >= 0 or right < 0);
        \\    }
        \\};
    ;
    const hex = try compile(source, "ShiftProbe.runar.zig");
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hexHasOpcode(hex, "98")); // OP_LSHIFT
    try std.testing.expect(hexHasOpcode(hex, "99")); // OP_RSHIFT
}
