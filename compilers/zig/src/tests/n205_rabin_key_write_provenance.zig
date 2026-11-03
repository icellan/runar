//! N-205 (a) — a stateful method must not write a spender-supplied value into
//! a MUTABLE property that verifyRabinSig uses as its public key.
//!
//! F-286 made verifyRabinSig's 4th argument a contract property or a literal,
//! but a mutable property is state the previous spend chose: `this.key =
//! newKey` (or `newKey` in the key's addOutput slot) lets a spender set the
//! next UTXO's modulus to 1 and forge any message one spend later. Rule (user
//! decision R80, ported from the TS reference `checkRabinPubKeyProvenance`):
//! every property whose value reaches a verifyRabinSig 4th argument is a KEY
//! property, closed under "is written into a key property"; outside the
//! constructor a mutable key property may only be written (assignment,
//! compound assignment, ++/--, addOutput slot) with a value F-286 trusts.
//!
//! Proves: this tier's validator refuses the write shapes below and accepts
//! the deployer-fixed ones, on the TS surface, the `.runar.zig` surface and
//! the bare-name Solidity surface, with the shared diagnostic naming the
//! property. Does not prove: the other six tiers, or the `--ir` path (that is
//! conformance/negatives/ir-rabin-key-provenance.test.ts).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

fn msgFor(w: std.mem.Allocator, prop: []const u8) ![]const u8 {
    return std.fmt.allocPrint(w, "verifyRabinSig public key property '{s}' may only be assigned a contract property or a literal " ++
        "outside the constructor; a spender-supplied Rabin modulus lets anyone forge a signature", .{prop});
}

const SETTER =
    \\  private setKey(v: RabinPubKey): void {
    \\    this.key = v;
    \\  }
;
const HELPER =
    \\  private check(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    \\    return verifyRabinSig(m, s, p, k);
    \\  }
;
const DIRECT = "verifyRabinSig(msg, sig, padding, this.key)";

/// `prop` null = must be accepted (no errors at all).
const Case = struct { label: []const u8, body: []const u8, extra: []const u8 = "", settle: []const u8 = DIRECT, prop: ?[]const u8 };

const cases = [_]Case{
    // refused: a spender chooses the next modulus
    .{ .label = "assigned a public parameter", .body = "this.key = newKey;", .prop = "key" },
    .{ .label = "assigned a const alias of a parameter", .body = "const k = newKey; this.key = k;", .prop = "key" },
    .{ .label = "compound assignment from a parameter", .body = "this.key += n;", .prop = "key" },
    .{ .label = "incremented", .body = "this.key++;", .prop = "key" },
    .{ .label = "assigned inside an if", .body = "if (n > 0n) { this.key = newKey; }", .prop = "key" },
    .{ .label = "parameter in its addOutput slot", .body = "this.addOutput(1000n, newKey, this.other, this.count);", .prop = "key" },
    .{ .label = "private setter fed a parameter", .body = "this.setKey(newKey);", .extra = SETTER, .prop = "key" },
    .{ .label = "key through a helper, written from a parameter", .body = "this.key = newKey;", .extra = HELPER, .settle = "this.check(msg, sig, padding, this.key)", .prop = "key" },
    .{ .label = "property feeding the key written from a parameter", .body = "this.key = this.other; this.other = newKey;", .prop = "other" },
    // accepted: the next modulus is fixed by the deployer
    .{ .label = "assigned a bigint literal", .body = "this.key = 1000003n;", .prop = null },
    .{ .label = "assigned a readonly property", .body = "this.key = this.backup;", .prop = null },
    .{ .label = "assigned a property only written from literals", .body = "this.key = this.other; this.other = 7n;", .prop = null },
    .{ .label = "non-key state written from a parameter", .body = "this.count = this.count + n;", .prop = null },
    .{ .label = "non-Rabin mutable property written from a parameter", .body = "this.other = newKey;", .prop = null },
    .{ .label = "the key in its own addOutput slot", .body = "this.addOutput(1000n, this.key, this.other, n);", .prop = null },
    .{ .label = "private setter fed a property at every site", .body = "this.setKey(this.backup);", .extra = SETTER, .prop = null },
};

const Verdict = struct { has_msg: bool, error_count: usize };

fn verdictFor(work: std.mem.Allocator, src: []const u8, file_name: []const u8, msg: []const u8) !Verdict {
    const parsed = compiler_api.parseSource(work, src, file_name);
    if (parsed.errors.len > 0) {
        for (parsed.errors) |e| std.debug.print("  unexpected parse error: {s}\n", .{e});
        return error.TestFixtureDidNotParse;
    }
    const result = try compiler_api.validateForFile(work, parsed.contract orelse return error.TestFixtureDidNotParse, file_name);
    var has = false;
    for (result.errors) |e| {
        if (std.mem.eql(u8, e.message, msg)) has = true;
    }
    if (!has and result.errors.len > 0) {
        for (result.errors) |e| std.debug.print("  other validation error: {s}\n", .{e.message});
    }
    return .{ .has_msg = has, .error_count = result.errors.len };
}

test "N-205: writes to a verifyRabinSig key property (TS surface shape matrix)" {
    var failed = false;
    for (cases) |c| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const w = arena.allocator();
        const src = try std.fmt.allocPrint(w,
            \\import {{ StatefulSmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig }} from 'runar-lang';
            \\class C extends StatefulSmartContract {{
            \\  key: RabinPubKey;
            \\  other: RabinPubKey;
            \\  count: bigint;
            \\  readonly backup: RabinPubKey;
            \\  constructor(key: RabinPubKey, other: RabinPubKey, count: bigint, backup: RabinPubKey) {{
            \\    super(key, other, count, backup); this.key = key; this.other = other; this.count = count; this.backup = backup;
            \\  }}
            \\  public settle(msg: ByteString, sig: RabinSig, padding: ByteString) {{
            \\    assert({s});
            \\  }}
            \\  public rotate(newKey: RabinPubKey, n: bigint) {{
            \\    {s}
            \\    assert(true);
            \\  }}
            \\{s}
            \\}}
        , .{ c.settle, c.body, c.extra });
        const v = try verdictFor(w, src, "C.runar.ts", try msgFor(w, c.prop orelse "key"));
        if (c.prop != null and !v.has_msg) {
            std.debug.print("  N-205 NOT refused: {s}\n", .{c.label});
            failed = true;
        } else if (c.prop == null and v.error_count != 0) {
            std.debug.print("  N-205 wrongly refused: {s}\n", .{c.label});
            failed = true;
        }
    }
    if (failed) return error.RabinKeyWriteProvenanceMismatch;
}

test "N-205: .runar.zig surface — literal write accepted, a parameter write refused" {
    const tmpl =
        \\const runar = @import("runar");
        \\
        \\pub const C = struct {{
        \\    pub const Contract = runar.StatefulSmartContract;
        \\
        \\    key: runar.RabinPubKey = 0,
        \\
        \\    pub fn init(key: runar.RabinPubKey) C {{
        \\        return .{{ .key = key }};
        \\    }}
        \\
        \\    pub fn settle(self: *const C, msg: runar.ByteString, sig: runar.RabinSig, padding: runar.ByteString) void {{
        \\        runar.assert(runar.verifyRabinSig(msg, sig, padding, self.key));
        \\    }}
        \\
        \\    pub fn rotate(self: *C, newKey: runar.RabinPubKey) void {{
        \\        self.key = {s};
        \\        runar.assert(true);
        \\    }}
        \\}};
        \\
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const w = arena.allocator();
    const msg = try msgFor(w, "key");

    const ok = try verdictFor(w, try std.fmt.allocPrint(w, tmpl, .{"1000003"}), "C.runar.zig", msg);
    try std.testing.expectEqual(@as(usize, 0), ok.error_count);

    const bad = try verdictFor(w, try std.fmt.allocPrint(w, tmpl, .{"newKey"}), "C.runar.zig", msg);
    try std.testing.expect(bad.has_msg);
}

test "N-205: .runar.sol bare-name write — literal accepted, a parameter refused" {
    const tmpl =
        \\pragma runar ^0.1.0;
        \\contract C is StatefulSmartContract {{
        \\    RabinPubKey key;
        \\    constructor(RabinPubKey _key) {{ key = _key; }}
        \\    function settle(bytes msg, RabinSig sig, bytes padding) public {{
        \\        require(verifyRabinSig(msg, sig, padding, this.key));
        \\    }}
        \\    function rotate(RabinPubKey newKey) public {{
        \\        key = {s};
        \\        require(true);
        \\    }}
        \\}}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const w = arena.allocator();
    const msg = try msgFor(w, "key");

    const ok = try verdictFor(w, try std.fmt.allocPrint(w, tmpl, .{"1000003"}), "C.runar.sol", msg);
    try std.testing.expectEqual(@as(usize, 0), ok.error_count);

    const bad = try verdictFor(w, try std.fmt.allocPrint(w, tmpl, .{"newKey"}), "C.runar.sol", msg);
    try std.testing.expect(bad.has_msg);
}
