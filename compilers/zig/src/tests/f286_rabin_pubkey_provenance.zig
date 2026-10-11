//! F-286 — verifyRabinSig's public key must come from the contract, not the
//! spender.
//!
//! `verifyRabinSig(msg, sig, padding, n)` checks `(sig² + padding) mod n ==
//! SHA256(msg) mod n`. A spender who chooses `n` forges any message (`n = 1`,
//! `sig = 0` passes real Spend). Rule (user decision R78, ported from the TS
//! reference `checkRabinPubKeyProvenance`): the 4th argument must be a contract
//! property or a literal, followed through local aliases and through private
//! helpers whose parameter is bound to such a value at every call site.
//!
//! Proves: this tier's validator refuses the spender-chosen modulus shapes
//! below and accepts the deployer-fixed ones, on the TS surface and on the
//! `.runar.zig` surface, with the one shared diagnostic. Does not prove: the
//! other six tiers (conformance/negatives N220–N228), or a hostile `--ir` JSON
//! naming a parameter as the modulus (`--ir` skips the frontend).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const MSG = "verifyRabinSig public key (4th argument) must be a contract property or a literal; " ++
    "a spender-supplied Rabin modulus lets anyone forge a signature";

const HELPER =
    \\  private check(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    \\    return verifyRabinSig(m, s, p, k);
    \\  }
;
const CHAIN =
    \\  private outer(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    \\    const kk = k;
    \\    return this.inner(m, s, p, kk);
    \\  }
    \\  private inner(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    \\    return verifyRabinSig(m, s, p, k);
    \\  }
;

const Case = struct { label: []const u8, params: []const u8, body: []const u8, extra: []const u8 = "", refused: bool };

const cases = [_]Case{
    // refused: the spender can choose the modulus
    .{ .label = "public method parameter", .params = ", n: RabinPubKey", .body = "assert(verifyRabinSig(msg, sig, padding, n));", .refused = true },
    .{ .label = "const alias of a parameter", .params = ", n: RabinPubKey", .body = "const k = n; assert(verifyRabinSig(msg, sig, padding, k));", .refused = true },
    .{ .label = "let reassigned from a parameter", .params = ", n: RabinPubKey", .body = "let k = this.pk; k = n; assert(verifyRabinSig(msg, sig, padding, k));", .refused = true },
    .{ .label = "helper bound to a parameter", .params = ", n: RabinPubKey", .body = "assert(this.check(msg, sig, padding, n));", .extra = HELPER, .refused = true },
    .{ .label = "helper bound to a property and a parameter", .params = ", n: RabinPubKey", .body = "assert(this.check(msg, sig, padding, this.pk)); assert(this.check(msg, sig, padding, n));", .extra = HELPER, .refused = true },
    .{ .label = "ternary", .params = ", n: RabinPubKey", .body = "assert(verifyRabinSig(msg, sig, padding, sig > 0n ? this.pk : n));", .refused = true },
    .{ .label = "arithmetic on a property", .params = "", .body = "assert(verifyRabinSig(msg, sig, padding, this.pk + 1n));", .refused = true },
    .{ .label = "parameter in a for nested in an if", .params = ", n: RabinPubKey", .body = "if (sig > 0n) { for (let i = 0n; i < 2n; i++) { assert(verifyRabinSig(msg, sig, padding, n)); } } assert(true);", .refused = true },
    // accepted: the modulus is fixed by the deployer
    .{ .label = "this.pk", .params = "", .body = "assert(verifyRabinSig(msg, sig, padding, this.pk));", .refused = false },
    .{ .label = "bigint literal", .params = "", .body = "assert(verifyRabinSig(msg, sig, padding, 1000003n));", .refused = false },
    .{ .label = "const alias of a property", .params = "", .body = "const k = this.pk; assert(verifyRabinSig(msg, sig, padding, k));", .refused = false },
    .{ .label = "let reassigned only from properties", .params = "", .body = "let k = this.pk; if (sig > 0n) { k = this.pk2; } assert(verifyRabinSig(msg, sig, padding, k));", .refused = false },
    .{ .label = "helper bound to a property at every site", .params = "", .body = "assert(this.check(msg, sig, padding, this.pk)); assert(this.check(msg, sig, padding, this.pk2));", .extra = HELPER, .refused = false },
    .{ .label = "two-level helper chain", .params = "", .body = "assert(this.outer(msg, sig, padding, this.pk));", .extra = CHAIN, .refused = false },
};

const Verdict = struct { has_msg: bool, error_count: usize };

fn verdictFor(work: std.mem.Allocator, src: []const u8, file_name: []const u8) !Verdict {
    const parsed = compiler_api.parseSource(work, src, file_name);
    if (parsed.errors.len > 0) {
        for (parsed.errors) |e| std.debug.print("  unexpected parse error: {s}\n", .{e});
        return error.TestFixtureDidNotParse;
    }
    const result = try compiler_api.validateForFile(work, parsed.contract orelse return error.TestFixtureDidNotParse, file_name);
    var has = false;
    for (result.errors) |e| {
        if (std.mem.eql(u8, e.message, MSG)) has = true;
    }
    if (!has and result.errors.len > 0) {
        for (result.errors) |e| std.debug.print("  other validation error: {s}\n", .{e.message});
    }
    return .{ .has_msg = has, .error_count = result.errors.len };
}

test "F-286: verifyRabinSig public key provenance (TS surface shape matrix)" {
    var failed = false;
    for (cases) |c| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const w = arena.allocator();
        const src = try std.fmt.allocPrint(w,
            \\import {{ SmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig }} from 'runar-lang';
            \\class C extends SmartContract {{
            \\  readonly pk: RabinPubKey;
            \\  readonly pk2: RabinPubKey;
            \\  constructor(pk: RabinPubKey, pk2: RabinPubKey) {{ super(pk, pk2); this.pk = pk; this.pk2 = pk2; }}
            \\  public settle(msg: ByteString, sig: RabinSig, padding: ByteString{s}) {{
            \\    {s}
            \\  }}
            \\{s}
            \\}}
        , .{ c.params, c.body, c.extra });
        const v = try verdictFor(w, src, "C.runar.ts");
        if (c.refused and !v.has_msg) {
            std.debug.print("  F-286 NOT refused: {s}\n", .{c.label});
            failed = true;
        } else if (!c.refused and v.error_count != 0) {
            std.debug.print("  F-286 wrongly refused: {s}\n", .{c.label});
            failed = true;
        }
    }
    if (failed) return error.RabinPubKeyProvenanceMismatch;
}

test "F-286: .runar.zig surface — self.pk accepted, a parameter refused" {
    const tmpl =
        \\const runar = @import("runar");
        \\
        \\pub const C = struct {{
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    pk: runar.RabinPubKey,
        \\
        \\    pub fn init(pk: runar.RabinPubKey) C {{
        \\        return .{{ .pk = pk }};
        \\    }}
        \\
        \\    pub fn settle(self: *const C, msg: runar.ByteString, sig: runar.RabinSig, padding: runar.ByteString{s}) void {{
        \\        runar.assert(runar.verifyRabinSig(msg, sig, padding, {s}));
        \\    }}
        \\}};
        \\
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const w = arena.allocator();

    const ok = try verdictFor(w, try std.fmt.allocPrint(w, tmpl, .{ "", "self.pk" }), "C.runar.zig");
    try std.testing.expectEqual(@as(usize, 0), ok.error_count);

    const bad = try verdictFor(w, try std.fmt.allocPrint(w, tmpl, .{ ", n: runar.RabinPubKey", "n" }), "C.runar.zig");
    try std.testing.expect(bad.has_msg);
}
