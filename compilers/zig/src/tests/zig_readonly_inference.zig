//! Readonly *inference* coverage for the `.runar.zig` surface parser.
//!
//! The Zig surface decides mutability from three inputs, in priority order:
//!   1. `runar.Readonly(T)` on the field            -> readonly (explicit)
//!   2. a field default (`count: i64 = 0`)          -> mutable
//!   3. an assignment to the field in a method body -> mutable   <-- inference
//!
//! Rule 3 had no implementation and no fixture: every checked-in stateful
//! `.runar.zig` contract gives its mutable fields a default, so rule 2 always
//! fired first and rule 3 was never exercised. A stateful contract whose
//! mutable field carries no default was therefore inferred fully-readonly,
//! the compiler warned "StatefulSmartContract has no mutable properties",
//! and the emitted script silently dropped its state continuation -- while
//! Go/Rust/TS compiled the same source correctly.
//!
//! These tests pin rule 3 (and guard rules 1/2 against regression) against
//! sources produced by the real parser.

const std = @import("std");
const testing = std.testing;
const types = @import("../ir/types.zig");
const parse_zig = @import("../passes/parse_zig.zig");
const readonly_inference = @import("../frontend/readonly_inference.zig");

const ContractNode = types.ContractNode;

/// Parse a `.runar.zig` source and return the contract with the surface's
/// readonly rules fully applied.
///
/// `applyMutationInference` is additive and idempotent -- it only demotes a
/// `readonly` the parser set from the no-default rule -- so composing it here
/// yields exactly the flags the parser produces once it calls the module
/// itself. `explicit_readonly` mirrors the `runar.Readonly(T)` field names the
/// parser collects while parsing field types.
fn parseInferred(
    arena: std.mem.Allocator,
    source: []const u8,
    explicit_readonly: []const []const u8,
) !ContractNode {
    const r = parse_zig.parseZig(arena, source, "T.runar.zig");
    for (r.errors) |err| std.debug.print("PARSE ERROR: {s}\n", .{err});
    try testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    readonly_inference.applyMutationInference(
        arena,
        c.parent_class,
        c.properties,
        c.methods,
        explicit_readonly,
    );
    return c;
}

fn propByName(c: ContractNode, name: []const u8) types.PropertyNode {
    for (c.properties) |p| {
        if (std.mem.eql(u8, p.name, name)) return p;
    }
    std.debug.panic("no property named '{s}'", .{name});
}

test "un-initialised property assigned in a method body is mutable" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\const runar = @import("runar");
        \\
        \\pub const Mini = struct {
        \\    pub const Contract = runar.StatefulSmartContract;
        \\
        \\    a: i64,
        \\    b: runar.Readonly(i64),
        \\
        \\    pub fn init(a: i64, b: i64) Mini {
        \\        return .{ .a = a, .b = b };
        \\    }
        \\
        \\    pub fn bump(self: *Mini, amount: i64) void {
        \\        runar.assert(amount > 0);
        \\        self.a = self.a + amount;
        \\        self.addOutput(1000, self.a);
        \\    }
        \\};
    ;

    const c = try parseInferred(arena.allocator(), source, &.{"b"});
    // `a` has no default and no runar.Readonly -- the assignment in bump()
    // is the ONLY signal that it is state. This is the bug.
    try testing.expect(!propByName(c, "a").readonly);
    // `b` is explicitly runar.Readonly(i64) and is never assigned.
    try testing.expect(propByName(c, "b").readonly);
}

test "explicit runar.Readonly field stays readonly even when assigned" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // A `runar.Readonly(T)` field that a method nevertheless assigns must
    // stay readonly: the explicit annotation outranks inference (the
    // validator is what rejects the write). Demoting it here would let a
    // typo silently turn an immutable field into state.
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const Locked = struct {
        \\    pub const Contract = runar.StatefulSmartContract;
        \\
        \\    cap: runar.Readonly(i64),
        \\    tally: i64,
        \\
        \\    pub fn init(cap: i64, tally: i64) Locked {
        \\        return .{ .cap = cap, .tally = tally };
        \\    }
        \\
        \\    pub fn touch(self: *Locked, amount: i64) void {
        \\        runar.assert(amount > 0);
        \\        self.cap = self.cap + amount;
        \\        self.tally = self.tally + 1;
        \\        self.addOutput(1000, self.tally);
        \\    }
        \\};
    ;

    const c = try parseInferred(arena.allocator(), source, &.{"cap"});
    try testing.expect(propByName(c, "cap").readonly);
    try testing.expect(!propByName(c, "tally").readonly);
}

test "initialised and mutated property stays mutable (pre-existing branch)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // This is the shape every checked-in .runar.zig fixture uses; it worked
    // before the fix and must keep working after it.
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const Counter = struct {
        \\    pub const Contract = runar.StatefulSmartContract;
        \\
        \\    owner: runar.PubKey,
        \\    count: i64 = 0,
        \\
        \\    pub fn init(owner: runar.PubKey, count: i64) Counter {
        \\        return .{ .owner = owner, .count = count };
        \\    }
        \\
        \\    pub fn increment(self: *Counter, sig: runar.Sig) void {
        \\        runar.assert(runar.checkSig(sig, self.owner));
        \\        self.count += 1;
        \\        self.addOutput(1, self.count);
        \\    }
        \\};
    ;

    const c = try parseInferred(arena.allocator(), source, &.{});
    try testing.expect(propByName(c, "owner").readonly);
    try testing.expect(!propByName(c, "count").readonly);
}

test "compound assignment infers mutability" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // `+=` / `-=` lower to Statement.assign with a synthesised binary RHS.
    // Neither field carries a default, so inference is the only signal.
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const Compound = struct {
        \\    pub const Contract = runar.StatefulSmartContract;
        \\
        \\    up: i64,
        \\    down: i64,
        \\
        \\    pub fn init(up: i64, down: i64) Compound {
        \\        return .{ .up = up, .down = down };
        \\    }
        \\
        \\    pub fn step(self: *Compound, amount: i64) void {
        \\        runar.assert(amount > 0);
        \\        self.up += amount;
        \\        self.down -= amount;
        \\        self.addOutput(1000, self.up, self.down);
        \\    }
        \\};
    ;

    const c = try parseInferred(arena.allocator(), source, &.{});
    try testing.expect(!propByName(c, "up").readonly);
    try testing.expect(!propByName(c, "down").readonly);
}

test "un-mutated un-initialised property stays readonly" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // Inference must not promote everything to mutable: a field that is only
    // ever READ is a constructor-baked constant, not state.
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const Mixed = struct {
        \\    pub const Contract = runar.StatefulSmartContract;
        \\
        \\    limit: i64,
        \\    used: i64,
        \\
        \\    pub fn init(limit: i64, used: i64) Mixed {
        \\        return .{ .limit = limit, .used = used };
        \\    }
        \\
        \\    pub fn spend(self: *Mixed, amount: i64) void {
        \\        runar.assert(self.used + amount <= self.limit);
        \\        self.used = self.used + amount;
        \\        self.addOutput(1000, self.used);
        \\    }
        \\};
    ;

    const c = try parseInferred(arena.allocator(), source, &.{});
    // `limit` is read in the assert but never written.
    try testing.expect(propByName(c, "limit").readonly);
    try testing.expect(!propByName(c, "used").readonly);
}

test "mutation nested inside if / for bodies is found" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const source =
        \\const runar = @import("runar");
        \\
        \\pub const Nested = struct {
        \\    pub const Contract = runar.StatefulSmartContract;
        \\
        \\    inIf: i64,
        \\    inElse: i64,
        \\    inLoop: i64,
        \\    untouched: i64,
        \\
        \\    pub fn init(inIf: i64, inElse: i64, inLoop: i64, untouched: i64) Nested {
        \\        return .{ .inIf = inIf, .inElse = inElse, .inLoop = inLoop, .untouched = untouched };
        \\    }
        \\
        \\    pub fn run(self: *Nested, flag: i64) void {
        \\        if (flag > 0) {
        \\            self.inIf = self.inIf + 1;
        \\        } else {
        \\            self.inElse = self.inElse + 1;
        \\        }
        \\        var i: i64 = 0;
        \\        while (i < 3) : (i += 1) {
        \\            self.inLoop = self.inLoop + 1;
        \\        }
        \\        self.addOutput(1000, self.inIf, self.inElse, self.inLoop);
        \\    }
        \\};
    ;

    const c = try parseInferred(arena.allocator(), source, &.{});
    try testing.expect(!propByName(c, "inIf").readonly);
    try testing.expect(!propByName(c, "inElse").readonly);
    try testing.expect(!propByName(c, "inLoop").readonly);
    try testing.expect(propByName(c, "untouched").readonly);
}

test "F-393: a local that shadows a readonly property name must not flip it to mutable" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // `limit` is a property with no default and no explicit runar.Readonly
    // -- rule 3 (assignment) is the only thing that can make it mutable.
    // `bump` declares a LOCAL also named `limit` and reassigns THAT local
    // (`limit = limit + 1;`, target_is_property == false, per
    // `types.targetIsProperty` / `parse_zig.zig`'s `parseExpressionStatement`)
    // -- `self.limit` is never written anywhere. The property must stay
    // readonly: a bare-name collision with a local is not a property write
    // (see `validate.zig`'s `checkReadonlyWrites`, which keys off
    // `target_is_property` for exactly this reason, and the Go reference
    // `collectZigMutatedProperties`, which only records a target that type-
    // asserts to `PropertyAccessExpr`).
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const Shadow = struct {
        \\    pub const Contract = runar.StatefulSmartContract;
        \\
        \\    limit: i64,
        \\    count: i64 = 0,
        \\
        \\    pub fn init(limit: i64, count: i64) Shadow {
        \\        return .{ .limit = limit, .count = count };
        \\    }
        \\
        \\    pub fn bump(self: *Shadow, amount: i64) void {
        \\        var limit: i64 = amount;
        \\        limit = limit + 1;
        \\        runar.assert(limit > 0);
        \\        self.count += 1;
        \\        self.addOutput(1000, self.count);
        \\    }
        \\};
    ;

    const c = try parseInferred(arena.allocator(), source, &.{});
    // expectEqual (not expect) so a failure prints "expected true, found
    // false" instead of a bare boolean -- the zig test binary bundles 1290
    // tests in one process and dumps a stale error-return-trace alongside
    // any failure, so a self-describing message is the only reliable signal
    // of WHY this test failed.
    try testing.expectEqual(true, propByName(c, "limit").readonly);
    try testing.expectEqual(false, propByName(c, "count").readonly);
}

test "SmartContract fields stay readonly regardless of assignment" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // Stateless contracts have no state continuation; every field is readonly
    // and inference must not touch them.
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const P2PKH = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    pubKeyHash: runar.Addr,
        \\
        \\    pub fn init(pubKeyHash: runar.Addr) P2PKH {
        \\        return .{ .pubKeyHash = pubKeyHash };
        \\    }
        \\
        \\    pub fn unlock(self: *P2PKH, sig: runar.Sig, pubKey: runar.PubKey) void {
        \\        runar.assert(runar.hash160(pubKey) == self.pubKeyHash);
        \\        runar.assert(runar.checkSig(sig, pubKey));
        \\    }
        \\};
    ;

    const c = try parseInferred(arena.allocator(), source, &.{});
    try testing.expect(propByName(c, "pubKeyHash").readonly);
}
