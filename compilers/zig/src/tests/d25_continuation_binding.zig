//! D25 — the contract-level continuation binding (passes/continuation_binding.zig):
//! classification, the SINGLE default, the hidden spent-outpoint field, the
//! diagnostics, and the `--ir` check. Port of
//! packages/runar-compiler/src/__tests__/d25-continuation-binding.test.ts.
//!
//! Proves: the Zig frontend classifies, rewrites the sighash, injects and
//! writes the hidden field, and emits the shared diagnostics as the TS
//! reference does; the IR loader refuses an unbound continuation.
//! Does NOT prove: script execution (the executed twin-input attacks are in
//! packages/runar-sdk/src/__tests__/d25-twin-input.test.ts; this tier has no
//! ScriptVM) or cross-tier byte parity (the conformance goldens gate that).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const json = @import("../ir/json.zig");
const required_fields = @import("../ir/required_fields.zig");
const types = @import("../ir/types.zig");

const FIELD = "_spentOutpointHash";

const STATEFUL =
    "import { StatefulSmartContract, assert, checkSig, extractAmount, extractOutputHash, hash256 } from 'runar-lang';\n" ++
    "import type { PubKey, Sig, Sha256 } from 'runar-lang';\n";

fn counter(comptime inc: []const u8, comptime dec: []const u8) []const u8 {
    return STATEFUL ++
        "class Counter extends StatefulSmartContract {\n" ++
        "  count: bigint;\n" ++
        "  constructor(count: bigint) { super(count); this.count = count; }\n" ++
        "  " ++ inc ++ "\n" ++
        "  public increment() { this.count++; }\n" ++
        "  " ++ dec ++ "\n" ++
        "  public decrement() { assert(this.count > 0n); this.count--; }\n" ++
        "}\n";
}

const MIXED = STATEFUL ++
    "class MixedPot extends StatefulSmartContract {\n" ++
    "  count: bigint;\n" ++
    "  constructor(count: bigint) { super(count); this.count = count; }\n" ++
    "  public increment() { this.count++; }\n" ++
    "  public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }\n" ++
    "}\n";

fn pot(comptime body: []const u8) []const u8 {
    return STATEFUL ++
        "class Pot extends StatefulSmartContract {\n" ++
        "  count: bigint;\n" ++
        "  readonly owner: PubKey;\n" ++
        "  constructor(count: bigint, owner: PubKey) { super(count, owner); this.count = count; this.owner = owner; }\n" ++
        "  public bump(sig: Sig) { " ++ body ++ " }\n" ++
        "}\n";
}

const Compiled = struct {
    artifact: std.json.Value,
    warnings: []const []const u8,
};

/// Compile (fold OFF) into the arena `a`; fail the test on a refusal.
fn ok(a: std.mem.Allocator, src: []const u8, file: []const u8) !Compiled {
    const r = try compiler_api.compileSourceWithOptions(a, src, file, true);
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, a, r.artifact_json.?, .{});
    return .{ .artifact = parsed, .warnings = r.warnings };
}

/// Every error line of a refused compile, or null on success.
fn errorsOf(a: std.mem.Allocator, src: []const u8, file: []const u8) !?[]const u8 {
    var diag: compiler_api.Diagnostics = .{};
    _ = compiler_api.runPipeline(a, src, file, .{ .disable_constant_folding = true }, &diag) catch {
        return try std.mem.join(a, "\n", diag.errors.items);
    };
    return null;
}

fn method(art: std.json.Value, name: []const u8) std.json.ObjectMap {
    for (art.object.get("abi").?.object.get("methods").?.array.items) |m| {
        if (std.mem.eql(u8, m.object.get("name").?.string, name)) return m.object;
    }
    unreachable;
}

fn abiMode(art: std.json.Value, name: []const u8) ?i64 {
    const v = method(art, name).get("sigHashType") orelse return null;
    return v.integer;
}

fn expectStateFields(art: std.json.Value, want: []const []const u8) !void {
    const sf = art.object.get("stateFields").?.array.items;
    try std.testing.expectEqual(want.len, sf.len);
    for (sf, want) |f, w| try std.testing.expectEqualStrings(w, f.object.get("name").?.string);
}

fn paramNames(a: std.mem.Allocator, m: std.json.ObjectMap) ![]const u8 {
    var names: std.ArrayListUnmanaged([]const u8) = .empty;
    for (m.get("params").?.array.items) |p| try names.append(a, p.object.get("name").?.string);
    return std.mem.join(a, ",", names.items);
}

fn countWarnings(ws: []const []const u8, needle: []const u8) usize {
    var n: usize = 0;
    for (ws) |w| {
        if (std.mem.indexOf(u8, w, needle) != null) n += 1;
    }
    return n;
}

// ---------------------------------------------------------------------------
// class 1
// ---------------------------------------------------------------------------

test "D25 class 1: defaults every continuation method to SINGLE|FORKID and drops the change params" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try ok(a, counter("", ""), "Counter.runar.ts");
    try std.testing.expectEqual(@as(?i64, 0x43), abiMode(r.artifact, "increment"));
    try std.testing.expectEqual(@as(?i64, 0x43), abiMode(r.artifact, "decrement"));
    try expectStateFields(r.artifact, &.{"count"});
    try std.testing.expectEqualStrings("_newAmount,txPreimage", try paramNames(a, method(r.artifact, "increment")));
}

test "D25 class 1: maps ALL|ANYONECANPAY|FORKID to SINGLE|ANYONECANPAY|FORKID" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const d = "/** @sighash ALL|ANYONECANPAY|FORKID */";
    const r = try ok(arena.allocator(), counter(d, d), "Counter.runar.ts");
    try std.testing.expectEqual(@as(?i64, 0xc3), abiMode(r.artifact, "increment"));
}

test "D25 class 1: keeps an explicit SINGLE|ANYONECANPAY|FORKID" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = try ok(arena.allocator(), counter("/** @sighash SINGLE|ANYONECANPAY|FORKID */", ""), "Counter.runar.ts");
    try std.testing.expectEqual(@as(?i64, 0xc3), abiMode(r.artifact, "increment"));
}

test "D25 class 1: refuses an explicit ALL|FORKID sibling (it would reopen the twin)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const errs = (try errorsOf(arena.allocator(), counter("", "/** @sighash ALL|FORKID */"), "Counter.runar.ts")) orelse return error.TestUnexpectedlyAccepted;
    try std.testing.expect(std.mem.indexOf(u8, errs, "method 'decrement': @sighash ALL|FORKID") != null);
}

test "D25 class 1: refuses an explicit ALL|FORKID sibling on a native surface (.runar.py)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src =
        \\from runar import StatefulSmartContract, Bigint, public, assert_
        \\
        \\class Counter(StatefulSmartContract):
        \\    count: Bigint
        \\
        \\    def __init__(self, count: Bigint):
        \\        super().__init__(count)
        \\        self.count = count
        \\
        \\    @public
        \\    def increment(self):
        \\        self.count += 1
        \\
        \\    @public(sighash="ALL|FORKID")
        \\    def decrement(self):
        \\        assert_(self.count > 0)
        \\        self.count -= 1
        \\
    ;
    const errs = (try errorsOf(arena.allocator(), src, "Counter.runar.py")) orelse return error.TestUnexpectedlyAccepted;
    try std.testing.expect(std.mem.indexOf(u8, errs, "method 'decrement': @sighash ALL|FORKID") != null);
}

test "D25 class 1: a terminal method keeps ALL (it makes no continuation)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src = STATEFUL ++
        "class Box extends StatefulSmartContract {\n" ++
        "  count: bigint;\n" ++
        "  readonly owner: PubKey;\n" ++
        "  constructor(count: bigint, owner: PubKey) { super(count, owner); this.count = count; this.owner = owner; }\n" ++
        "  public bump() { this.count++; }\n" ++
        "  public close(sig: Sig) { assert(checkSig(sig, this.owner)); }\n" ++
        "}\n";
    const r = try ok(arena.allocator(), src, "Box.runar.ts");
    try std.testing.expectEqual(@as(?i64, 0x43), abiMode(r.artifact, "bump"));
    try std.testing.expectEqual(@as(?i64, null), abiMode(r.artifact, "close"));
}

// ---------------------------------------------------------------------------
// class 2
// ---------------------------------------------------------------------------

test "D25 class 2: appends a zero-initialised Sha256 field last, outside the constructor ABI" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try ok(a, MIXED, "MixedPot.runar.ts");
    try expectStateFields(r.artifact, &.{ "count", FIELD });
    const ctor = r.artifact.object.get("abi").?.object.get("constructor").?.object;
    try std.testing.expectEqualStrings("count", try paramNames(a, ctor));
    const sf = r.artifact.object.get("stateFields").?.array.items[1].object;
    try std.testing.expectEqualStrings("Sha256", sf.get("type").?.string);
    try std.testing.expectEqualStrings("00" ** 32, sf.get("initialValue").?.string);
    // Every method keeps ALL: no blending of SINGLE and the field.
    try std.testing.expectEqual(@as(?i64, null), abiMode(r.artifact, "increment"));
    try std.testing.expectEqual(@as(?i64, null), abiMode(r.artifact, "bump"));
}

fn anfOf(a: std.mem.Allocator, src: []const u8, file: []const u8) !types.ANFProgram {
    var diag: compiler_api.Diagnostics = .{};
    const p = try compiler_api.runPipeline(a, src, file, .{ .disable_constant_folding = true, .stop_after = .anf }, &diag);
    return p.program.?;
}

fn walkUpdates(bs: []const types.ANFBinding, name: []const u8) usize {
    var n: usize = 0;
    for (bs) |b| switch (b.value) {
        .update_prop => |u| {
            if (std.mem.eql(u8, u.name, name)) n += 1;
        },
        .@"if" => |v| n += walkUpdates(v.then, name) + walkUpdates(v.@"else", name),
        .loop => |v| n += walkUpdates(v.body, name),
        else => {},
    };
    return n;
}

fn addOutputs(bs: []const types.ANFBinding, out: *std.ArrayListUnmanaged(types.ANFAddOutput), a: std.mem.Allocator) !void {
    for (bs) |b| switch (b.value) {
        .add_output => |ao| try out.append(a, ao),
        .@"if" => |v| {
            try addOutputs(v.then, out, a);
            try addOutputs(v.@"else", out, a);
        },
        .loop => |v| try addOutputs(v.body, out, a),
        else => {},
    };
}

test "D25 class 2: writes sha256(extractOutpoint) in the auto-continuation and appends it to addOutput" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p = try anfOf(a, MIXED, "MixedPot.runar.ts");
    const last = p.properties[p.properties.len - 1];
    try std.testing.expectEqualStrings(FIELD, last.name);
    try std.testing.expectEqualStrings("Sha256", last.type_name);
    try std.testing.expectEqualStrings("00" ** 32, last.initial_value.?.string);
    for (p.methods) |m| {
        if (std.mem.eql(u8, m.name, "increment")) try std.testing.expectEqual(@as(usize, 1), walkUpdates(m.body, FIELD));
        if (std.mem.eql(u8, m.name, "bump")) {
            var outs: std.ArrayListUnmanaged(types.ANFAddOutput) = .empty;
            try addOutputs(m.body, &outs, a);
            try std.testing.expectEqual(@as(usize, 1), outs.items.len);
            try std.testing.expectEqual(@as(usize, 2), outs.items[0].state_values.len);
        }
    }
}

test "D25 class 2: a mutate-only contract that reads extractOutputHash cannot run under SINGLE, so it is bound" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src = STATEFUL ++
        "class Peek extends StatefulSmartContract {\n" ++
        "  count: bigint;\n" ++
        "  constructor(count: bigint) { super(count); this.count = count; }\n" ++
        "  public bump(h: Sha256) { assert(extractOutputHash(this.txPreimage) !== h); this.count++; }\n" ++
        "}\n";
    const r = try ok(arena.allocator(), src, "Peek.runar.ts");
    try std.testing.expectEqual(@as(?i64, null), abiMode(r.artifact, "bump"));
    try expectStateFields(r.artifact, &.{ "count", FIELD });
}

test "D25 class 2: the field name is reserved" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src = STATEFUL ++
        "class X extends StatefulSmartContract {\n" ++
        "  _spentOutpointHash: bigint;\n" ++
        "  constructor(_spentOutpointHash: bigint) { super(_spentOutpointHash); this._spentOutpointHash = _spentOutpointHash; }\n" ++
        "  public bump() { this._spentOutpointHash++; }\n" ++
        "}\n";
    const errs = (try errorsOf(arena.allocator(), src, "X.runar.ts")) orelse return error.TestUnexpectedlyAccepted;
    try std.testing.expect(std.mem.indexOf(u8, errs, "'_spentOutpointHash' is reserved") != null);
}

// ---------------------------------------------------------------------------
// class 3
// ---------------------------------------------------------------------------

test "D25 class 3: warns on an unsigned addOutput(extractAmount(...)) re-creation (D12 C1)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = try ok(arena.allocator(), pot("this.addOutput(extractAmount(this.txPreimage), this.count + 1n);"), "Pot.runar.ts");
    try std.testing.expectEqual(@as(usize, 1), countWarnings(r.warnings, "twin-input aliasing"));
    try expectStateFields(r.artifact, &.{"count"});
    try std.testing.expectEqual(@as(?i64, null), abiMode(r.artifact, "bump"));
}

test "D25 class 3: a local initialised from extractAmount is followed" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = try ok(arena.allocator(), pot("const v: bigint = extractAmount(this.txPreimage); this.addOutput(v, this.count + 1n);"), "Pot.runar.ts");
    try std.testing.expectEqual(@as(usize, 1), countWarnings(r.warnings, "twin-input aliasing"));
}

test "D25 class 3: does not warn when the method checks a signature" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = try ok(arena.allocator(), pot("assert(checkSig(sig, this.owner)); this.addOutput(extractAmount(this.txPreimage), this.count + 1n);"), "Pot.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), countWarnings(r.warnings, "twin-input aliasing"));
}

// ---------------------------------------------------------------------------
// --ir check
// ---------------------------------------------------------------------------

fn irJson(a: std.mem.Allocator, src: []const u8, file: []const u8) !std.json.Value {
    const p = try anfOf(a, src, file);
    const text = try json.serializeCanonicalJSON(a, p);
    return std.json.parseFromSliceLeaky(std.json.Value, a, text, .{});
}

fn loads(a: std.mem.Allocator, v: std.json.Value) !void {
    const text = try std.json.Stringify.valueAlloc(a, v, .{});
    _ = try json.parseANFProgram(a, text);
}

fn refusedWith(a: std.mem.Allocator, v: std.json.Value, needle: []const u8) !void {
    const text = try std.json.Stringify.valueAlloc(a, v, .{});
    if (json.parseANFProgram(a, text)) |_| return error.TestUnexpectedlyAccepted else |_| {}
    const msg = required_fields.lastDiagnostic() orelse "<none>";
    if (std.mem.indexOf(u8, msg, needle) == null) {
        std.debug.print("unexpected diagnostic: {s}\n", .{msg});
        return error.TestUnexpectedDiagnostic;
    }
}

fn irMethod(v: std.json.Value, name: []const u8) *std.json.ObjectMap {
    for (v.object.get("methods").?.array.items) |*m| {
        if (std.mem.eql(u8, m.object.get("name").?.string, name)) return &m.object;
    }
    unreachable;
}

test "D25 --ir: accepts the frontend IR of every class" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try loads(a, try irJson(a, counter("", ""), "Counter.runar.ts"));
    try loads(a, try irJson(a, MIXED, "MixedPot.runar.ts"));
}

test "D25 --ir: refuses a mutate-only program whose continuation commits under ALL" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p = try irJson(a, counter("", ""), "Counter.runar.ts");
    // The pre-D25 ALL label: the scaffold check or this rule refuses it.
    _ = irMethod(p, "decrement").orderedRemove("sigHashType");
    try refusedWith(a, p, "IR validation");
}

fn jstr(v: std.json.Value, key: []const u8) ?[]const u8 {
    if (v != .object) return null;
    const x = v.object.get(key) orelse return null;
    return if (x == .string) x.string else null;
}

fn findBinding(bs: []std.json.Value, name: []const u8) ?std.json.Value {
    for (bs) |b| {
        if (std.mem.eql(u8, jstr(b, "name").?, name)) return b;
    }
    return null;
}

test "D25 --ir: refuses a mixed program without the binding field" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var p = try irJson(a, MIXED, "MixedPot.runar.ts");
    // The pre-D25 IR: no field, no write, no extra add_output value, no hash chain.
    const props = &p.object.getPtr("properties").?.array;
    _ = props.pop();
    for (p.object.get("methods").?.array.items) |*m| {
        const body = &m.object.getPtr("body").?.array;
        var drop: std.StringHashMapUnmanaged(void) = .empty;
        var hashes: std.ArrayListUnmanaged([]const u8) = .empty;
        for (body.items) |*b| {
            const v = b.object.getPtr("value").?;
            const kind = jstr(v.*, "kind").?;
            if (std.mem.eql(u8, kind, "update_prop") and std.mem.eql(u8, jstr(v.*, "name").?, FIELD)) {
                try drop.put(a, jstr(b.*, "name").?, {});
                try hashes.append(a, jstr(v.*, "value").?);
            }
            if (std.mem.eql(u8, kind, "add_output")) {
                const sv = &v.object.getPtr("stateValues").?.array;
                try hashes.append(a, sv.pop().?.string);
            }
        }
        for (hashes.items) |h| {
            try drop.put(a, h, {});
            const sha = findBinding(body.items, h).?.object.get("value").?;
            const eo_name = sha.object.get("args").?.array.items[0].string;
            try drop.put(a, eo_name, {});
            const eo = findBinding(body.items, eo_name).?.object.get("value").?;
            try drop.put(a, eo.object.get("args").?.array.items[0].string, {});
        }
        var kept: std.ArrayListUnmanaged(std.json.Value) = .empty;
        for (body.items) |b| {
            if (!drop.contains(jstr(b, "name").?)) try kept.append(a, b);
        }
        body.items = kept.items;
    }
    try refusedWith(a, p, "not bound to its input");
}

test "D25 --ir: refuses an add_output whose last state value is not the spent outpoint hash" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p = try irJson(a, MIXED, "MixedPot.runar.ts");
    for (irMethod(p, "bump").get("body").?.array.items) |*b| {
        const v = b.object.getPtr("value").?;
        if (std.mem.eql(u8, jstr(v.*, "kind").?, "add_output")) {
            const sv = v.object.get("stateValues").?.array.items;
            sv[1] = sv[0];
        }
    }
    try refusedWith(a, p, "every add_output must carry");
}
