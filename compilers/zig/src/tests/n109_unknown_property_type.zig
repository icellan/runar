//! N-109 — an unrecognised type name in a PROPERTY declaration.
//!
//! All seven tiers refuse `count: Foobarium`, so nothing unsafe compiles. What
//! diverged was WHICH PASS refused and what the author was told:
//!
//!   ts     Unsupported type 'Foobarium' in property declaration. ...
//!   go     Unknown.runar.ts:4:2: unsupported type 'Foobarium' in property ...
//!   rust   Unsupported type 'Foobarium' in property ...
//!   python Unknown.runar.ts:4:2: unsupported type 'Foobarium' in property ...
//!   ruby   Unknown.runar.ts:4:2: unsupported type 'Foobarium' in property ...
//!   java   Unknown.runar.ts:4:2: Unsupported type 'Foobarium' ...
//!   zig    error: StackLowerFailed          <-- this tier
//!
//! Six tiers name the type and the line at VALIDATE. Zig fell over three
//! passes later in stack lowering with `UnsupportedOperation` — no type name,
//! no source location, nothing an author can act on, and a pass whose
//! diagnostics are written for compiler developers rather than contract
//! authors. `runar.lang`-style frontend-only entry points (`--parse-only`,
//! `stop_after = .validate`) therefore green-lit the contract entirely.
//!
//! Root cause: `validateProperties` already had the arm, but it was guarded
//! with `and prop.type_info != .unknown` — and `.unknown` is exactly what
//! `typeNodeToRunarType` returns for a `custom_type`, i.e. for every
//! unrecognised type name. The arm could therefore never fire on the case it
//! was written for. `PropertyNode` also carried neither the spelled type name
//! nor a source location, so even once the arm fired it had nothing to say.
//!
//! Scope note — the neighbouring positions were measured and are NOT this
//! finding. An unknown type on a method parameter, a constructor parameter or
//! a private helper's return type is ACCEPTED by every tier (Zig and Go emit
//! byte-identical hex for all three); an unknown type on a local declaration
//! is rejected at TYPECHECK by both. Only the property slot had Zig refusing
//! in a different pass from its peers.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const validate = @import("../passes/validate.zig");
const compiler_api = @import("../compiler_api.zig");

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/// The probe. `Foobarium` is not a Rúnar type on any surface.
/// Line 4 / column 3 (1-based) is the `count` field.
const UNKNOWN_PROP =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\
    \\export class UnknownProp extends StatefulSmartContract {
    \\  count: Foobarium;
    \\
    \\  constructor(count: Foobarium) { super(count); this.count = count; }
    \\
    \\  public go(v: bigint) {
    \\    assert(v >= 0n);
    \\  }
    \\}
;

/// The control: identical but for the type. Must keep compiling.
const CONTROL =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\
    \\export class UnknownProp extends StatefulSmartContract {
    \\  count: bigint;
    \\
    \\  constructor(count: bigint) { super(count); this.count = count; }
    \\
    \\  public go(v: bigint) {
    \\    assert(v >= 0n);
    \\  }
    \\}
;

/// Over-rejection guard. Every legitimate property type in one stateless
/// contract — if the new arm is too broad, this stops compiling.
const ALL_LEGAL_TYPES =
    \\import { SmartContract, assert, ByteString, PubKey, Sig, Sha256, Ripemd160, Addr, SigHashPreimage, RabinSig, RabinPubKey, Point, P256Point, P384Point, FixedArray } from 'runar-lang';
    \\
    \\export class AllTypes extends SmartContract {
    \\  readonly a: bigint;
    \\  readonly b: boolean;
    \\  readonly c: ByteString;
    \\  readonly d: PubKey;
    \\  readonly e: Sig;
    \\  readonly f: Sha256;
    \\  readonly g: Ripemd160;
    \\  readonly h: Addr;
    \\  readonly i: SigHashPreimage;
    \\  readonly j: RabinSig;
    \\  readonly k: RabinPubKey;
    \\  readonly l: Point;
    \\  readonly m: P256Point;
    \\  readonly n: P384Point;
    \\  readonly o: FixedArray<bigint, 3> = [1n, 2n, 3n];
    \\
    \\  constructor(a: bigint, b: boolean, c: ByteString, d: PubKey, e: Sig, f: Sha256, g: Ripemd160, h: Addr, i: SigHashPreimage, j: RabinSig, k: RabinPubKey, l: Point, m: P256Point, n: P384Point) {
    \\    super(a, b, c, d, e, f, g, h, i, j, k, l, m, n);
    \\    this.a = a; this.b = b; this.c = c; this.d = d; this.e = e;
    \\    this.f = f; this.g = g; this.h = h; this.i = i; this.j = j;
    \\    this.k = k; this.l = l; this.m = m; this.n = n;
    \\  }
    \\
    \\  public go(x: bigint) {
    \\    assert(x >= this.a);
    \\    assert(this.b);
    \\    assert(this.o[0] >= 0n);
    \\  }
    \\}
;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse + VALIDATE only. Returns the validation errors so a test can assert
/// on the prose, not merely on "something failed". A parse failure is raised
/// rather than silently counted as a rejection — a fixture refused at the
/// wrong pass would make this file vacuous, which is the exact shape N-109 is.
fn validateErrors(
    w: std.mem.Allocator,
    src: []const u8,
    file_name: []const u8,
) ![]const @import("../ir/types.zig").CompilerDiagnostic {
    const parsed = parse_ts.parseTs(w, src, file_name);
    if (parsed.errors.len > 0) {
        for (parsed.errors) |e| std.debug.print("  unexpected parse error: {s}\n", .{e});
        return error.TestFixtureDidNotParse;
    }
    const contract = parsed.contract orelse return error.TestFixtureDidNotParse;
    const result = try validate.validate(w, contract);
    return result.errors;
}

// ---------------------------------------------------------------------------
// The defect
// ---------------------------------------------------------------------------

test "N-109: an unknown property type is refused at VALIDATE, naming the type" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const w = arena.allocator();

    const errors = try validateErrors(w, UNKNOWN_PROP, "Unknown.runar.ts");

    var found = false;
    for (errors) |d| {
        if (std.mem.indexOf(u8, d.message, "unsupported type 'Foobarium' in property declaration") != null) {
            found = true;
        }
    }
    if (!found) {
        std.debug.print("validate produced {d} error(s):\n", .{errors.len});
        for (errors) |d| std.debug.print("  {s}\n", .{d.message});
    }
    try std.testing.expect(found);
}

test "N-109: the diagnostic carries the property's source location" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const w = arena.allocator();

    const errors = try validateErrors(w, UNKNOWN_PROP, "Unknown.runar.ts");

    var checked = false;
    for (errors) |d| {
        if (std.mem.indexOf(u8, d.message, "unsupported type 'Foobarium'") == null) continue;
        checked = true;
        // Message tail matches the Go / Python / Ruby peers byte for byte.
        try std.testing.expect(std.mem.indexOf(u8, d.message, "at Unknown.runar.ts:4") != null);
        // ... and the structured location is populated so the CLI can print
        // the `file:line:col:` prefix the same peers print.
        const loc = d.location orelse return error.DiagnosticHasNoLocation;
        try std.testing.expectEqualStrings("Unknown.runar.ts", loc.file);
        try std.testing.expectEqual(@as(u32, 4), loc.line);
        // AST-wide convention is 1-based; `count` starts at column 3.
        try std.testing.expectEqual(@as(u32, 3), loc.column);
    }
    try std.testing.expect(checked);
}

test "N-109: the pipeline fails at ValidationFailed, not StackLowerFailed" {
    const a = std.testing.allocator;
    try std.testing.expectError(
        error.ValidationFailed,
        compiler_api.compileSource(a, UNKNOWN_PROP, "Unknown.runar.ts"),
    );
}

// ---------------------------------------------------------------------------
// Controls — nothing legitimate may start being refused
// ---------------------------------------------------------------------------

test "N-109 control: the bigint twin still compiles" {
    const a = std.testing.allocator;
    const result = try compiler_api.compileSource(a, CONTROL, "Control.runar.ts");
    defer a.free(result.script_hex);
    defer if (result.artifact_json) |j| a.free(j);
    try std.testing.expect(result.script_hex.len > 0);
}

test "N-109 control: every legitimate property type still validates and compiles" {
    const a = std.testing.allocator;

    {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const errors = try validateErrors(arena.allocator(), ALL_LEGAL_TYPES, "AllTypes.runar.ts");
        if (errors.len > 0) {
            for (errors) |d| std.debug.print("  unexpected validation error: {s}\n", .{d.message});
        }
        try std.testing.expectEqual(@as(usize, 0), errors.len);
    }

    const result = try compiler_api.compileSource(a, ALL_LEGAL_TYPES, "AllTypes.runar.ts");
    defer a.free(result.script_hex);
    defer if (result.artifact_json) |j| a.free(j);
    try std.testing.expect(result.script_hex.len > 0);
}
