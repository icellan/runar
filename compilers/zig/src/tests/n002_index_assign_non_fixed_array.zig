//! N-002 (CL-BUG-214, the cross-tier half of F-013): an index assignment is
//! only a write when its root is a FixedArray contract property.
//!
//! `expand_fixed_arrays` rewrites `this.arr[i] = v` only when `arr` is a
//! FixedArray property. Every other index target (a ByteString property, a
//! local, a parameter, a member-chained root) survived to ANF lowering, which
//! lowered it as a READ and dropped the value: a deployable script, no
//! diagnostic, state that never changes. Pre-fix, F-013's Blob.runar.ts
//! compiled here to the same `61ab7676aa517f…` script as TS/Go/Rust, which
//! @bsv/sdk Spend.validate showed accepting a continuation with the UNCHANGED
//! blob (remediation-logs/N-002/exec-proof*.txt).
//!
//! What this proves: the Zig tier refuses every non-FixedArray index-write
//! shape below with F-013's shared diagnostic and a location, on the TS surface
//! and on the Zig surface, and the whole compile fails; FixedArray index writes
//! (literal, runtime, compound, ++, nested literal) still compile.
//! What it does NOT prove: the other tiers (their own suites and
//! conformance/negatives/N81-N94 cover that), or byte-identity of the
//! FixedArray goldens (the conformance golden + multi-format runs do).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const NEEDLE = "index assignment is only supported on FixedArray contract properties; " ++
    "the target here is not a FixedArray property";

fn blob(comptime body: []const u8) []const u8 {
    return "import { StatefulSmartContract, ByteString, assert } from 'runar-lang';\n\n" ++
        "class Blob extends StatefulSmartContract {\n  blob: ByteString;\n\n" ++
        "  constructor(blob: ByteString) {\n    super(blob);\n    this.blob = blob;\n  }\n\n" ++
        "  public poke(i: bigint) {\n    " ++ body ++ "\n    assert(true);\n  }\n}\n";
}

const TS_LOCAL =
    \\import { SmartContract, ByteString, assert } from 'runar-lang';
    \\
    \\class Loc extends SmartContract {
    \\  readonly h: ByteString;
    \\
    \\  constructor(h: ByteString) {
    \\    super(h);
    \\    this.h = h;
    \\  }
    \\
    \\  public unlock(b: ByteString) {
    \\    let c: ByteString = b;
    \\    c[0n] = 7n;
    \\    assert(c == this.h);
    \\  }
    \\}
;

const TS_PARAM =
    \\import { SmartContract, ByteString, assert } from 'runar-lang';
    \\
    \\class Par extends SmartContract {
    \\  readonly h: ByteString;
    \\
    \\  constructor(h: ByteString) {
    \\    super(h);
    \\    this.h = h;
    \\  }
    \\
    \\  public unlock(b: ByteString) {
    \\    b[0n] = 7n;
    \\    assert(b == this.h);
    \\  }
    \\}
;

const ZIG_PROP =
    \\const runar = @import("runar");
    \\
    \\pub const Blob = struct {
    \\    pub const Contract = runar.StatefulSmartContract;
    \\
    \\    blob: runar.ByteString = "",
    \\
    \\    pub fn init(blob: runar.ByteString) Blob {
    \\        return .{ .blob = blob };
    \\    }
    \\
    \\    pub fn poke(self: *Blob) void {
    \\        self.blob[0] = 7;
    \\        runar.assert(true);
    \\    }
    \\};
;

const ZIG_LOCAL_PARAM =
    \\const runar = @import("runar");
    \\
    \\pub const Loc = struct {
    \\    pub const Contract = runar.SmartContract;
    \\
    \\    h: runar.ByteString,
    \\
    \\    pub fn init(h: runar.ByteString) Loc {
    \\        return .{ .h = h };
    \\    }
    \\
    \\    pub fn unlock(self: *const Loc, b: runar.ByteString) void {
    \\        var c = b;
    \\        c[0] = 7;
    \\        b[1] = 7;
    \\        runar.assert(runar.bytesEq(c, self.h));
    \\    }
    \\};
;

/// Parse + validate `src`, returning how many N-002 diagnostics it produced
/// (each must carry a location). A parse failure is an error, never a
/// "rejection": a fixture that stops parsing would make this file vacuous.
fn needleCount(src: []const u8, file: []const u8) !usize {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const w = arena.allocator();
    const parsed = compiler_api.parseSource(w, src, file);
    if (parsed.errors.len > 0) {
        for (parsed.errors) |e| std.debug.print("  unexpected parse error in {s}: {s}\n", .{ file, e });
        return error.TestFixtureDidNotParse;
    }
    const contract = parsed.contract orelse return error.TestFixtureDidNotParse;
    const result = try compiler_api.validateForFile(w, contract, file);
    var n: usize = 0;
    for (result.errors) |d| {
        if (std.mem.eql(u8, d.message, NEEDLE)) {
            n += 1;
            const loc = d.location orelse return error.DiagnosticHasNoLocation;
            if (loc.line == 0) return error.DiagnosticHasNoLocation;
        }
    }
    return n;
}

fn expectRefused(src: []const u8, file: []const u8, want: usize) !void {
    const got = try needleCount(src, file);
    if (got != want) {
        std.debug.print("  {s}: expected {d} N-002 diagnostic(s), got {d}\n", .{ file, want, got });
        return error.TestExpectedEqual;
    }
    try std.testing.expectError(error.ValidationFailed, compiler_api.compileSource(std.testing.allocator, src, file));
}

test "N-002: ByteString property, literal index" {
    try expectRefused(blob("this.blob[0n] = 7n;"), "Blob.runar.ts", 1);
}
test "N-002: ByteString property, runtime index" {
    try expectRefused(blob("this.blob[i] = 7n;"), "Blob.runar.ts", 1);
}
test "N-002: ByteString property, compound ops" {
    try expectRefused(blob("this.blob[0n] += 7n;"), "Blob.runar.ts", 1);
    try expectRefused(blob("this.blob[0n] -= 7n;"), "Blob.runar.ts", 1);
    try expectRefused(blob("this.blob[0n] *= 7n;"), "Blob.runar.ts", 1);
    try expectRefused(blob("this.blob[0n] /= 7n;"), "Blob.runar.ts", 1);
    try expectRefused(blob("this.blob[0n] %= 7n;"), "Blob.runar.ts", 1);
}
test "N-002: ByteString property, nested index" {
    try expectRefused(blob("this.blob[0n][1n] = 7n;"), "Blob.runar.ts", 1);
}
test "N-002: member-chained root" {
    try expectRefused(blob("this.blob.x[0n] = 7n;"), "Blob.runar.ts", 1);
}
test "N-002: local and parameter (TS surface)" {
    try expectRefused(TS_LOCAL, "Loc.runar.ts", 1);
    try expectRefused(TS_PARAM, "Par.runar.ts", 1);
}
test "N-002: Zig surface, ByteString property and local + parameter" {
    try expectRefused(ZIG_PROP, "Blob.runar.zig", 1);
    try expectRefused(ZIG_LOCAL_PARAM, "Loc.runar.zig", 2);
}

const FIXED_ARRAY_WRITES =
    \\import { StatefulSmartContract, FixedArray, assert } from 'runar-lang';
    \\
    \\class Board extends StatefulSmartContract {
    \\  board: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];
    \\
    \\  constructor() {
    \\    super();
    \\  }
    \\
    \\  public set(i: bigint, v: bigint) {
    \\    this.board[i] = v;
    \\    this.board[0n] = v;
    \\    this.board[1n] += v;
    \\    this.board[2n]++;
    \\    this.grid[0n][1n] = v;
    \\    assert(true);
    \\  }
    \\}
;

test "N-002: FixedArray index writes still validate and compile" {
    try std.testing.expectEqual(@as(usize, 0), try needleCount(FIXED_ARRAY_WRITES, "Board.runar.ts"));
    const a = std.testing.allocator;
    const r = try compiler_api.compileSource(a, FIXED_ARRAY_WRITES, "Board.runar.ts");
    defer a.free(r.script_hex);
    defer if (r.artifact_json) |j| a.free(j);
    defer {
        for (r.warnings) |line| a.free(line);
        a.free(r.warnings);
    }
    try std.testing.expect(r.script_hex.len > 0);
}
