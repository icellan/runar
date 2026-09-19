//! N-097 — a FixedArray element READ is untypeable in arithmetic position.
//!
//! Repro (the supported, initialized-property form):
//!
//!     xs: FixedArray<bigint, 3> = [0n, 0n, 0n];
//!     ...
//!     assert(this.xs[0] >= 0n);
//!
//! TS / Go / Rust / Python / Ruby / Java accept it. Zig refused it with
//!
//!     left operand of '>=' must be bigint, got 'unknown'
//!
//! because `inferExprType`'s `.index_access` arm returns `.unknown` for every
//! element read.
//!
//! WHY THIS IS NOT COSMETIC: a tier that rejects valid code for the wrong
//! reason hides defects behind the refusal. N-092 (a constructor-parameter
//! FixedArray that Zig accepted and emitted a 480-byte script for) was masked
//! exactly this way — the dispatch probe read `this.xs[0]`, Zig refused it for
//! THIS reason, and the real defect looked like a correct late rejection.
//!
//! ---------------------------------------------------------------------------
//! THE N-019 CONSTRAINT — read before touching this file
//! ---------------------------------------------------------------------------
//!
//! The N-019 tripwire at the bottom of `passes/typecheck.zig` forbids teaching
//! `.index_access` to return the element type, because `this.board[i]++` would
//! then compile: this tier's `expand_fixed_arrays` rewrites `.increment` by
//! recursing into its operand, so a runtime-index increment becomes
//! `increment(<read-dispatch ternary>)` — an increment of a temporary that
//! writes back to no slot and emits NO state continuation. That is the N-019
//! fund-loss defect verbatim.
//!
//! This fix therefore does NOT touch `.index_access`. Following R-073
//! (`1f8eb8a9`), it reads the element type off the DECLARED property at the one
//! site that needs it — `checkBinaryExpr`'s two operands — and leaves general
//! inference returning `.unknown`. `inferExprType(.index_access)` is still
//! `.unknown`, so the `.increment` / `.decrement` arms still see `.unknown` and
//! still refuse. The tripwire test passes unmodified; so does the literal-index
//! increment, which stays refused (a separate, narrower gap, pinned below).
//!
//! Enumeration of where an element read can legally appear, and what each tier
//! did BEFORE this fix (measured with `--disable-constant-folding`):
//!
//!     position                     go/ts/rust/py/ruby/java   zig before   zig after
//!     `==` / `!=` operand          accept                    accept       accept
//!     call argument (`min(..)`)    accept                    accept       accept
//!     RHS of an assignment         accept                    accept       accept
//!     RHS of a typed `const`       accept                    accept       accept
//!     `return` value               accept                    accept       accept
//!     arithmetic/relational operand accept                   REJECT       accept
//!     `arr[i]++`                   accept                    REJECT       REJECT (N-019)
//!
//! Only the arithmetic/relational operand row moved. That is the whole fix.
//!
//! N-124 UPDATE: the last row moved too, one commit later and for the reason
//! this file's own header gives — the pass-3b increment desugar was ported, so
//! `arr[i]++` is rewritten to `arr[i] = arr[i] + 1` and the write-back the
//! refusal was standing in for is now real. The three tests below that pinned
//! the refusal are rewritten to pin the acceptance; the bytes are pinned
//! against the Go tier in `n124_fixed_array_increment.zig`, and the expression
//! form (`const y = arr[i]++`) is refused there, in `expand_fixed_arrays.zig`
//! rather than in the typechecker.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const typecheck = @import("../passes/typecheck.zig");
const compiler_api = @import("../compiler_api.zig");

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/// The filed repro.
const REPRO =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class P1binop extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  xs: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  total: bigint = 0n;
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public probe(v: bigint) {
    \\    assert(this.xs[0] >= 0n);
    \\  }
    \\}
;

/// The N-019 shape: a RUNTIME-index increment. Refused until N-124 ported the
/// pass-3b increment desugar; accepted, and byte-identical to the Go tier,
/// since.
const N019_RUNTIME_INCR =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class BumpDyn extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  xs: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public probe(i: bigint) {
    \\    this.xs[i]++;
    \\  }
    \\}
;

/// The literal-index increment. `expand_fixed_arrays` lowers it to a plain
/// `this.xs__0 = this.xs__0 + 1` property write. Was refused alongside the
/// runtime form because both go through the `.increment` arm; N-124 closed
/// both, since the desugar covers either index shape.
const LITERAL_INCR =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class BumpLit extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  xs: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public probe(v: bigint) {
    \\    this.xs[0]++;
    \\  }
    \\}
;

/// The element type must be the DECLARED one, not a blanket `.bigint`. A
/// `FixedArray<ByteString, 2>` element in arithmetic position stays an error —
/// and now names the real type, exactly as Go does.
const BYTESTRING_ELEMENT_IN_ARITHMETIC =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class NegWords extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  words: FixedArray<ByteString, 2> = ["00", "00"];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public probe(v: bigint) {
    \\    assert(this.words[0] >= 0n);
    \\  }
    \\}
;

/// R-073 pin, restated here: the element WRITE check must not be disturbed by
/// the read-side change.
const R073_BAD_WRITE =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class CellProbe extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  cells: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public setBad(v: ByteString) {
    \\    assert(this.owner > 0n);
    \\    this.cells[0] = v;
    \\  }
    \\}
;

/// Control 1: no FixedArray anywhere. Byte-pinned.
const CONTROL_NO_ARRAY =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class NoArr extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  total: bigint = 0n;
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public probe(v: bigint) {
    \\    assert(this.total >= 0n);
    \\    this.total = v + 1n;
    \\  }
    \\}
;

/// Control 2: the supported FixedArray WRITE path. Byte-pinned; this tier
/// already agreed with Go here and must keep agreeing.
const CONTROL_ARRAY_WRITE =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class P9write extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  xs: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  total: bigint = 0n;
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public probe(v: bigint) {
    \\    this.xs[0] = v;
    \\  }
    \\}
;

// ---------------------------------------------------------------------------
// Cross-tier byte pins. Captured from `compilers/go/runar-go --source <f> --hex
// --disable-constant-folding`, which the conformance suite treats as the
// reference tier. Asserting the BYTES (not merely "it compiled") is what makes
// this a parity test rather than a smoke test.
// ---------------------------------------------------------------------------

/// Go's locking script for `REPRO`.
const GO_REPRO_HEX = "76ab76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad69768254947f7701007e8101419d01687f7782012c947f758258947f75820120947f77587f7c817c587f7c817c587f7c817c81537900a27777777777";

/// Go's locking script for `CONTROL_ARRAY_WRITE` (unchanged by this fix).
const GO_ARRAY_WRITE_HEX = "61ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f8201219d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f75820120947f77587f7c817c587f7c817c587f7c817c81587a547a75577a577a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c5880547a58807e537a58807e7b58807e5279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f758777";

/// This tier's locking script for `CONTROL_NO_ARRAY`, captured before the fix.
const ZIG_NO_ARRAY_HEX = "61ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f77817600a269557a8b77547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f758777";


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn typecheckHasError(a: std.mem.Allocator, src: []const u8, needle: []const u8) !bool {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const w = arena.allocator();

    const parsed = parse_ts.parseTs(w, src, "N097.runar.ts");
    if (parsed.errors.len > 0) {
        for (parsed.errors) |e| std.debug.print("  unexpected parse error: {s}\n", .{e});
        return error.TestFixtureDidNotParse;
    }
    const contract = parsed.contract orelse return error.TestFixtureDidNotParse;

    const result = try typecheck.typeCheck(w, contract);
    for (result.errors) |msg| {
        if (std.mem.indexOf(u8, msg, needle) != null) return true;
    }
    return false;
}

fn typecheckErrorCount(a: std.mem.Allocator, src: []const u8) !usize {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const w = arena.allocator();
    const parsed = parse_ts.parseTs(w, src, "N097.runar.ts");
    if (parsed.contract == null) return error.TestFixtureDidNotParse;
    const result = try typecheck.typeCheck(w, parsed.contract.?);
    return result.errors.len;
}

/// Compile end-to-end and hand back the locking-script hex (caller frees).
fn compileHex(a: std.mem.Allocator, src: []const u8, file_name: []const u8) ![]const u8 {
    const result = try compiler_api.compileSource(a, src, file_name);
    if (result.artifact_json) |j| a.free(j);
    return result.script_hex;
}

// ---------------------------------------------------------------------------
// The defect
// ---------------------------------------------------------------------------

test "N-097: a literal-index element read is a legal bigint operand" {
    const a = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 0), try typecheckErrorCount(a, REPRO));
}

test "N-097: the repro compiles byte-identically to the Go tier" {
    const a = std.testing.allocator;
    const hex = try compileHex(a, REPRO, "P1binop.runar.ts");
    defer a.free(hex);
    try std.testing.expectEqualStrings(GO_REPRO_HEX, hex);
}

test "N-097: the element type is the declared one, not a blanket bigint" {
    const a = std.testing.allocator;
    // Go: "left operand of '>=' must be bigint, got 'ByteString'".
    try std.testing.expect(try typecheckHasError(
        a,
        BYTESTRING_ELEMENT_IN_ARITHMETIC,
        "left operand of '>=' must be bigint, got 'ByteString'",
    ));
}

// ---------------------------------------------------------------------------
// N-019 must stay shut
// ---------------------------------------------------------------------------

test "N-019 is closed by the desugar, not by the refusal: `this.xs[i]++` compiles" {
    // WAS "N-019 stays shut: still refused". N-124 ported the pass-3b increment
    // desugar this file's header names as the prerequisite, so the refusal is
    // gone and the write-back is real. The bytes are pinned against the Go tier
    // in `n124_fixed_array_increment.zig`; what is asserted here is only that
    // the old refusal is no longer produced.
    const a = std.testing.allocator;
    try std.testing.expect(!try typecheckHasError(
        a,
        N019_RUNTIME_INCR,
        "++ operator requires bigint",
    ));
    try std.testing.expectEqual(@as(usize, 0), try typecheckErrorCount(a, N019_RUNTIME_INCR));
}

test "N-019 is closed: the whole compile accepts the runtime-index increment" {
    const a = std.testing.allocator;
    const hex = try compileHex(a, N019_RUNTIME_INCR, "BumpDyn.runar.ts");
    defer a.free(hex);
    try std.testing.expect(hex.len > 0);
}

test "N-097 residual gap CLOSED: the literal-index increment compiles" {
    const a = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 0), try typecheckErrorCount(a, LITERAL_INCR));
}

// ---------------------------------------------------------------------------
// R-073 must stay shut
// ---------------------------------------------------------------------------

test "R-073 stays shut: a ByteString written into FixedArray<bigint,3> is refused" {
    const a = std.testing.allocator;
    try std.testing.expect(try typecheckHasError(
        a,
        R073_BAD_WRITE,
        "type 'ByteString' is not assignable to type 'bigint'",
    ));
}

test "R-073 stays shut: still exactly one diagnostic, not a cascade" {
    const a = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 1), try typecheckErrorCount(a, R073_BAD_WRITE));
}

// ---------------------------------------------------------------------------
// Controls: bytes must not move
// ---------------------------------------------------------------------------

test "N-097 control: a contract with no FixedArray is byte-unchanged" {
    const a = std.testing.allocator;
    const hex = try compileHex(a, CONTROL_NO_ARRAY, "NoArr.runar.ts");
    defer a.free(hex);
    try std.testing.expectEqualStrings(ZIG_NO_ARRAY_HEX, hex);
}

test "N-097 control: the supported FixedArray write path is byte-unchanged" {
    const a = std.testing.allocator;
    const hex = try compileHex(a, CONTROL_ARRAY_WRITE, "P9write.runar.ts");
    defer a.free(hex);
    try std.testing.expectEqualStrings(GO_ARRAY_WRITE_HEX, hex);
}

