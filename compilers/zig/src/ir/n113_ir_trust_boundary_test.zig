//! N-113 — the two shapes the Go tier rejected alone (R-079 / R-081).
//!
//! Both are `--ir`-only: the source path refuses each shape in
//! `passes/validate.zig`, and `parseANFProgram` is reached only from the IR
//! loader. Go grew these guards first (compilers/go/ir/loader.go) and was
//! deliberately, transiently stricter than its six peers until N-113;
//! `conformance/negatives/ir-rejection-parity.test.ts` is the gate that now
//! compares the six.
//!
//! Zig's IR loader is an error-enum channel with no message payload, so the
//! error NAME is the whole diagnostic — hence `EmptyRawScriptBody` and
//! `NoPublicMethods` rather than another `InvalidConstValue`.

const std = @import("std");
const testing = std.testing;
const json = @import("json.zig");

/// A one-method contract parameterised on the two fields under test, so every
/// case below differs from the VALID control in exactly one way.
fn irJson(allocator: std.mem.Allocator, is_public: bool, raw_bytes: []const u8, out_arity: u8) ![]const u8 {
    return std.fmt.allocPrint(allocator,
        \\{{"contractName":"Anyone","properties":[],"methods":[{{"name":"unlock","params":[],"isPublic":{},"body":[{{"name":"t0","value":{{"kind":"raw_script","bytes":"{s}","in_arity":0,"out_arity":{d}}}}}]}}]}}
    , .{ is_public, raw_bytes, out_arity });
}

// The control every case below is derived from. A probe whose control also
// fails proves nothing.
test "control: valid IR is accepted" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const src = try irJson(allocator, true, "51", 1);
    const program = try json.parseANFProgram(allocator, src);
    try testing.expectEqualStrings("Anyone", program.contract_name);
}

// R-079: lowering pops in_arity and pushes out_arity on the stack model while
// emission writes nothing for a zero-length span. The span degrades to the
// identity function and a DIFFERENT WITNESS spends the output. Measured on
// @bsv/sdk's Spend: `8f01859c` accepts x=5 and rejects x=-5; with the body
// erased, `01859c` does the opposite.
test "rejects an empty raw_script body" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const src = try irJson(allocator, true, "", 1);
    try testing.expectError(error.EmptyRawScriptBody, json.parseANFProgram(allocator, src));
}

// The degenerate in=0/out=0 case is harmless on its own and is rejected
// anyway: mirroring the source validator exactly beats a narrower
// arity-conditional rule that would differ from the rule one pass earlier.
test "rejects an empty raw_script body even at zero arity" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const src = try irJson(allocator, true, "", 0);
    try testing.expectError(error.EmptyRawScriptBody, json.parseANFProgram(allocator, src));
}

// R-081: emission succeeds with an EMPTY locking script, which is
// anyone-can-spend. On @bsv/sdk's Spend under full consensus wrappers,
// lock="" with unlock=OP_1 (0x51) validates.
test "rejects a contract with no public methods" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const src = try irJson(allocator, false, "51", 1);
    try testing.expectError(error.NoPublicMethods, json.parseANFProgram(allocator, src));
}

test "rejects an empty method list" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const src =
        \\{"contractName":"Empty","properties":[],"methods":[]}
    ;
    try testing.expectError(error.NoPublicMethods, json.parseANFProgram(allocator, src));
}

// Ordering matters and is asserted, not assumed: when a binding is ALSO
// malformed, the malformed binding is the more actionable diagnostic. Same
// ordering as compilers/go/ir/loader.go — the per-binding parse runs first, so
// the odd-hex error wins over the missing entry point.
test "structural errors keep priority over the entry-point error" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const src = try irJson(allocator, false, "515", 1);
    try testing.expectError(error.InvalidConstValue, json.parseANFProgram(allocator, src));
}
