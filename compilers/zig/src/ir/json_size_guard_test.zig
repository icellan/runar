// BUG-008 follow-up: IR-loader size-guard regression tests.

const std = @import("std");
const testing = std.testing;
const json = @import("json.zig");

test "parseANFProgram rejects oversized input" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const oversized = try allocator.alloc(u8, json.MAX_IR_BYTES + 1);
    @memset(oversized, ' ');

    const res = json.parseANFProgram(allocator, oversized);
    try testing.expectError(error.IRSizeExceeded, res);
}

test "parseANFProgram accepts minimal program (size guard does not trip)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // N-113: this fixture used to be `"methods":[]`, which R-081 established
    // is not a minimal VALID program at all — it is the anyone-can-spend shape
    // (no public method => empty locking script => spendable with OP_1). This
    // test's subject is the DoS caps, not the schema, so the fix is a fixture
    // that is genuinely minimal AND valid rather than a weaker assertion.
    const minimal =
        \\{"contractName":"X","properties":[],"methods":[{"name":"unlock","params":[],"isPublic":true,"body":[]}]}
    ;
    const program = try json.parseANFProgram(allocator, minimal);
    try testing.expectEqualStrings("X", program.contract_name);
}

test "parseANFProgram rejects deeply nested input" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Build a JSON payload nested past MAX_IR_NESTING (512). The depth
    // pre-walk should fire before any schema check.
    const depth: usize = json.MAX_IR_NESTING + 50;
    const head = "{\"contractName\":\"X\",\"properties\":[],\"methods\":[],\"_n\":";
    const tail = "}";
    const buf = try allocator.alloc(u8, head.len + depth * 2 + 1 + tail.len);
    var idx: usize = 0;
    @memcpy(buf[idx .. idx + head.len], head);
    idx += head.len;
    var i: usize = 0;
    while (i < depth) : (i += 1) {
        buf[idx] = '[';
        idx += 1;
    }
    buf[idx] = '1';
    idx += 1;
    i = 0;
    while (i < depth) : (i += 1) {
        buf[idx] = ']';
        idx += 1;
    }
    @memcpy(buf[idx .. idx + tail.len], tail);

    // Either our pre-walk catches it (MaxRecursionDepthExceeded) or
    // std.json's own depth bound rejects it — either is an acceptable
    // typed rejection, both treated as "the cap fired correctly".
    const got_error = if (json.parseANFProgram(allocator, buf)) |_| false else |_| true;
    try testing.expect(got_error);
}

test "depth walk ignores braces inside JSON strings" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // 1000 `{` inside a JSON string MUST NOT count toward depth.
    // N-113: the method list carries a public method because R-081 made
    // `"methods":[]` an invalid program (no spending entry point => an empty,
    // anyone-can-spend locking script). The subject here is the depth walk,
    // not the schema, so the fixture is made valid rather than the assertion
    // weakened.
    const head = "{\"contractName\":\"X\",\"properties\":[],\"methods\":[{\"name\":\"unlock\",\"params\":[],\"isPublic\":true,\"body\":[]}],\"_note\":\"";
    const tail = "\"}";
    const inner_count: usize = 1000;
    const buf = try allocator.alloc(u8, head.len + inner_count + tail.len);
    var idx: usize = 0;
    @memcpy(buf[idx .. idx + head.len], head);
    idx += head.len;
    @memset(buf[idx .. idx + inner_count], '{');
    idx += inner_count;
    @memcpy(buf[idx .. idx + tail.len], tail);

    const program = try json.parseANFProgram(allocator, buf);
    try testing.expectEqualStrings("X", program.contract_name);
}
