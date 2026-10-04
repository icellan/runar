//! N-087 — `parseANFProgram` enforces the source validator's parentClass
//! rules and refuses a write to a readonly or undeclared property, with the
//! diagnostics shared by all seven tiers. These cases are copied verbatim from
//! conformance/negatives/ir-parent-class-cases.json; the full corpus is driven
//! through this tier's CLI by conformance/negatives/ir-parent-class.test.ts.
//!
//! Before: a SmartContract declaring `owner` with readonly:false (F-107's
//! v2-mut-stateless) made `compile-ir` print 76767b8777, which an attacker's
//! key spends under strict @bsv/sdk Spend; a readonly write, a stateful-only
//! node in a non-stateful contract and raw_script outside
//! UnsafeSmartContract compiled too.
//!
//! Proves: each case is refused with its shared message and the accepted
//! programs (incl. parentClass-less IR) load. Does not prove that a declared
//! StatefulSmartContract body enforces its state continuation.

const std = @import("std");
const testing = std.testing;
const json = @import("json.zig");
const required_fields = @import("required_fields.zig");

fn expectLoads(src: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    _ = try json.parseANFProgram(arena.allocator(), src);
}

fn expectRefused(src: []const u8, want: []const u8, prefix: bool) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    if (json.parseANFProgram(arena.allocator(), src)) |_| {
        return error.TestUnexpectedlyAccepted;
    } else |_| {}
    const got = required_fields.lastDiagnostic() orelse "<none>";
    if (prefix) {
        try testing.expect(std.mem.startsWith(u8, got, want));
    } else {
        try testing.expectEqualStrings(want, got);
    }
}

test "N-087 accepts p2pk-smartcontract" {
    try expectLoads("{\"contractName\":\"X\",\"properties\":[{\"name\":\"pk\",\"type\":\"PubKey\",\"readonly\":true}],\"methods\":[{\"name\":\"unlock\",\"isPublic\":true,\"params\":[{\"name\":\"sig\",\"type\":\"Sig\"}],\"body\":[{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"sig\"}},{\"name\":\"t1\",\"value\":{\"kind\":\"load_prop\",\"name\":\"pk\"}},{\"name\":\"t2\",\"value\":{\"kind\":\"call\",\"func\":\"checkSig\",\"args\":[\"t0\",\"t1\"]}},{\"name\":\"t3\",\"value\":{\"kind\":\"assert\",\"value\":\"t2\"}}]}],\"parentClass\":\"SmartContract\"}");
}

test "N-087 accepts p2pk-no-parent-class" {
    try expectLoads("{\"contractName\":\"X\",\"properties\":[{\"name\":\"pk\",\"type\":\"PubKey\",\"readonly\":true}],\"methods\":[{\"name\":\"unlock\",\"isPublic\":true,\"params\":[{\"name\":\"sig\",\"type\":\"Sig\"}],\"body\":[{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"sig\"}},{\"name\":\"t1\",\"value\":{\"kind\":\"load_prop\",\"name\":\"pk\"}},{\"name\":\"t2\",\"value\":{\"kind\":\"call\",\"func\":\"checkSig\",\"args\":[\"t0\",\"t1\"]}},{\"name\":\"t3\",\"value\":{\"kind\":\"assert\",\"value\":\"t2\"}}]}]}");
}

test "N-087 accepts asm-raw-script-no-parent-class" {
    try expectLoads("{\"contractName\":\"Anyone\",\"methods\":[{\"body\":[{\"name\":\"t0\",\"value\":{\"args\":[],\"func\":\"super\",\"kind\":\"call\"}}],\"isPublic\":false,\"name\":\"constructor\",\"params\":[]},{\"body\":[{\"name\":\"t0\",\"value\":{\"bytes\":\"51\",\"in_arity\":0,\"kind\":\"raw_script\",\"out_arity\":1}}],\"isPublic\":true,\"name\":\"unlock\",\"params\":[]}],\"properties\":[]}");
}

test "N-087 refuses hijack-mutable-owner-smartcontract" {
    try expectRefused(
        "{\"contractName\":\"Hijack\",\"parentClass\":\"SmartContract\",\"properties\":[{\"name\":\"owner\",\"type\":\"PubKey\",\"readonly\":false}],\"methods\":[{\"name\":\"constructor\",\"params\":[{\"name\":\"owner\",\"type\":\"PubKey\"}],\"isPublic\":false,\"body\":[]},{\"name\":\"steal\",\"params\":[{\"name\":\"x\",\"type\":\"PubKey\"}],\"isPublic\":true,\"body\":[{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"x\"}},{\"name\":\"t1\",\"value\":{\"kind\":\"update_prop\",\"name\":\"owner\",\"value\":\"t0\"}},{\"name\":\"t2\",\"value\":{\"kind\":\"load_prop\",\"name\":\"owner\"}},{\"name\":\"t3\",\"value\":{\"kind\":\"load_param\",\"name\":\"x\"}},{\"name\":\"t4\",\"value\":{\"kind\":\"bin_op\",\"op\":\"===\",\"left\":\"t2\",\"right\":\"t3\",\"result_type\":\"bytes\"}},{\"name\":\"t5\",\"value\":{\"kind\":\"assert\",\"value\":\"t4\"}}]}]}",
        "IR validation: Property 'owner' in SmartContract must be readonly. Use StatefulSmartContract for mutable state.",
        false,
    );
}

test "N-087 refuses hijack-mutable-owner-no-parent-class" {
    try expectRefused(
        "{\"contractName\":\"Hijack\",\"properties\":[{\"name\":\"owner\",\"type\":\"PubKey\",\"readonly\":false}],\"methods\":[{\"name\":\"constructor\",\"params\":[{\"name\":\"owner\",\"type\":\"PubKey\"}],\"isPublic\":false,\"body\":[]},{\"name\":\"steal\",\"params\":[{\"name\":\"x\",\"type\":\"PubKey\"}],\"isPublic\":true,\"body\":[{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"x\"}},{\"name\":\"t1\",\"value\":{\"kind\":\"update_prop\",\"name\":\"owner\",\"value\":\"t0\"}},{\"name\":\"t2\",\"value\":{\"kind\":\"load_prop\",\"name\":\"owner\"}},{\"name\":\"t3\",\"value\":{\"kind\":\"load_param\",\"name\":\"x\"}},{\"name\":\"t4\",\"value\":{\"kind\":\"bin_op\",\"op\":\"===\",\"left\":\"t2\",\"right\":\"t3\",\"result_type\":\"bytes\"}},{\"name\":\"t5\",\"value\":{\"kind\":\"assert\",\"value\":\"t4\"}}]}]}",
        "IR validation: Property 'owner' in SmartContract must be readonly. Use StatefulSmartContract for mutable state.",
        false,
    );
}

test "N-087 refuses readonly-write" {
    try expectRefused(
        "{\"contractName\":\"Hijack\",\"parentClass\":\"SmartContract\",\"properties\":[{\"name\":\"owner\",\"type\":\"PubKey\",\"readonly\":true}],\"methods\":[{\"name\":\"constructor\",\"params\":[{\"name\":\"owner\",\"type\":\"PubKey\"}],\"isPublic\":false,\"body\":[]},{\"name\":\"steal\",\"params\":[{\"name\":\"x\",\"type\":\"PubKey\"}],\"isPublic\":true,\"body\":[{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"x\"}},{\"name\":\"t1\",\"value\":{\"kind\":\"update_prop\",\"name\":\"owner\",\"value\":\"t0\"}},{\"name\":\"t2\",\"value\":{\"kind\":\"load_prop\",\"name\":\"owner\"}},{\"name\":\"t3\",\"value\":{\"kind\":\"load_param\",\"name\":\"x\"}},{\"name\":\"t4\",\"value\":{\"kind\":\"bin_op\",\"op\":\"===\",\"left\":\"t2\",\"right\":\"t3\",\"result_type\":\"bytes\"}},{\"name\":\"t5\",\"value\":{\"kind\":\"assert\",\"value\":\"t4\"}}]}]}",
        "IR validation: cannot assign to readonly property 'owner' in method 'steal'",
        true,
    );
}

test "N-087 refuses undeclared-property-write" {
    try expectRefused(
        "{\"contractName\":\"Hijack\",\"parentClass\":\"SmartContract\",\"properties\":[{\"name\":\"owner\",\"type\":\"PubKey\",\"readonly\":true}],\"methods\":[{\"name\":\"constructor\",\"params\":[{\"name\":\"owner\",\"type\":\"PubKey\"}],\"isPublic\":false,\"body\":[]},{\"name\":\"steal\",\"params\":[{\"name\":\"x\",\"type\":\"PubKey\"}],\"isPublic\":true,\"body\":[{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"x\"}},{\"name\":\"t1\",\"value\":{\"kind\":\"update_prop\",\"name\":\"ghost\",\"value\":\"t0\"}},{\"name\":\"t2\",\"value\":{\"kind\":\"load_prop\",\"name\":\"owner\"}},{\"name\":\"t3\",\"value\":{\"kind\":\"load_param\",\"name\":\"x\"}},{\"name\":\"t4\",\"value\":{\"kind\":\"bin_op\",\"op\":\"===\",\"left\":\"t2\",\"right\":\"t3\",\"result_type\":\"bytes\"}},{\"name\":\"t5\",\"value\":{\"kind\":\"assert\",\"value\":\"t4\"}}]}]}",
        "IR validation: method 'steal' assigns to undeclared property 'ghost'",
        false,
    );
}

test "N-087 refuses add-output-in-smartcontract" {
    try expectRefused(
        "{\"contractName\":\"X\",\"properties\":[{\"name\":\"pk\",\"type\":\"PubKey\",\"readonly\":true}],\"methods\":[{\"name\":\"unlock\",\"isPublic\":true,\"params\":[{\"name\":\"sig\",\"type\":\"Sig\"}],\"body\":[{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"sig\"}},{\"name\":\"t1\",\"value\":{\"kind\":\"load_prop\",\"name\":\"pk\"}},{\"name\":\"t2\",\"value\":{\"kind\":\"call\",\"func\":\"checkSig\",\"args\":[\"t0\",\"t1\"]}},{\"name\":\"t4\",\"value\":{\"kind\":\"load_const\",\"value\":1}},{\"name\":\"t5\",\"value\":{\"kind\":\"add_output\",\"satoshis\":\"t4\",\"stateValues\":[],\"preimage\":\"t0\"}},{\"name\":\"t3\",\"value\":{\"kind\":\"assert\",\"value\":\"t2\"}}]}],\"parentClass\":\"SmartContract\"}",
        "IR validation: 'add_output' in method 'unlock' is only available in StatefulSmartContract; got SmartContract",
        false,
    );
}

test "N-087 refuses get-state-script-in-if-arm-unsafesmartcontract" {
    try expectRefused(
        "{\"contractName\":\"X\",\"properties\":[{\"name\":\"pk\",\"type\":\"PubKey\",\"readonly\":true}],\"methods\":[{\"name\":\"unlock\",\"isPublic\":true,\"params\":[{\"name\":\"sig\",\"type\":\"Sig\"}],\"body\":[{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"sig\"}},{\"name\":\"t1\",\"value\":{\"kind\":\"load_prop\",\"name\":\"pk\"}},{\"name\":\"t2\",\"value\":{\"kind\":\"call\",\"func\":\"checkSig\",\"args\":[\"t0\",\"t1\"]}},{\"name\":\"t5\",\"value\":{\"kind\":\"if\",\"cond\":\"t2\",\"then\":[{\"name\":\"t6\",\"value\":{\"kind\":\"get_state_script\"}}],\"else\":[]}},{\"name\":\"t3\",\"value\":{\"kind\":\"assert\",\"value\":\"t2\"}}]}],\"parentClass\":\"UnsafeSmartContract\"}",
        "IR validation: 'get_state_script' in method 'unlock' is only available in StatefulSmartContract; got UnsafeSmartContract",
        false,
    );
}

test "N-087 refuses raw-script-in-smartcontract" {
    try expectRefused(
        "{\"contractName\":\"Anyone\",\"methods\":[{\"body\":[{\"name\":\"t0\",\"value\":{\"args\":[],\"func\":\"super\",\"kind\":\"call\"}}],\"isPublic\":false,\"name\":\"constructor\",\"params\":[]},{\"body\":[{\"name\":\"t0\",\"value\":{\"bytes\":\"51\",\"in_arity\":0,\"kind\":\"raw_script\",\"out_arity\":1}}],\"isPublic\":true,\"name\":\"unlock\",\"params\":[]}],\"parentClass\":\"SmartContract\",\"properties\":[]}",
        "IR validation: 'raw_script' in method 'unlock' is only available in contracts extending UnsafeSmartContract; got SmartContract",
        false,
    );
}

test "N-087 refuses raw-script-with-stateful-marker-no-parent-class" {
    try expectRefused(
        "{\"contractName\":\"Anyone\",\"methods\":[{\"body\":[{\"name\":\"t0\",\"value\":{\"args\":[],\"func\":\"super\",\"kind\":\"call\"}}],\"isPublic\":false,\"name\":\"constructor\",\"params\":[]},{\"body\":[{\"name\":\"t1\",\"value\":{\"kind\":\"get_state_script\"}},{\"name\":\"t0\",\"value\":{\"bytes\":\"51\",\"in_arity\":0,\"kind\":\"raw_script\",\"out_arity\":1}}],\"isPublic\":true,\"name\":\"unlock\",\"params\":[]}],\"properties\":[]}",
        "IR validation: 'raw_script' in method 'unlock' is only available in contracts extending UnsafeSmartContract; got StatefulSmartContract",
        false,
    );
}
