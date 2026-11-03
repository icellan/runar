//! F-164 (round 2): `executeStrict` must mock the WHOLE auto-injected
//! stateful prologue (checkPreimage's assert AND the sighash-type assert),
//! not just developer asserts.
//!
//! See `packages/runar-sdk/src/anf-interpreter.ts` for the TS reference
//! this ports (`detectAutoInjectedPrologueAsserts` there,
//! `detectAutoInjectedPrologue` in `sdk_anf_interpreter.zig`).
//!
//! Round 1 of F-164 fixed the `check_preimage` ANFNode kind to mock-return
//! `true` in strict mode. That alone is NOT enough: the compiler's
//! prologue also emits a SECOND, un-marked assert right after — the
//! sighash-type check (`assert(extractSigHashType(txPreimage) ===
//! <mode>)`) — and `extractSigHashType` has no real/mock value off-chain.
//! Before round 2, a strict-mode call against a REAL compiled stateful
//! method would get past checkPreimage only to throw at the sighash-type
//! assert instead — never reaching the method's actual body.
//!
//! Both bodies below spell out the exact 8-binding prologue
//! `compilers/zig/src/passes/anf_lower.zig`'s stateful-prologue emitter
//! injects at the START of every public stateful method (mirrors compiled
//! conformance/tests/stateful-counter expected-ir.json: t0-t7), followed
//! by user code.

const std = @import("std");
const interp = @import("sdk_anf_interpreter.zig");

const ANFProgram = interp.ANFProgram;
const ANFProperty = interp.ANFProperty;
const ANFParam = interp.ANFParam;
const ANFMethod = interp.ANFMethod;
const ANFBinding = interp.ANFBinding;
const ANFValue = interp.ANFValue;
const AssertionFailureInfo = interp.AssertionFailureInfo;

fn freshStates(allocator: std.mem.Allocator) !struct {
    current_state: std.StringHashMap(ANFValue),
    args: std.StringHashMap(ANFValue),
} {
    var current_state = std.StringHashMap(ANFValue).init(allocator);
    try current_state.put("count", .{ .int = 0 });
    const args = std.StringHashMap(ANFValue).init(allocator);
    return .{ .current_state = current_state, .args = args };
}

test "executeStrict mocks the WHOLE auto-injected prologue, including the sighash-type assert (F-164 round 2)" {
    const allocator = std.testing.allocator;

    const props = struct {
        var p = [_]ANFProperty{
            .{ .name = "count", .type_name = "bigint", .readonly = false },
        };
    };
    const params = struct {
        var p = [_]ANFParam{
            .{ .name = "txPreimage", .type_name = "SigHashPreimage" },
        };
    };
    const extract_args = struct {
        var a = [_][]const u8{"t3"};
    };
    const body = struct {
        var b = [_]ANFBinding{
            .{ .name = "t0", .value = .{ .load_param = .{ .name = "txPreimage" } } },
            .{ .name = "t1", .value = .{ .check_preimage = .{} } },
            .{ .name = "t2", .value = .{ .assert_node = .{ .value = "t1" } } },
            .{ .name = "t3", .value = .{ .load_param = .{ .name = "txPreimage" } } },
            .{ .name = "t4", .value = .{ .call = .{ .func = "extractSigHashType", .args = &extract_args.a } } },
            .{ .name = "t5", .value = .{ .load_const = .{ .value = .{ .int = 65 } } } },
            .{ .name = "t6", .value = .{ .bin_op = .{ .op = "===", .left = "t4", .right = "t5" } } },
            .{ .name = "t7", .value = .{ .assert_node = .{ .value = "t6" } } },
            .{ .name = "t8", .value = .{ .load_prop = .{ .name = "count" } } },
            .{ .name = "t9", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "t10", .value = .{ .bin_op = .{ .op = "+", .left = "t8", .right = "t9", .result_type = "bigint" } } },
            .{ .name = "t11", .value = .{ .update_prop = .{ .name = "count", .value = "t10" } } },
        };
    };
    const methods = struct {
        var m = [_]ANFMethod{
            .{ .name = "increment", .params = &params.p, .body = &body.b, .is_public = true },
        };
    };
    const anf: ANFProgram = .{
        .contract_name = "Counter",
        .properties = &props.p,
        .methods = &methods.m,
    };

    var states = try freshStates(allocator);
    defer states.current_state.deinit();
    defer states.args.deinit();

    var result = try interp.executeStrict(allocator, &anf, "increment", states.current_state, states.args, &.{});
    defer {
        result.state.deinit();
        allocator.free(result.data_outputs);
        allocator.free(result.raw_outputs);
        allocator.free(result.outputs);
    }

    const got = result.state.get("count").?;
    try std.testing.expectEqual(@as(i64, 1), got.int);
}

test "does NOT mock a user-written assert that also calls extractSigHashType after the prologue (F-164 round 2)" {
    const allocator = std.testing.allocator;

    const props = struct {
        var p = [_]ANFProperty{
            .{ .name = "count", .type_name = "bigint", .readonly = false },
        };
    };
    const params = struct {
        var p = [_]ANFParam{
            .{ .name = "txPreimage", .type_name = "SigHashPreimage" },
        };
    };
    const extract_args = struct {
        var a = [_][]const u8{"t3"};
    };
    const u_args = struct {
        var a = [_][]const u8{"u0"};
    };
    const body = struct {
        var b = [_]ANFBinding{
            .{ .name = "t0", .value = .{ .load_param = .{ .name = "txPreimage" } } },
            .{ .name = "t1", .value = .{ .check_preimage = .{} } },
            .{ .name = "t2", .value = .{ .assert_node = .{ .value = "t1" } } },
            .{ .name = "t3", .value = .{ .load_param = .{ .name = "txPreimage" } } },
            .{ .name = "t4", .value = .{ .call = .{ .func = "extractSigHashType", .args = &extract_args.a } } },
            .{ .name = "t5", .value = .{ .load_const = .{ .value = .{ .int = 65 } } } },
            .{ .name = "t6", .value = .{ .bin_op = .{ .op = "===", .left = "t4", .right = "t5" } } },
            .{ .name = "t7", .value = .{ .assert_node = .{ .value = "t6" } } },
            // User code redundantly re-checks the sighash type against a
            // WRONG expected mode (1 instead of the real 65) — must fail,
            // proving the mocking does not reach past the prologue.
            .{ .name = "u0", .value = .{ .load_param = .{ .name = "txPreimage" } } },
            .{ .name = "u1", .value = .{ .call = .{ .func = "extractSigHashType", .args = &u_args.a } } },
            .{ .name = "u2", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "u3", .value = .{ .bin_op = .{ .op = "===", .left = "u1", .right = "u2" } } },
            .{ .name = "userAssert", .value = .{ .assert_node = .{ .value = "u3" } } },
            .{ .name = "t8", .value = .{ .load_prop = .{ .name = "count" } } },
            .{ .name = "t9", .value = .{ .load_const = .{ .value = .{ .int = 1 } } } },
            .{ .name = "t10", .value = .{ .bin_op = .{ .op = "+", .left = "t8", .right = "t9", .result_type = "bigint" } } },
            .{ .name = "t11", .value = .{ .update_prop = .{ .name = "count", .value = "t10" } } },
        };
    };
    const methods = struct {
        var m = [_]ANFMethod{
            .{ .name = "increment", .params = &params.p, .body = &body.b, .is_public = true },
        };
    };
    const anf: ANFProgram = .{
        .contract_name = "Counter",
        .properties = &props.p,
        .methods = &methods.m,
    };

    var states = try freshStates(allocator);
    defer states.current_state.deinit();
    defer states.args.deinit();

    var info = AssertionFailureInfo{};
    const result = interp.executeStrictWithFailureInfo(allocator, &anf, "increment", states.current_state, states.args, &.{}, &info);
    try std.testing.expectError(error.AssertionFailure, result);
    try std.testing.expectEqualStrings("userAssert", info.binding_name);
}
