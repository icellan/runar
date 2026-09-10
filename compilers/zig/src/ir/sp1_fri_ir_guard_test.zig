//! R-012 / CL-BUG-093, Zig tier — pin that the `--ir` path cannot emit the
//! known-unsound SP1 FRI verifier.
//!
//! The Go tier's `--ir` entry point compiled ANF IR that reaches
//! `verifySP1FRI` with no error and no warning, bypassing the
//! `@acknowledgeUnsoundSP1FriVerifier` refusal that `frontend.Validate`
//! enforces on the source path. `compileFromIR` in `src/main.zig` has the same
//! shape — it parses ANF JSON and goes straight to stack lowering, never
//! running `passes/validate.zig`.
//!
//! Zig is nonetheless NOT exposed, for a structural reason: the SP1 FRI
//! verifier is Go-only by project policy (see CLAUDE.md), so `verifySP1FRI` is
//! not a builtin this tier can lower at all, and `stack_lower`'s builtin
//! dispatch ends in `else => return LowerError.InvalidBuiltin` rather than a
//! silent no-op. There is no unsound verifier here to emit, acknowledged or
//! not.
//!
//! That is a property of the current builtin table, not a decision anyone
//! recorded, so this test records it. If a future port teaches this tier to
//! lower `verifySP1FRI`, the test goes red — and whoever does the port has to
//! bring the refusal with it instead of silently reopening the bypass in a
//! second tier.

const std = @import("std");
const json = @import("json.zig");
const stack_lower = @import("../passes/stack_lower.zig");

/// ANF IR that reaches the SP1 FRI verifier. This is the shape the Go tier's
/// `--emit-ir` produces from an acknowledged contract — note that it carries no
/// trace of the acknowledgement, which is the whole reason a loader-side guard
/// cannot consult a flag.
const sp1_fri_ir =
    \\{
    \\  "contractName": "Sp1Guard",
    \\  "properties": [
    \\    { "name": "sp1VKeyHash", "type": "ByteString", "readonly": true }
    \\  ],
    \\  "methods": [
    \\    {
    \\      "name": "verify",
    \\      "isPublic": true,
    \\      "params": [
    \\        { "name": "proofBlob", "type": "ByteString" },
    \\        { "name": "publicValues", "type": "ByteString" }
    \\      ],
    \\      "body": [
    \\        { "name": "t0", "value": { "kind": "load_param", "name": "proofBlob" } },
    \\        { "name": "t1", "value": { "kind": "load_param", "name": "publicValues" } },
    \\        { "name": "t2", "value": { "kind": "load_prop", "name": "sp1VKeyHash" } },
    \\        { "name": "t3", "value": { "kind": "call", "func": "verifySP1FRI", "args": ["t0", "t1", "t2"] } },
    \\        { "name": "t4", "value": { "kind": "assert", "value": "t3" } }
    \\      ]
    \\    }
    \\  ]
    \\}
;

test "ir path: verifySP1FRI is refused, never lowered" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // The loader accepts it — `call` is a real ANF kind, so the refusal cannot
    // come from JSON parsing.
    const program = try json.parseANFProgram(allocator, sp1_fri_ir);

    // Lowering must refuse. A success here means this tier grew the ability to
    // emit the unsound verifier without growing the refusal that guards it.
    const lowered = stack_lower.lower(allocator, program);
    if (lowered) |_| {
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expectEqual(error.InvalidBuiltin, err);
    }
}

/// Control: ordinary IR with nothing to do with SP1 still lowers. Without this,
/// the test above would pass just as happily against a tier that refused
/// everything.
const ordinary_ir =
    \\{
    \\  "contractName": "P2PKH",
    \\  "properties": [
    \\    { "name": "pubKeyHash", "type": "Addr", "readonly": true }
    \\  ],
    \\  "methods": [
    \\    {
    \\      "name": "unlock",
    \\      "isPublic": true,
    \\      "params": [
    \\        { "name": "sig", "type": "Sig" },
    \\        { "name": "pubKey", "type": "PubKey" }
    \\      ],
    \\      "body": [
    \\        { "name": "t0", "value": { "kind": "load_param", "name": "sig" } },
    \\        { "name": "t1", "value": { "kind": "load_param", "name": "pubKey" } },
    \\        { "name": "t2", "value": { "kind": "load_prop", "name": "pubKeyHash" } },
    \\        { "name": "t3", "value": { "kind": "call", "func": "hash160", "args": ["t1"] } },
    \\        { "name": "t4", "value": { "kind": "bin_op", "op": "===", "left": "t3", "right": "t2" } },
    \\        { "name": "t5", "value": { "kind": "assert", "value": "t4" } },
    \\        { "name": "t6", "value": { "kind": "call", "func": "checkSig", "args": ["t0", "t1"] } },
    \\        { "name": "t7", "value": { "kind": "assert", "value": "t6" } }
    \\      ]
    \\    }
    \\  ]
    \\}
;

test "ir path: ordinary IR still lowers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const program = try json.parseANFProgram(allocator, ordinary_ir);
    const lowered = try stack_lower.lower(allocator, program);
    try std.testing.expect(lowered.methods.len > 0);
}
