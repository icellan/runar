// Signature hygiene (spec §9).

const std = @import("std");
const types = @import("analyzer_types.zig");

const Opcode = types.Opcode;
const Finding = types.Finding;
const Code = types.Code;
const ExecutionPath = types.ExecutionPath;

pub fn analyzeSigHygiene(
    allocator: std.mem.Allocator,
    ops: []const Opcode,
    paths: []const ExecutionPath,
) ![]Finding {
    var findings = std.ArrayList(Finding).empty;
    errdefer {
        for (findings.items) |f| f.deinit(allocator);
        findings.deinit(allocator);
    }

    // NO_SIG_CHECK per reachable path without checkSig.
    for (paths) |p| {
        if (p.reachable and !p.has_check_sig) {
            const msg = try allocator.dupe(u8, "Execution path has no signature verification (OP_CHECKSIG/OP_CHECKMULTISIG)");
            try findings.append(allocator, Finding{
                .severity = Code.NO_SIG_CHECK.severity(),
                .code = .NO_SIG_CHECK,
                .message = msg,
                .path = try allocator.dupe(u8, p.description),
            });
        }
    }

    // CHECKSIG_RESULT_DROPPED: OP_CHECKSIG/OP_CHECKMULTISIG followed by OP_DROP.
    if (ops.len >= 2) {
        var i: usize = 0;
        while (i + 1 < ops.len) : (i += 1) {
            const cur = ops[i];
            const nxt = ops[i + 1];
            const is_check = cur.opcode == 0xac or cur.opcode == 0xae;
            if (is_check and nxt.opcode == 0x75) {
                const msg = try std.fmt.allocPrint(
                    allocator,
                    "{s} result is dropped by {s} — signature check has no effect",
                    .{ cur.name, nxt.name },
                );
                try findings.append(allocator, Finding{
                    .severity = Code.CHECKSIG_RESULT_DROPPED.severity(),
                    .code = .CHECKSIG_RESULT_DROPPED,
                    .message = msg,
                    .offset = cur.offset,
                    .opcode = try allocator.dupe(u8, cur.name),
                });
            }
        }
    }

    return try findings.toOwnedSlice(allocator);
}
