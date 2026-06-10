// Path enumeration + per-path analysis (spec §7).

const std = @import("std");
const types = @import("analyzer_types.zig");
const stack_mod = @import("analyzer_stack.zig");

const Opcode = types.Opcode;
const Finding = types.Finding;
const Code = types.Code;
const ExecutionPath = types.ExecutionPath;

const MAX_PATHS: usize = 256;

const Branch = struct {
    if_index: usize,
    else_index: i64, // -1 if absent
    endif_index: usize,
    is_notif: bool,
};

pub const PathAnalysisResult = struct {
    paths: []ExecutionPath,
    findings: []Finding,

    pub fn deinit(self: PathAnalysisResult, allocator: std.mem.Allocator) void {
        for (self.paths) |p| p.deinit(allocator);
        allocator.free(self.paths);
        for (self.findings) |f| f.deinit(allocator);
        allocator.free(self.findings);
    }
};

/// Spec §7. Caller owns returned slices + their owned strings.
pub fn analyzePaths(allocator: std.mem.Allocator, ops: []const Opcode) !PathAnalysisResult {
    var findings = std.ArrayList(Finding).empty;
    errdefer {
        for (findings.items) |f| f.deinit(allocator);
        findings.deinit(allocator);
    }

    // ── Phase 1: structural matching ───────────────────────────────────
    var frames = std.ArrayList(Branch).empty;
    defer frames.deinit(allocator);
    var branches = std.ArrayList(Branch).empty;
    defer branches.deinit(allocator);
    var has_structural_error = false;

    for (ops, 0..) |op, i| {
        if (op.opcode == 0x63 or op.opcode == 0x64) {
            try frames.append(allocator, .{
                .if_index = i,
                .else_index = -1,
                .endif_index = 0,
                .is_notif = (op.opcode == 0x64),
            });
        } else if (op.opcode == 0x67) {
            if (frames.items.len == 0) {
                const msg = try allocator.dupe(u8, "OP_ELSE without matching OP_IF");
                try findings.append(allocator, Finding{
                    .severity = Code.UNBALANCED_IF_ENDIF.severity(),
                    .code = .UNBALANCED_IF_ENDIF,
                    .message = msg,
                    .offset = op.offset,
                    .opcode = try allocator.dupe(u8, op.name),
                });
                has_structural_error = true;
            } else {
                frames.items[frames.items.len - 1].else_index = @intCast(i);
            }
        } else if (op.opcode == 0x68) {
            if (frames.items.len == 0) {
                const msg = try allocator.dupe(u8, "OP_ENDIF without matching OP_IF");
                try findings.append(allocator, Finding{
                    .severity = Code.UNBALANCED_IF_ENDIF.severity(),
                    .code = .UNBALANCED_IF_ENDIF,
                    .message = msg,
                    .offset = op.offset,
                    .opcode = try allocator.dupe(u8, op.name),
                });
                has_structural_error = true;
            } else {
                var top = frames.items[frames.items.len - 1];
                top.endif_index = i;
                _ = frames.pop();
                try branches.append(allocator, top);
            }
        }
    }
    // Any remaining frames → unclosed IF/NOTIF.
    for (frames.items) |fr| {
        has_structural_error = true;
        const if_op = ops[fr.if_index];
        const msg = try std.fmt.allocPrint(
            allocator,
            "{s} at offset {d} has no matching OP_ENDIF",
            .{ if_op.name, if_op.offset },
        );
        try findings.append(allocator, Finding{
            .severity = Code.UNBALANCED_IF_ENDIF.severity(),
            .code = .UNBALANCED_IF_ENDIF,
            .message = msg,
            .offset = if_op.offset,
            .opcode = try allocator.dupe(u8, if_op.name),
        });
    }

    if (has_structural_error) {
        return PathAnalysisResult{
            .paths = &[_]ExecutionPath{},
            .findings = try findings.toOwnedSlice(allocator),
        };
    }

    // ── Phase 2: collect IF/NOTIF source-order indices ────────────────
    var if_indices = std.ArrayList(usize).empty;
    defer if_indices.deinit(allocator);
    for (ops, 0..) |op, i| {
        if (op.opcode == 0x63 or op.opcode == 0x64) try if_indices.append(allocator, i);
    }
    const num_branches: u32 = @intCast(if_indices.items.len);

    // ── Phase 3: paths ─────────────────────────────────────────────────
    var paths = std.ArrayList(ExecutionPath).empty;
    errdefer {
        for (paths.items) |p| p.deinit(allocator);
        paths.deinit(allocator);
    }

    if (num_branches == 0) {
        // Linear path.
        const desc = try allocator.dupe(u8, "linear (no branches)");
        const choices = try allocator.alloc(bool, 0);
        const collected = try collectLinearOpcodes(allocator, ops);
        defer allocator.free(collected);
        const linres = try stack_mod.analyzeStackLinear(allocator, collected, 0);
        // Attach linres.findings with path field set.
        try appendPathFindings(allocator, &findings, linres, desc);
        defer allocator.free(linres.findings); // findings transferred individually
        // Unconditional success check.
        try maybeAppendUnconditionallySucceeds(allocator, &findings, collected, desc);
        try paths.append(allocator, ExecutionPath{
            .id = 0,
            .description = desc,
            .branch_choices = choices,
            .reachable = true,
            .has_check_sig = computeHasCheckSig(collected),
            .stack_depth_at_end = linres.depth,
        });
    } else {
        // Spec v1.2 §5.1: render symbolically when 2^num_branches
        // overflows the canonical TS reference's safe-integer range.
        const LARGE_BRANCH_THRESHOLD: u32 = 53;
        const use_exact_count: bool = num_branches < LARGE_BRANCH_THRESHOLD;
        const num_paths: usize = blk: {
            if (use_exact_count) {
                const exact: u64 = @as(u64, 1) << @as(u6, @intCast(num_branches));
                break :blk @min(@as(usize, @intCast(exact)), MAX_PATHS);
            } else {
                break :blk MAX_PATHS;
            }
        };

        const truncated: bool = blk: {
            if (use_exact_count) {
                const exact: u64 = @as(u64, 1) << @as(u6, @intCast(num_branches));
                break :blk exact > MAX_PATHS;
            } else {
                break :blk true;
            }
        };

        if (truncated) {
            const msg = if (use_exact_count) blk: {
                const exact: u64 = @as(u64, 1) << @as(u6, @intCast(num_branches));
                break :blk try std.fmt.allocPrint(
                    allocator,
                    "Script has {d} branch points (2^{d} = {d} paths); analysis truncated to the first 256. Consider reducing branching or splitting the contract into smaller spending paths.",
                    .{ num_branches, num_branches, exact },
                );
            } else try std.fmt.allocPrint(
                allocator,
                "Script has {d} branch points (more than 2^{d} paths); analysis truncated to the first 256. Consider reducing branching or splitting the contract into smaller spending paths.",
                .{ num_branches, LARGE_BRANCH_THRESHOLD },
            );
            try findings.append(allocator, Finding{
                .severity = Code.PATHS_TRUNCATED.severity(),
                .code = .PATHS_TRUNCATED,
                .message = msg,
            });
        }

        var combo: u32 = 0;
        while (combo < num_paths) : (combo += 1) {
            const choices = try allocator.alloc(bool, num_branches);
            errdefer allocator.free(choices);
            var b: u32 = 0;
            while (b < num_branches) : (b += 1) {
                // `combo` is bounded by MAX_PATHS = 256, so bits at
                // positions >= 8 are mathematically always 0. Clamp to
                // b < 31 to match the canonical TS reference, where JS
                // `>>` would otherwise mask the shift count to 5 bits
                // and wrap.
                if (b < 31) {
                    const shift: u5 = @intCast(b);
                    choices[b] = ((combo >> shift) & 1) == 1;
                } else {
                    choices[b] = false;
                }
            }
            const desc = try formatPathDescription(allocator, ops, if_indices.items, choices);
            errdefer allocator.free(desc);
            const collected = try collectBranchedOpcodes(allocator, ops, if_indices.items, choices);
            defer allocator.free(collected);
            const linres = try stack_mod.analyzeStackLinear(allocator, collected, 0);
            try appendPathFindings(allocator, &findings, linres, desc);
            allocator.free(linres.findings);
            try maybeAppendUnconditionallySucceeds(allocator, &findings, collected, desc);
            try paths.append(allocator, ExecutionPath{
                .id = @intCast(combo),
                .description = desc,
                .branch_choices = choices,
                .reachable = true,
                .has_check_sig = computeHasCheckSig(collected),
                .stack_depth_at_end = linres.depth,
            });
        }
    }

    // ── Phase 4: INCONSISTENT_BRANCH_DEPTH per balanced branch ────────
    for (branches.items) |br| {
        const endif_op = ops[br.endif_index];
        if (br.else_index < 0) {
            // No-ELSE form: flat delta of body (if_index+1, endif_index).
            const delta_opt = flatDelta(ops, br.if_index + 1, br.endif_index);
            if (delta_opt) |delta| {
                if (delta != 0) {
                    const msg = try std.fmt.allocPrint(
                        allocator,
                        "OP_IF body has net stack delta {d}; without an OP_ELSE the depth after OP_ENDIF depends on the branch condition",
                        .{delta},
                    );
                    try findings.append(allocator, Finding{
                        .severity = Code.INCONSISTENT_BRANCH_DEPTH.severity(),
                        .code = .INCONSISTENT_BRANCH_DEPTH,
                        .message = msg,
                        .offset = endif_op.offset,
                        .opcode = try allocator.dupe(u8, "OP_ENDIF"),
                    });
                }
            }
        } else {
            const else_idx: usize = @intCast(br.else_index);
            const then_delta_opt = flatDelta(ops, br.if_index + 1, else_idx);
            const else_delta_opt = flatDelta(ops, else_idx + 1, br.endif_index);
            if (then_delta_opt) |t_delta| {
                if (else_delta_opt) |e_delta| {
                    if (t_delta != e_delta) {
                        const msg = try std.fmt.allocPrint(
                            allocator,
                            "IF/ELSE branches leave different stack depths (THEN: {d}, ELSE: {d}) — code after OP_ENDIF will see a depth that depends on which branch ran",
                            .{ t_delta, e_delta },
                        );
                        try findings.append(allocator, Finding{
                            .severity = Code.INCONSISTENT_BRANCH_DEPTH.severity(),
                            .code = .INCONSISTENT_BRANCH_DEPTH,
                            .message = msg,
                            .offset = endif_op.offset,
                            .opcode = try allocator.dupe(u8, "OP_ENDIF"),
                        });
                    }
                }
            }
        }
    }

    return PathAnalysisResult{
        .paths = try paths.toOwnedSlice(allocator),
        .findings = try findings.toOwnedSlice(allocator),
    };
}

/// Collect linear opcodes — strip IF/NOTIF/ELSE/ENDIF.
fn collectLinearOpcodes(allocator: std.mem.Allocator, ops: []const Opcode) ![]Opcode {
    var out = std.ArrayList(Opcode).empty;
    errdefer out.deinit(allocator);
    for (ops) |op| {
        switch (op.opcode) {
            0x63, 0x64, 0x67, 0x68 => {},
            else => try out.append(allocator, op), // Shallow copy — caller doesn't deinit individuals.
        }
    }
    return try out.toOwnedSlice(allocator);
}

/// Collect opcodes executed under given branch choices (spec §7.4).
///
/// **Choice indexing**: matches the TS reference's running-counter
/// semantics — the k-th IF *encountered during the walk* binds to
/// choices[k], NOT the k-th IF in source order. This differs from the
/// path-description format, which always lists all source-order IFs
/// (`formatPathDescription`). When an outer IF is false, its inner IFs
/// are skipped without consuming choices, so subsequent IFs that ARE
/// encountered (e.g. in the outer ELSE body) get choices[1], [2], ...
/// rather than their source-order index. Spec §7.4 is ambiguous; the
/// goldens (stateful-counter, auction) require this interpretation.
fn collectBranchedOpcodes(
    allocator: std.mem.Allocator,
    ops: []const Opcode,
    if_indices: []const usize,
    choices: []const bool,
) ![]Opcode {
    _ = if_indices;
    var out = std.ArrayList(Opcode).empty;
    errdefer out.deinit(allocator);

    const match = try matchFrames(allocator, ops);
    defer allocator.free(match.endif_for_if);
    defer allocator.free(match.else_for_if);

    var counter: usize = 0;
    try collectRange(allocator, &out, ops, &match, choices, &counter, 0, ops.len);
    return try out.toOwnedSlice(allocator);
}

/// Collect opcodes in `[start, end)`, consuming `choices` linearly via
/// `counter` (running-counter semantics — see `collectBranchedOpcodes`).
fn collectRange(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(Opcode),
    ops: []const Opcode,
    match: *const FrameMatch,
    choices: []const bool,
    counter: *usize,
    start: usize,
    end: usize,
) !void {
    var i = start;
    while (i < end) {
        const op = ops[i];
        if (op.opcode == 0x63 or op.opcode == 0x64) {
            const choice = if (counter.* < choices.len) choices[counter.*] else true;
            counter.* += 1;
            const endif_i = match.endif_for_if[i];
            const else_i = match.else_for_if[i];
            if (choice) {
                const then_end: usize = if (else_i >= 0) @intCast(else_i) else endif_i;
                try collectRange(allocator, out, ops, match, choices, counter, i + 1, then_end);
            } else if (else_i >= 0) {
                try collectRange(allocator, out, ops, match, choices, counter, @as(usize, @intCast(else_i)) + 1, endif_i);
            }
            i = endif_i + 1;
        } else if (op.opcode == 0x67 or op.opcode == 0x68) {
            i += 1;
        } else {
            try out.append(allocator, op);
            i += 1;
        }
    }
}

const FrameMatch = struct {
    /// For each ops index that is IF/NOTIF, the matched ENDIF index (else 0).
    endif_for_if: []usize,
    /// For each ops index that is IF/NOTIF, the matched ELSE index (-1 if none).
    else_for_if: []i64,
};

fn matchFrames(allocator: std.mem.Allocator, ops: []const Opcode) !FrameMatch {
    var endif_for = try allocator.alloc(usize, ops.len);
    @memset(endif_for, 0);
    var else_for = try allocator.alloc(i64, ops.len);
    @memset(else_for, -1);

    var stack = std.ArrayList(usize).empty;
    defer stack.deinit(allocator);
    for (ops, 0..) |op, i| {
        if (op.opcode == 0x63 or op.opcode == 0x64) {
            try stack.append(allocator, i);
        } else if (op.opcode == 0x67) {
            if (stack.items.len > 0) {
                const top = stack.items[stack.items.len - 1];
                else_for[top] = @intCast(i);
            }
        } else if (op.opcode == 0x68) {
            if (stack.items.len > 0) {
                const top = stack.pop().?;
                endif_for[top] = i;
            }
        }
    }
    return .{ .endif_for_if = endif_for, .else_for_if = else_for };
}

fn formatPathDescription(
    allocator: std.mem.Allocator,
    ops: []const Opcode,
    if_indices: []const usize,
    choices: []const bool,
) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(allocator);
    for (if_indices, 0..) |op_i, k| {
        if (k > 0) try buf.appendSlice(allocator, " -> ");
        const op = ops[op_i];
        const label: []const u8 = if (op.opcode == 0x64) "NOTIF" else "IF";
        const choice = if (k < choices.len) choices[k] else true;
        const choice_str: []const u8 = if (choice) "true" else "false";
        const piece = try std.fmt.allocPrint(allocator, "{s}[{s}] at {d}", .{ label, choice_str, op.offset });
        defer allocator.free(piece);
        try buf.appendSlice(allocator, piece);
    }
    return try buf.toOwnedSlice(allocator);
}

fn computeHasCheckSig(ops: []const Opcode) bool {
    for (ops) |op| {
        switch (op.opcode) {
            0xac, 0xad, 0xae, 0xaf => return true,
            else => {},
        }
    }
    return false;
}

fn appendPathFindings(
    allocator: std.mem.Allocator,
    findings: *std.ArrayList(Finding),
    linres: stack_mod.LinearResult,
    path_desc: []const u8,
) !void {
    for (linres.findings) |f| {
        // Take ownership of f's fields; attach path.
        try findings.append(allocator, Finding{
            .severity = f.severity,
            .code = f.code,
            .message = f.message,
            .offset = f.offset,
            .opcode = f.opcode,
            .path = try allocator.dupe(u8, path_desc),
        });
    }
}

fn maybeAppendUnconditionallySucceeds(
    allocator: std.mem.Allocator,
    findings: *std.ArrayList(Finding),
    ops: []const Opcode,
    path_desc: []const u8,
) !void {
    if (ops.len == 0) return;
    for (ops) |op| {
        switch (op.opcode) {
            0x69, 0x6a, 0x88, 0x9d, 0xac, 0xad, 0xae, 0xaf => return,
            else => {},
        }
    }
    const msg = try allocator.dupe(u8, "Execution path has no verification opcode — any unlocking input will satisfy it");
    try findings.append(allocator, Finding{
        .severity = Code.UNCONDITIONALLY_SUCCEEDS.severity(),
        .code = .UNCONDITIONALLY_SUCCEEDS,
        .message = msg,
        .path = try allocator.dupe(u8, path_desc),
    });
}

fn flatDelta(ops: []const Opcode, start: usize, end: usize) ?i64 {
    var d: i64 = 0;
    var i = start;
    while (i < end) : (i += 1) {
        const op = ops[i];
        if (op.opcode == 0x63 or op.opcode == 0x64) return null;
        if (op.opcode == 0x67 or op.opcode == 0x68) continue;
        const eff = stack_mod.stackEffect(op);
        d += @as(i64, eff.pushes) - @as(i64, eff.pops);
    }
    return d;
}

test "linear path produced for branchless script" {
    const a = std.testing.allocator;
    const parser = @import("analyzer_script_parser.zig");
    const ops = try parser.parseScript(a, "76a90088ac");
    defer {
        for (ops) |op| op.deinit(a);
        a.free(ops);
    }
    const result = try analyzePaths(a, ops);
    defer result.deinit(a);
    try std.testing.expectEqual(@as(usize, 1), result.paths.len);
    try std.testing.expectEqualStrings("linear (no branches)", result.paths[0].description);
    try std.testing.expectEqual(@as(usize, 0), result.findings.len);
}
