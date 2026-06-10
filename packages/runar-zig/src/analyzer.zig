// Bitcoin Script static analyzer — entry point.
//
// Spec: spec/script-analyzer-format.md
// All seven tiers MUST produce byte-identical JSON output for the
// same input hex.

const std = @import("std");
pub const types = @import("analyzer_types.zig");
pub const script_parser = @import("analyzer_script_parser.zig");
pub const stack_mod = @import("analyzer_stack.zig");
pub const path_mod = @import("analyzer_path.zig");
pub const sig_mod = @import("analyzer_sig.zig");
pub const opcode_concerns = @import("analyzer_opcode_concerns.zig");

pub const Severity = types.Severity;
pub const Code = types.Code;
pub const Finding = types.Finding;
pub const Opcode = types.Opcode;
pub const ExecutionPath = types.ExecutionPath;
pub const Summary = types.Summary;
pub const AnalysisResult = types.AnalysisResult;
pub const RawScriptSpan = types.RawScriptSpan;

pub const AnalyzeOptions = struct {
    raw_script_spans: []const RawScriptSpan = &.{},
};

/// Top-level analyzer (spec §11). Caller owns the result.
pub fn analyzeScript(
    allocator: std.mem.Allocator,
    hex_script: []const u8,
    options: AnalyzeOptions,
) !AnalysisResult {
    const normalized = try script_parser.normalizeHex(allocator, hex_script);
    errdefer allocator.free(normalized);
    const script_size_bytes: i64 = @intCast(normalized.len / 2);

    if (script_size_bytes == 0) {
        // Empty-script result (spec §2.1).
        var findings = try allocator.alloc(Finding, 1);
        findings[0] = Finding{
            .severity = .error_,
            .code = .INVALID_TERMINAL_STACK,
            .message = try allocator.dupe(u8, "Empty script — no opcodes to execute"),
        };
        const paths = try allocator.alloc(ExecutionPath, 0);
        return AnalysisResult{
            .script = normalized,
            .script_size = 0,
            .findings = findings,
            .paths = paths,
            .summary = .{
                .total_paths = 0,
                .reachable_paths = 0,
                .paths_with_check_sig = 0,
                .paths_without_check_sig = 0,
                .max_stack_depth = 0,
                .script_size_bytes = 0,
            },
        };
    }

    var opcodes = try script_parser.parseScript(allocator, normalized);
    errdefer {
        for (opcodes) |op| op.deinit(allocator);
        allocator.free(opcodes);
    }
    if (options.raw_script_spans.len > 0) {
        opcodes = try script_parser.collapseRawScriptSpans(allocator, opcodes, options.raw_script_spans);
    }

    var all_findings = std.ArrayList(Finding).empty;
    errdefer {
        for (all_findings.items) |f| f.deinit(allocator);
        all_findings.deinit(allocator);
    }

    // Step 1 — paths + structural + per-path findings + branch-depth.
    const pa = try path_mod.analyzePaths(allocator, opcodes);
    // Move ownership of paths + findings into outer scope.
    const paths = pa.paths;
    for (pa.findings) |f| try all_findings.append(allocator, f);
    allocator.free(pa.findings);

    const has_unbalanced = hasUnbalanced(all_findings.items);

    // Step 2 — linear-fallback if no paths + no UNBALANCED.
    if (paths.len == 0 and !has_unbalanced) {
        const lin = try stack_mod.analyzeStackLinear(allocator, opcodes, 0);
        for (lin.findings) |f| try all_findings.append(allocator, f);
        allocator.free(lin.findings);
    }

    // Step 3 — sig hygiene.
    const sig_findings = try sig_mod.analyzeSigHygiene(allocator, opcodes, paths);
    for (sig_findings) |f| try all_findings.append(allocator, f);
    allocator.free(sig_findings);

    // Step 4 — opcode concerns.
    const oc = try opcode_concerns.analyzeOpcodeConcerns(allocator, opcodes, script_size_bytes);
    for (oc) |f| try all_findings.append(allocator, f);
    allocator.free(oc);

    // Free opcodes — paths held shallow copies of opcode names? No — they own
    // their own description strings; opcodes can be freed independently.
    for (opcodes) |op| op.deinit(allocator);
    allocator.free(opcodes);

    // Stable sort by (severityRank, offsetRank).
    const sorted = try stableSortFindings(allocator, try all_findings.toOwnedSlice(allocator));

    // Build summary.
    var reachable: i32 = 0;
    var with_csig: i32 = 0;
    var without_csig: i32 = 0;
    var max_depth: i64 = 0;
    if (paths.len == 0) {
        max_depth = 0;
    } else {
        // Spec §8.3 says `max(p.stackDepthAtEnd over all paths)` with
        // default 0 only when paths is empty — but the 8 normative goldens
        // floor at 0 even when paths exist (e.g. basic-p2pkh has a single
        // path with stackDepthAtEnd=-1 yet maxStackDepth=0). Following
        // the goldens (golden-as-oracle per spec §1).
        max_depth = 0;
        for (paths) |p| if (p.stack_depth_at_end > max_depth) {
            max_depth = p.stack_depth_at_end;
        };
        for (paths) |p| {
            if (p.reachable) {
                reachable += 1;
                if (p.has_check_sig) with_csig += 1 else without_csig += 1;
            }
        }
    }

    return AnalysisResult{
        .script = normalized,
        .script_size = script_size_bytes,
        .findings = sorted,
        .paths = paths,
        .summary = .{
            .total_paths = @intCast(paths.len),
            .reachable_paths = reachable,
            .paths_with_check_sig = with_csig,
            .paths_without_check_sig = without_csig,
            .max_stack_depth = max_depth,
            .script_size_bytes = script_size_bytes,
        },
    };
}

fn hasUnbalanced(findings: []const Finding) bool {
    for (findings) |f| if (f.code == .UNBALANCED_IF_ENDIF) return true;
    return false;
}

/// Stable sort by (severityRank, offsetRank=offset or +inf), breaking
/// ties on original insertion index. Spec §11.1.
fn stableSortFindings(allocator: std.mem.Allocator, findings: []Finding) ![]Finding {
    const N = findings.len;
    const Pair = struct {
        original_index: u32,
        severity_rank: u8,
        has_offset: bool,
        offset: i64,
    };
    const pairs = try allocator.alloc(Pair, N);
    defer allocator.free(pairs);
    for (findings, 0..) |f, i| {
        pairs[i] = .{
            .original_index = @intCast(i),
            .severity_rank = f.severity.rank(),
            .has_offset = f.offset != null,
            .offset = if (f.offset) |o| o else 0,
        };
    }
    // Stable sort: use stable sort (std.mem.sort is stable in Zig 0.16).
    std.mem.sort(Pair, pairs, {}, struct {
        fn lt(_: void, a: Pair, b: Pair) bool {
            if (a.severity_rank != b.severity_rank) return a.severity_rank < b.severity_rank;
            // offset rank: offset if present, else +inf (sorts later).
            if (a.has_offset and b.has_offset) {
                if (a.offset != b.offset) return a.offset < b.offset;
            } else if (a.has_offset and !b.has_offset) {
                return true;
            } else if (!a.has_offset and b.has_offset) {
                return false;
            }
            return a.original_index < b.original_index;
        }
    }.lt);

    const out = try allocator.alloc(Finding, N);
    for (pairs, 0..) |p, i| out[i] = findings[p.original_index];
    allocator.free(findings);
    return out;
}

// ─── JSON writer ────────────────────────────────────────────────────────
//
// Mimics `JSON.stringify(_, null, 2) + '\n'`:
//   - 2-space indentation
//   - LF line endings
//   - "key": value (colon + space)
//   - elements on own lines; trailing `\n` at end of file
//   - empty arrays/objects collapse to `[]` / `{}`.

pub fn writeReportJson(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    result: AnalysisResult,
) !void {
    var jw = JsonWriter{ .out = out, .allocator = allocator, .indent = 0 };
    try jw.beginObject(); // top
    try jw.key("script");
    try jw.string(result.script);
    try jw.comma();
    try jw.key("scriptSize");
    try jw.integer(result.script_size);
    try jw.comma();
    try jw.key("findings");
    if (result.findings.len == 0) {
        try jw.emptyArray();
    } else {
        try jw.beginArray();
        for (result.findings, 0..) |f, i| {
            if (i > 0) try jw.comma();
            try jw.itemNewline();
            try jw.beginObjectInline();
            try jw.key("severity");
            try jw.string(f.severity.name());
            try jw.comma();
            try jw.key("code");
            try jw.string(f.code.name());
            try jw.comma();
            try jw.key("message");
            try jw.string(f.message);
            if (f.offset) |o| {
                try jw.comma();
                try jw.key("offset");
                try jw.integer(o);
            }
            if (f.opcode) |op| {
                try jw.comma();
                try jw.key("opcode");
                try jw.string(op);
            }
            if (f.path) |p| {
                try jw.comma();
                try jw.key("path");
                try jw.string(p);
            }
            try jw.endObject();
        }
        try jw.endArray();
    }
    try jw.comma();
    try jw.key("paths");
    if (result.paths.len == 0) {
        try jw.emptyArray();
    } else {
        try jw.beginArray();
        for (result.paths, 0..) |p, i| {
            if (i > 0) try jw.comma();
            try jw.itemNewline();
            try jw.beginObjectInline();
            try jw.key("id");
            try jw.integer(p.id);
            try jw.comma();
            try jw.key("description");
            try jw.string(p.description);
            try jw.comma();
            try jw.key("branchChoices");
            if (p.branch_choices.len == 0) {
                try jw.emptyArray();
            } else {
                try jw.beginArray();
                for (p.branch_choices, 0..) |c, j| {
                    if (j > 0) try jw.comma();
                    try jw.itemNewline();
                    try jw.boolValue(c);
                }
                try jw.endArray();
            }
            try jw.comma();
            try jw.key("reachable");
            try jw.boolValue(p.reachable);
            try jw.comma();
            try jw.key("hasCheckSig");
            try jw.boolValue(p.has_check_sig);
            try jw.comma();
            try jw.key("stackDepthAtEnd");
            try jw.integer(p.stack_depth_at_end);
            try jw.endObject();
        }
        try jw.endArray();
    }
    try jw.comma();
    try jw.key("summary");
    try jw.beginObjectInline();
    try jw.key("totalPaths");
    try jw.integer(result.summary.total_paths);
    try jw.comma();
    try jw.key("reachablePaths");
    try jw.integer(result.summary.reachable_paths);
    try jw.comma();
    try jw.key("pathsWithCheckSig");
    try jw.integer(result.summary.paths_with_check_sig);
    try jw.comma();
    try jw.key("pathsWithoutCheckSig");
    try jw.integer(result.summary.paths_without_check_sig);
    try jw.comma();
    try jw.key("maxStackDepth");
    try jw.integer(result.summary.max_stack_depth);
    try jw.comma();
    try jw.key("scriptSizeBytes");
    try jw.integer(result.summary.script_size_bytes);
    try jw.endObject();
    try jw.endObject(); // top
    try jw.writeAll("\n");
}

const JsonWriter = struct {
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    indent: u32,

    const Self = @This();

    fn writeAll(self: *Self, s: []const u8) !void {
        try self.out.appendSlice(self.allocator, s);
    }

    fn writeIndent(self: *Self) !void {
        var i: u32 = 0;
        while (i < self.indent) : (i += 1) {
            try self.out.appendSlice(self.allocator, "  ");
        }
    }

    pub fn beginObject(self: *Self) !void {
        try self.writeAll("{\n");
        self.indent += 1;
        try self.writeIndent();
    }

    pub fn beginObjectInline(self: *Self) !void {
        try self.writeAll("{\n");
        self.indent += 1;
        try self.writeIndent();
    }

    pub fn endObject(self: *Self) !void {
        self.indent -= 1;
        try self.writeAll("\n");
        try self.writeIndent();
        try self.writeAll("}");
    }

    pub fn beginArray(self: *Self) !void {
        try self.writeAll("[\n");
        self.indent += 1;
        try self.writeIndent();
    }

    pub fn endArray(self: *Self) !void {
        self.indent -= 1;
        try self.writeAll("\n");
        try self.writeIndent();
        try self.writeAll("]");
    }

    pub fn emptyArray(self: *Self) !void {
        try self.writeAll("[]");
    }

    pub fn comma(self: *Self) !void {
        try self.writeAll(",\n");
        try self.writeIndent();
    }

    pub fn itemNewline(self: *Self) !void {
        _ = self;
    }

    pub fn key(self: *Self, k: []const u8) !void {
        try self.writeAll("\"");
        try writeStringEscaped(self, k);
        try self.writeAll("\": ");
    }

    pub fn string(self: *Self, s: []const u8) !void {
        try self.writeAll("\"");
        try writeStringEscaped(self, s);
        try self.writeAll("\"");
    }

    pub fn integer(self: *Self, n: i64) !void {
        try self.out.print(self.allocator, "{d}", .{n});
    }

    pub fn boolValue(self: *Self, b: bool) !void {
        try self.writeAll(if (b) "true" else "false");
    }
};

/// Escape per RFC 8259 — matches JSON.stringify default behavior:
/// `\"`, `\\`, control chars as `\b`, `\f`, `\n`, `\r`, `\t`, others as
/// `\u00XX`. Non-ASCII UTF-8 bytes are passed through unchanged.
fn writeStringEscaped(jw: *JsonWriter, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try jw.writeAll("\\\""),
            '\\' => try jw.writeAll("\\\\"),
            0x08 => try jw.writeAll("\\b"),
            0x09 => try jw.writeAll("\\t"),
            0x0a => try jw.writeAll("\\n"),
            0x0c => try jw.writeAll("\\f"),
            0x0d => try jw.writeAll("\\r"),
            0x00...0x07, 0x0b, 0x0e...0x1f => {
                try jw.out.print(jw.allocator, "\\u{x:0>4}", .{c});
            },
            else => try jw.writeAll(&[_]u8{c}),
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────

test "analyzeScript empty input" {
    const a = std.testing.allocator;
    const r = try analyzeScript(a, "", .{});
    defer r.deinit(a);
    try std.testing.expectEqual(@as(i64, 0), r.script_size);
    try std.testing.expectEqual(@as(usize, 1), r.findings.len);
    try std.testing.expectEqual(Code.INVALID_TERMINAL_STACK, r.findings[0].code);
}

test "analyzeScript basic-p2pkh — matches golden" {
    const a = std.testing.allocator;
    const r = try analyzeScript(a, "76a90088ac", .{});
    defer r.deinit(a);
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(a);
    try writeReportJson(a, &buf, r);

    const expected =
        \\{
        \\  "script": "76a90088ac",
        \\  "scriptSize": 5,
        \\  "findings": [],
        \\  "paths": [
        \\    {
        \\      "id": 0,
        \\      "description": "linear (no branches)",
        \\      "branchChoices": [],
        \\      "reachable": true,
        \\      "hasCheckSig": true,
        \\      "stackDepthAtEnd": -1
        \\    }
        \\  ],
        \\  "summary": {
        \\    "totalPaths": 1,
        \\    "reachablePaths": 1,
        \\    "pathsWithCheckSig": 1,
        \\    "pathsWithoutCheckSig": 0,
        \\    "maxStackDepth": 0,
        \\    "scriptSizeBytes": 5
        \\  }
        \\}
        \\
    ;
    try std.testing.expectEqualStrings(expected, buf.items);
}
