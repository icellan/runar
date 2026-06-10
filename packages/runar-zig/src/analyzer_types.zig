// Shared types for the Bitcoin Script static analyzer.
//
// Spec: spec/script-analyzer-format.md
// Cross-tier byte-identical JSON output is required.

const std = @import("std");

pub const Severity = enum {
    error_,
    warning,
    info,

    pub fn rank(self: Severity) u8 {
        return switch (self) {
            .error_ => 0,
            .warning => 1,
            .info => 2,
        };
    }

    pub fn name(self: Severity) []const u8 {
        return switch (self) {
            .error_ => "error",
            .warning => "warning",
            .info => "info",
        };
    }
};

/// Stable analyzer finding code (spec §5).
pub const Code = enum {
    STACK_UNDERFLOW,
    INVALID_TERMINAL_STACK,
    UNBALANCED_IF_ENDIF,
    INCONSISTENT_BRANCH_DEPTH,
    UNREACHABLE_AFTER_RETURN,
    UNCONDITIONALLY_SUCCEEDS,
    NO_SIG_CHECK,
    CHECKSIG_RESULT_DROPPED,
    CODESEPARATOR_PRESENT,
    INEFFICIENT_PUSH,
    LARGE_SCRIPT,
    PATHS_TRUNCATED,

    pub fn severity(self: Code) Severity {
        return switch (self) {
            .STACK_UNDERFLOW => .error_,
            .INVALID_TERMINAL_STACK => .error_,
            .UNBALANCED_IF_ENDIF => .error_,
            .INCONSISTENT_BRANCH_DEPTH => .warning,
            .UNREACHABLE_AFTER_RETURN => .warning,
            .UNCONDITIONALLY_SUCCEEDS => .warning,
            .NO_SIG_CHECK => .warning,
            .CHECKSIG_RESULT_DROPPED => .warning,
            .CODESEPARATOR_PRESENT => .info,
            .INEFFICIENT_PUSH => .info,
            .LARGE_SCRIPT => .info,
            .PATHS_TRUNCATED => .warning,
        };
    }

    pub fn name(self: Code) []const u8 {
        return @tagName(self);
    }
};

/// A single analyzer finding. Owned strings are allocated by the
/// finding's producer and freed via `Finding.deinit`.
pub const Finding = struct {
    severity: Severity,
    code: Code,
    /// Owned (allocator) — the canonical message text.
    message: []const u8,
    offset: ?i64 = null,
    /// Owned (allocator) — optional opcode name.
    opcode: ?[]const u8 = null,
    /// Owned (allocator) — optional path descriptor.
    path: ?[]const u8 = null,

    pub fn deinit(self: Finding, allocator: std.mem.Allocator) void {
        allocator.free(self.message);
        if (self.opcode) |s| allocator.free(s);
        if (self.path) |s| allocator.free(s);
    }
};

/// A single decoded opcode.
///
/// `opcode == -1` marks the synthetic raw-span step (spec §6).
pub const Opcode = struct {
    /// Raw byte (0..255) or -1 for synthetic raw-span steps.
    opcode: i32,
    /// Canonical name (owned).
    name: []const u8,
    /// Byte offset of the opcode in the script.
    offset: i64,
    /// Total byte size in the script (opcode byte + length prefix + data).
    size: i64,
    /// For push operations, the length of the data payload.
    data_length: ?i64 = null,
    /// Push encoding kind, if applicable.
    push_encoding: PushEncoding = .none,
    /// For raw-span steps, the (inArity, outArity) pair.
    raw_span_arity: ?[2]i32 = null,

    pub fn deinit(self: Opcode, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
    }
};

pub const PushEncoding = enum {
    none,
    direct,
    pushdata1,
    pushdata2,
    pushdata4,
    op_n,
};

pub const ExecutionPath = struct {
    id: i32,
    /// Owned (allocator).
    description: []const u8,
    /// Owned slice of booleans (one per IF/NOTIF in source order).
    branch_choices: []const bool,
    reachable: bool,
    has_check_sig: bool,
    stack_depth_at_end: i64,

    pub fn deinit(self: ExecutionPath, allocator: std.mem.Allocator) void {
        allocator.free(self.description);
        allocator.free(self.branch_choices);
    }
};

pub const Summary = struct {
    total_paths: i32,
    reachable_paths: i32,
    paths_with_check_sig: i32,
    paths_without_check_sig: i32,
    max_stack_depth: i64,
    script_size_bytes: i64,
};

pub const AnalysisResult = struct {
    /// Owned (allocator) — normalized lowercase hex script.
    script: []const u8,
    script_size: i64,
    /// Owned slice (caller-allocator). Each Finding owns its own strings.
    findings: []Finding,
    /// Owned slice (caller-allocator). Each path owns its own strings.
    paths: []ExecutionPath,
    summary: Summary,

    pub fn deinit(self: AnalysisResult, allocator: std.mem.Allocator) void {
        allocator.free(self.script);
        for (self.findings) |f| f.deinit(allocator);
        allocator.free(self.findings);
        for (self.paths) |p| p.deinit(allocator);
        allocator.free(self.paths);
    }
};

pub const RawScriptSpan = struct {
    offset: i64,
    length: i64,
    in_arity: i32,
    out_arity: i32,
};
