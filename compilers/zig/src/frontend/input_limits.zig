// DoS-bound input limits + typed errors for the Zig frontend.
//
// Mirrors InputLimits from packages/runar-ir-schema/src/input-limits.ts.
// See compilers/go/frontend/input_limits.go for the reference shape.

const std = @import("std");
const types = @import("../ir/types.zig");

/// Mirrors `InputLimits.MAX_SOURCE_BYTES` (4 MiB) from the TS schema package.
/// Rúnar source files larger than this are rejected at the public entry
/// point (compileSource) BEFORE the tokenizer touches the input.
/// BUG-008 follow-up.
pub const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;

/// Mirrors `InputLimits.MAX_SOURCE_NESTING` (128) from
/// packages/runar-ir-schema/src/input-limits.ts, which defines the two
/// measures it bounds (F-213): (A) parse nesting, counted by every surface
/// parser through `NestingCounter`, and (B) AST nesting, checked on the parsed
/// tree by `contractNestingViolation`. MAX_SOURCE_BYTES never bounded
/// recursion: a 5,000-term `a + a + ...` chain is 40 KB and used to SIGABRT
/// this CLI.
pub const MAX_SOURCE_NESTING: u32 = 128;

/// The one diagnostic every tier emits for an over-nested source.
pub const SOURCE_NESTING_MESSAGE = std.fmt.comptimePrint(
    "source nesting depth exceeds MAX_SOURCE_NESTING (limit={d})",
    .{MAX_SOURCE_NESTING},
);

/// Mirrors `InputLimits.MAX_CALL_DEPTH` (128) from
/// packages/runar-ir-schema/src/input-limits.ts (N-180). The call depth of a
/// method is 0 if it calls no contract method, else 1 + the largest call depth
/// among the contract methods it calls. Private methods are inlined at every
/// call site, so this is the inlining depth; the validator refuses a method
/// that does not reach a call cycle and sits deeper than this, naming the first
/// such method in declaration order with `CALL_DEPTH_MESSAGE_FMT`.
pub const MAX_CALL_DEPTH: usize = 128;

/// The one diagnostic every tier emits for a call chain past MAX_CALL_DEPTH
/// (format string; the one argument is the method name).
pub const CALL_DEPTH_MESSAGE_FMT = "call depth of method '{s}' exceeds MAX_CALL_DEPTH (limit=" ++
    std.fmt.comptimePrint("{d}", .{MAX_CALL_DEPTH}) ++ ")";

/// Typed error set for source-size rejection. Distinct from generic
/// ParseFailed so callers can distinguish DoS-bound rejection.
pub const SourceSizeError = error{SourceSizeExceeded};

/// Returns SourceSizeError.SourceSizeExceeded if source.len > MAX_SOURCE_BYTES,
/// void otherwise.
pub fn assertSourceBytesUnderLimit(source: []const u8) SourceSizeError!void {
    if (source.len > MAX_SOURCE_BYTES) {
        return SourceSizeError.SourceSizeExceeded;
    }
}

// ---------------------------------------------------------------------------
// Fail-closed guard for author-facing comment directives that the Zig frontend
// honours ONLY on the `.runar.ts` surface (matching the TS reference compiler,
// which implements them only there): `@sighash <FLAGS>` (#123, per-method
// sighash type) and `@embedAlways` (#109, readonly-field DCE opt-out). The
// eight non-TS surface parsers ignore comments, so silently dropping a
// directive would change signing / DCE semantics — those formats reject rather
// than diverge. The `.runar.ts` parse path is exempt (it implements the
// directives) — the guard callers narrow accordingly.
// ---------------------------------------------------------------------------

/// The `@sighash` refusal for the non-TS surface named `surface` ("Solidity",
/// "Move", "Python", "Go DSL", "Rust", "Ruby", "Zig", "Java"). Identical text
/// in all seven tiers (N-244). Detection is a plain substring match on
/// `@sighash` (see `compiler_api.parseSource`), NOT `containsDirectiveToken`:
/// N-039 made every occurrence of the marker a directive, so a glued
/// `@sighashSINGLE|FORKID` is refused rather than read as prose.
pub fn sighashDirectiveError(comptime surface: []const u8) []const u8 {
    return "@sighash directive (issue #123) is not supported by the " ++ surface ++ " surface parser; write the contract in TypeScript (.runar.ts) where @sighash is honoured";
}
pub const EMBED_ALWAYS_DIRECTIVE_ERROR = "@embedAlways directive (issue #109) is only honoured on the TypeScript (.runar.ts) surface; write the contract in .runar.ts where @embedAlways is implemented";

fn isWordByte(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or c == '_';
}

/// True when `marker` (which begins with a non-word `@`) appears in `source`
/// followed by a word boundary — i.e. the next byte is not `[A-Za-z0-9_]`.
/// Mirrors the TypeScript compiler's `/@embedAlways\b/` scan. NOT used for the
/// non-TS `@sighash` guard, which matches any occurrence of `@sighash`, glued
/// or not (N-244; see `compiler_api.parseSource`).
pub fn containsDirectiveToken(source: []const u8, marker: []const u8) bool {
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, source, i, marker)) |pos| {
        const after = pos + marker.len;
        if (after >= source.len or !isWordByte(source[after])) return true;
        i = pos + 1;
    }
    return false;
}


// ---------------------------------------------------------------------------
// N-136: the size guard above (`assertSourceBytesUnderLimit`) was reachable
// only through `runPipeline`'s Pass 0. `compiler_api.parseSource` (the
// format-dispatching entry) and every one of the nine per-format
// `passes/parse_*.zig` functions it dispatches to are `pub fn` and
// re-exported (directly, for `parseZig`; via `parseSource`, for the rest) by
// `frontend_api.zig` for the Zig SDK's direct use — so a caller reaching any
// of those ten entries without going through `runPipeline` got no DoS-bound
// rejection at all. Each entry now calls `sourceSizeGuardErrors` first.
// ---------------------------------------------------------------------------

var source_size_exceeded_fallback = [_][]const u8{"source exceeds MAX_SOURCE_BYTES"};

/// The size-guard refusal text, shared by `sourceSizeGuardErrors` and the CLI,
/// which refuses an over-cap file while reading it (main.zig) and so never
/// holds the whole source to hand to the guard.
pub fn sourceSizeExceededMessage(allocator: std.mem.Allocator, actual: u64) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "source exceeds MAX_SOURCE_BYTES (limit={d}, actual={d})",
        .{ MAX_SOURCE_BYTES, actual },
    );
}

/// Returns an allocated one-element `[][]const u8` carrying the DoS-bound
/// size-exceeded diagnostic when `source` exceeds `MAX_SOURCE_BYTES`, or
/// `null` when it is within bounds (strictly: `source.len <=
/// MAX_SOURCE_BYTES` is accepted, matching `assertSourceBytesUnderLimit`).
pub fn sourceSizeGuardErrors(allocator: std.mem.Allocator, source: []const u8) ?[][]const u8 {
    if (source.len <= MAX_SOURCE_BYTES) return null;
    const text = sourceSizeExceededMessage(allocator, source.len) catch return source_size_exceeded_fallback[0..];
    const out = allocator.alloc([]const u8, 1) catch return source_size_exceeded_fallback[0..];
    out[0] = text;
    return out;
}

// ---------------------------------------------------------------------------
// F-213: source nesting limit (see MAX_SOURCE_NESTING above)
// ---------------------------------------------------------------------------

/// Measure (A): the parse-nesting counter. A parser enters one level per
/// statement, per full-expression parse, per prefix-unary operand, per other
/// self-recursion and per nested type argument, and leaves it on return.
/// `enter` refuses (returns false) once a level would exceed the limit, and
/// keeps refusing after that, so a parser's recursion never gets deeper than
/// MAX_SOURCE_NESTING counted frames.
pub const NestingCounter = struct {
    depth: u32 = 0,
    exceeded: bool = false,

    /// Enter one level; false when that would exceed the limit (the caller
    /// must then NOT call `exit`).
    pub fn enter(self: *NestingCounter) bool {
        if (self.exceeded) return false;
        if (self.depth >= MAX_SOURCE_NESTING) {
            self.exceeded = true;
            return false;
        }
        self.depth += 1;
        return true;
    }

    pub fn exit(self: *NestingCounter) void {
        self.depth -= 1;
    }
};

/// `file:line:col: <SOURCE_NESTING_MESSAGE>`, in the parsers' diagnostic shape.
/// `col` is 1-based (the AST / tokenizer convention); the printed column is
/// 0-based (N-078, R88a).
pub fn nestingErrorAt(allocator: std.mem.Allocator, file_name: []const u8, line: u32, col: u32) []const u8 {
    const printed = if (col > 0) col - 1 else 0;
    return std.fmt.allocPrint(allocator, "{s}:{d}:{d}: {s}", .{ file_name, line, printed, SOURCE_NESTING_MESSAGE }) catch SOURCE_NESTING_MESSAGE;
}

fn nestingErrorAtLoc(allocator: std.mem.Allocator, file_name: []const u8, loc: ?types.SourceLocation) []const u8 {
    if (loc) |l| return nestingErrorAt(allocator, file_name, l.line, l.column);
    return SOURCE_NESTING_MESSAGE;
}

var source_nesting_fallback = [_][]const u8{SOURCE_NESTING_MESSAGE};

fn oneError(allocator: std.mem.Allocator, msg: []const u8) [][]const u8 {
    const out = allocator.alloc([]const u8, 1) catch return source_nesting_fallback[0..];
    out[0] = msg;
    return out;
}

/// The single-diagnostic error list a parser entry returns when the source is
/// over-nested, or null. `parse_error` is the (A) diagnostic the parser
/// recorded, if it tripped; otherwise measure (B) is checked on `contract`.
/// Every per-format `parse*` entry calls this right after its parser returns,
/// before validate / typecheck / expand / ANF can recurse on the tree.
pub fn nestingGuardErrors(
    allocator: std.mem.Allocator,
    parse_error: ?[]const u8,
    contract: ?types.ContractNode,
    file_name: []const u8,
) ?[][]const u8 {
    if (parse_error) |msg| return oneError(allocator, msg);
    const c = contract orelse return null;
    const v = contractNestingViolation(c) orelse return null;
    return oneError(allocator, nestingErrorAtLoc(allocator, file_name, v.loc));
}

/// Where measure (B) found the contract too deep (the location may be null
/// when the offending node carries none).
pub const NestingViolation = struct { loc: ?types.SourceLocation };

/// True iff some node of `e`, sitting at nesting `level`, is deeper than the
/// limit. exprDepth(leaf) = 1, a node is one deeper than its deepest child.
/// The callee of a call is a leaf child, a method call's `object.method`
/// callee is two deep, mirroring the TS AST's `call_expr.callee`. Recursion
/// stops as soon as `level` passes the limit, so it never goes deeper than
/// MAX_SOURCE_NESTING + 1 frames on any tree.
pub fn exprTooDeep(e: types.Expression, level: u32) bool {
    if (level > MAX_SOURCE_NESTING) return true;
    const next = level + 1;
    switch (e) {
        .binary_op => |b| return exprTooDeep(b.left, next) or exprTooDeep(b.right, next),
        .unary_op => |u| return exprTooDeep(u.operand, next),
        .call => |c| {
            if (next > MAX_SOURCE_NESTING) return true;
            for (c.args) |a| if (exprTooDeep(a, next)) return true;
            return false;
        },
        .method_call => |m| {
            if (next + 1 > MAX_SOURCE_NESTING) return true;
            for (m.args) |a| if (exprTooDeep(a, next)) return true;
            return false;
        },
        .ternary => |t| return exprTooDeep(t.condition, next) or exprTooDeep(t.then_expr, next) or exprTooDeep(t.else_expr, next),
        .index_access => |ia| return exprTooDeep(ia.object, next) or exprTooDeep(ia.index, next),
        .increment => |inc| return exprTooDeep(inc.operand, next),
        .decrement => |dec| return exprTooDeep(dec.operand, next),
        .array_literal => |elems| {
            for (elems) |el| if (exprTooDeep(el, next)) return true;
            return false;
        },
        .literal_int, .literal_bool, .literal_bytes, .identifier, .literal_bigint, .property_access => return false,
    }
}

fn stmtLoc(st: types.Statement) ?types.SourceLocation {
    return switch (st) {
        .const_decl => |d| d.source_loc,
        .let_decl => |d| d.source_loc,
        .assign => |a| a.source_loc,
        .if_stmt => |i| i.source_loc,
        .for_stmt => |f| f.source_loc,
        .expr_stmt => |e| e.source_loc,
        .assert_stmt => |a| a.source_loc,
        .return_stmt => null,
    };
}

/// Measure (B) over a statement list whose statements sit at `level` (a body's
/// top level is 1; an if's branches and a loop's body and update are one
/// deeper than the statement). An expression slot of a statement at level k
/// starts at level k + 1. `assert_stmt` is the TS AST's `assert(cond)` call
/// statement, so its condition sits one deeper again. Returns the offending
/// statement, or null. Recursion is bounded by the early exit at the limit.
pub fn stmtsTooDeep(stmts: []const types.Statement, level: u32) ?types.Statement {
    for (stmts) |st| {
        if (level > MAX_SOURCE_NESTING) return st;
        const slot = level + 1;
        const bad = switch (st) {
            .const_decl => |d| exprTooDeep(d.value, slot),
            .let_decl => |d| if (d.value) |v| exprTooDeep(v, slot) else false,
            .assign => |a| blk: {
                if (a.index_target) |ia| {
                    if (exprTooDeep(.{ .index_access = ia }, slot)) break :blk true;
                } else if (slot > MAX_SOURCE_NESTING) break :blk true;
                break :blk exprTooDeep(a.value, slot);
            },
            .expr_stmt => |e| exprTooDeep(e.expr, slot),
            .assert_stmt => |a| slot + 1 > MAX_SOURCE_NESTING or exprTooDeep(a.condition, slot + 1),
            .return_stmt => |v| if (v) |e| exprTooDeep(e, slot) else false,
            .if_stmt => |i| blk: {
                if (exprTooDeep(i.condition, slot)) break :blk true;
                if (stmtsTooDeep(i.then_body, slot)) |inner| return inner;
                if (i.else_body) |eb| if (stmtsTooDeep(eb, slot)) |inner| return inner;
                break :blk false;
            },
            .for_stmt => |f| blk: {
                if (f.update) |u| if (stmtsTooDeep(u[0..1], slot)) |inner| return inner;
                if (stmtsTooDeep(f.body, slot)) |inner| return inner;
                break :blk false;
            },
        };
        if (bad) return st;
    }
    return null;
}

/// Measure (B) for one property initializer (a property sits at level 0).
pub fn propertyTooDeep(p: types.PropertyNode) bool {
    if (p.initializer) |init| return exprTooDeep(init, 1);
    return false;
}

/// Measure (B) for a method / constructor body; null when within the limit.
pub fn bodyNestingViolation(body: []const types.Statement, fallback: ?types.SourceLocation) ?NestingViolation {
    const bad = stmtsTooDeep(body, 1) orelse return null;
    return .{ .loc = stmtLoc(bad) orelse fallback };
}

/// Measure (B) over the members a parser has collected so far, for the
/// parsers that run a recursive pass of their own (an identifier rewrite, a
/// property resolution) before handing the contract back: they call this
/// first, so that pass never walks an over-deep tree.
pub fn membersTooDeep(properties: []const types.PropertyNode, methods: []const types.MethodNode) bool {
    for (properties) |p| if (propertyTooDeep(p)) return true;
    for (methods) |m| if (stmtsTooDeep(m.body, 1) != null) return true;
    return false;
}

/// Measure (B) over a whole contract: property initializers, the constructor
/// (its `super(...)` call is a level-1 statement, so each argument sits at
/// level 3) and every method body. Type nesting needs no check here: this AST
/// keeps no `TypeNode` past the parser (properties and parameters carry only
/// a collapsed `RunarType`), and every recursive type parse is a counted (A)
/// site.
pub fn contractNestingViolation(c: types.ContractNode) ?NestingViolation {
    for (c.properties) |p| {
        if (propertyTooDeep(p)) return .{ .loc = p.source_loc };
    }
    for (c.constructor.super_args) |a| {
        if (exprTooDeep(a, 3)) return .{ .loc = null };
    }
    for (c.constructor.assignments) |a| {
        if (exprTooDeep(a.value, 2)) return .{ .loc = null };
    }
    if (bodyNestingViolation(c.constructor.body, null)) |v| return v;
    for (c.methods) |m| {
        if (bodyNestingViolation(m.body, m.source_loc)) |v| return v;
    }
    return null;
}
