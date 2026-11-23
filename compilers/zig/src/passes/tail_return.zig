const types = @import("../ir/types.zig");

/// N-511: on the surfaces whose trailing expression IS the value (.runar.move
/// with a declared return type, .runar.rb private helpers) the trailing
/// expression statement becomes an explicit return, recursively through the
/// arms of a trailing if/else (`if c { x } else { 0 }`) when `into_arms`. The
/// return keeps the expression statement's own source location, so the
/// lowered ANF is unchanged; the type checker needs no tail-value heuristic.
pub fn promoteTailReturns(stmts: []types.Statement, into_arms: bool) void {
    if (stmts.len == 0) return;
    const last = &stmts[stmts.len - 1];
    switch (last.*) {
        .expr_stmt => |e| {
            last.* = .{ .return_stmt = .{ .value = e.expr, .source_loc = e.source_loc } };
        },
        .if_stmt => |f| if (into_arms) {
            if (f.else_body) |else_body| {
                promoteTailReturns(f.then_body, true);
                promoteTailReturns(else_body, true);
            }
        },
        else => {},
    }
}

/// N-511: whether a `return <value>` appears anywhere in the list.
pub fn hasValueReturn(stmts: []const types.Statement) bool {
    for (stmts) |st| {
        switch (st) {
            .return_stmt => |r| if (r.value != null) return true,
            .if_stmt => |f| {
                if (hasValueReturn(f.then_body)) return true;
                if (f.else_body) |else_body| if (hasValueReturn(else_body)) return true;
            },
            .for_stmt => |f| if (hasValueReturn(f.body)) return true,
            else => {},
        }
    }
    return false;
}
