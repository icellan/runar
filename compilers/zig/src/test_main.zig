test {
    _ = @import("ir/types.zig");
    _ = @import("ir/json.zig");
    _ = @import("codegen/opcodes.zig");
    _ = @import("codegen/emit.zig");
    _ = @import("passes/stack_lower.zig");
    _ = @import("passes/peephole.zig");
    _ = @import("passes/parse_zig.zig");
    _ = @import("passes/parse_ts.zig");
    _ = @import("passes/validate.zig");
    _ = @import("passes/typecheck.zig");
    _ = @import("passes/anf_lower.zig");
    _ = @import("passes/constant_fold.zig");
    _ = @import("passes/ec_optimizer.zig");
    _ = @import("tests/e2e.zig");
    _ = @import("compiler_api.zig");
}
