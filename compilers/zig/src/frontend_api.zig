const parse_zig = @import("passes/parse_zig.zig");
const typecheck = @import("passes/typecheck.zig");
const validate = @import("passes/validate.zig");

pub const parseZig = parse_zig.parseZig;
pub const ParseResult = parse_zig.ParseResult;

pub const validateContract = validate.validateZig;
pub const ValidationResult = validate.ValidationResult;

pub const typeCheck = typecheck.typeCheck;
pub const TypeCheckResult = typecheck.TypeCheckResult;

const compiler = @import("compiler_api.zig");
pub const compileSource = compiler.compileSource;
pub const compileSourceToHex = compiler.compileSourceToHex;
pub const CompileResult = compiler.CompileResult;
pub const CompileError = compiler.CompileError;
