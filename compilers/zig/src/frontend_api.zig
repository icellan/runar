const parse_zig = @import("passes/parse_zig.zig");
const typecheck = @import("passes/typecheck.zig");
const validate = @import("passes/validate.zig");
const input_limits = @import("frontend/input_limits.zig");

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

// R-093 — the guards the CLI's `runPipeline` applies around its parse. The Zig
// SDK's `compileCheckSource` used to call `parseZig` directly, so it applied
// neither, and answered "valid Runar" for sources the compiler refuses. These
// are re-exports, not copies: there is one input cap, one directive guard, one
// format dispatch, and now one set of callers.
//
// `parseSource` is the guarded, format-dispatching parse entry (it carries the
// fail-closed `@sighash` / `@embedAlways` refusal); `validateForFile` picks the
// validator the surface calls for; `assertSourceBytesUnderLimit` is pass 0.
pub const parseSource = compiler.parseSource;
pub const validateForFile = compiler.validateForFile;
pub const assertSourceBytesUnderLimit = input_limits.assertSourceBytesUnderLimit;
pub const MAX_SOURCE_BYTES = input_limits.MAX_SOURCE_BYTES;
pub const SourceSizeError = input_limits.SourceSizeError;
pub const SIGHASH_DIRECTIVE_ERROR = input_limits.SIGHASH_DIRECTIVE_ERROR;
pub const EMBED_ALWAYS_DIRECTIVE_ERROR = input_limits.EMBED_ALWAYS_DIRECTIVE_ERROR;
