const std = @import("std");
const types = @import("ir/types.zig");
const json_parser = @import("ir/json.zig");
const parse_zig = @import("passes/parse_zig.zig");
const parse_ts = @import("passes/parse_ts.zig");
const validate_pass = @import("passes/validate.zig");
const typecheck_pass = @import("passes/typecheck.zig");
const anf_lower = @import("passes/anf_lower.zig");
const constant_fold = @import("passes/constant_fold.zig");
const ec_optimizer = @import("passes/ec_optimizer.zig");
const stack_lower = @import("passes/stack_lower.zig");
const peephole = @import("passes/peephole.zig");
const emit = @import("codegen/emit.zig");

const CompileOptions = struct {
    emit_ir: bool = false,
    hex_only: bool = false,
    disable_constant_folding: bool = false,
};

const ParseOptionsError = error{
    UnknownFlag,
    UnsupportedFlag,
};

fn parseCompileOptions(args: []const []const u8, allow_disable_constant_folding: bool) ParseOptionsError!CompileOptions {
    var opts = CompileOptions{};
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--emit-ir")) {
            opts.emit_ir = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--hex")) {
            opts.hex_only = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--disable-constant-folding")) {
            if (!allow_disable_constant_folding) return error.UnsupportedFlag;
            opts.disable_constant_folding = true;
            continue;
        }
        return error.UnknownFlag;
    }
    return opts;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        std.process.exit(1);
    }

    const first = args[1];

    // Subcommand form
    if (std.mem.eql(u8, first, "compile-ir")) {
        if (args.len < 3) {
            std.debug.print("error: missing file argument\n", .{});
            std.process.exit(1);
        }
        const opts = parseCompileOptions(args[3..], false) catch |err| {
            const message = switch (err) {
                error.UnknownFlag => "error: unknown compile-ir flag\n",
                error.UnsupportedFlag => "error: --disable-constant-folding is only valid for source compilation\n",
            };
            std.debug.print("{s}", .{message});
            std.process.exit(1);
        };
        compileFromIR(allocator, args[2], opts) catch |err| {
            std.debug.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        return;
    }
    if (std.mem.eql(u8, first, "compile")) {
        if (args.len < 3) {
            std.debug.print("error: missing file argument\n", .{});
            std.process.exit(1);
        }
        const opts = parseCompileOptions(args[3..], true) catch |err| {
            const message = switch (err) {
                error.UnknownFlag => "error: unknown compile flag\n",
                error.UnsupportedFlag => "error: unsupported compile flag\n",
            };
            std.debug.print("{s}", .{message});
            std.process.exit(1);
        };
        compileFromSource(allocator, args[2], opts) catch |err| {
            std.debug.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        return;
    }
    if (std.mem.eql(u8, first, "--help") or std.mem.eql(u8, first, "-h")) {
        printUsage();
        return;
    }

    // Flag form: --source <file> [--emit-ir] [--hex] [--disable-constant-folding]
    if (std.mem.eql(u8, first, "--source")) {
        if (args.len < 3) {
            std.debug.print("error: --source requires a file path\n", .{});
            std.process.exit(1);
        }
        const file_path = args[2];
        const opts = parseCompileOptions(args[3..], true) catch |err| {
            const message = switch (err) {
                error.UnknownFlag => "error: unknown source flag\n",
                error.UnsupportedFlag => "error: unsupported source flag\n",
            };
            std.debug.print("{s}", .{message});
            std.process.exit(1);
        };
        const format = detectFormat(file_path);
        const result = if (format == .anf_json)
            compileFromIR(allocator, file_path, opts)
        else
            compileFromSource(allocator, file_path, opts);
        result catch |err| {
            std.debug.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        return;
    }

    std.debug.print("Unknown command: {s}\n", .{first});
    printUsage();
    std.process.exit(1);
}

const FileFormat = enum { runar_zig, runar_ts, anf_json, unknown };

fn detectFormat(path: []const u8) FileFormat {
    if (std.mem.endsWith(u8, path, ".runar.zig")) return .runar_zig;
    if (std.mem.endsWith(u8, path, ".runar.ts")) return .runar_ts;
    if (std.mem.endsWith(u8, path, ".json")) return .anf_json;
    return .unknown;
}

fn printUsage() void {
    std.debug.print(
        \\Usage: runar-zig <command> [options]
        \\
        \\Commands:
        \\  compile <file> [flags]    Full pipeline: source -> Bitcoin Script
        \\  compile-ir <file>         IR consumer: ANF IR JSON -> Bitcoin Script
        \\  --source <file> [flags]   Flag mode (conformance runner compatible)
        \\  --help, -h                Show this help
        \\
        \\Flags:
        \\  --emit-ir                 Output canonical ANF IR JSON (stop after pass 4)
        \\  --hex                     Output script hex only (no artifact JSON)
        \\  --disable-constant-folding  Skip constant folding pass
        \\
        \\Formats: .runar.zig, .runar.ts, .json
        \\
    , .{});
}

/// Compile from ANF IR JSON (passes 5-6 only)
fn compileFromIR(allocator: std.mem.Allocator, path: []const u8, opts: CompileOptions) !void {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const source = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(source);

    const program = try json_parser.parseANFProgram(allocator, source);
    defer program.deinit(allocator);

    if (opts.emit_ir) {
        const canonical = try json_parser.serializeCanonicalJSON(allocator, program);
        defer allocator.free(canonical);
        const stdout = std.fs.File.stdout();
        try stdout.writeAll(canonical);
        return;
    }

    const stack_program = try stack_lower.lower(allocator, program);
    defer stack_program.deinit(allocator);
    const optimized_methods = try peephole.optimize(allocator, stack_program.methods);
    const optimized_stack_program = types.StackProgram{
        .methods = optimized_methods,
        .contract_name = stack_program.contract_name,
        .properties = stack_program.properties,
        .constructor_params = stack_program.constructor_params,
    };

    if (opts.hex_only) {
        const stdout = std.fs.File.stdout();
        for (optimized_stack_program.methods) |method| {
            const hex = try emit.emitMethodScript(allocator, method.instructions);
            defer allocator.free(hex);
            try stdout.writeAll(hex);
            try stdout.writeAll("\n");
        }
        return;
    }

    const artifact = try emit.emitArtifact(allocator, optimized_stack_program, program);
    defer allocator.free(artifact);
    const stdout = std.fs.File.stdout();
    try stdout.writeAll(artifact);
    try stdout.writeAll("\n");
}

/// Full pipeline: source -> parse -> validate -> typecheck -> ANF -> stack -> emit
fn compileFromSource(allocator: std.mem.Allocator, path: []const u8, opts: CompileOptions) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const work_allocator = arena.allocator();

    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const source = try file.readToEndAlloc(work_allocator, 1 * 1024 * 1024);

    const format = detectFormat(path);

    // Pass 1: Parse (dispatch by format, extract contract or fail)
    const contract: types.ContractNode = switch (format) {
        .runar_zig => blk: {
            const r = parse_zig.parseZig(work_allocator, source, path);
            if (r.errors.len > 0) {
                for (r.errors) |err| std.debug.print("  parse error: {s}\n", .{err});
                return error.ParseFailed;
            }
            break :blk r.contract orelse return error.ParseFailed;
        },
        .runar_ts => blk: {
            const r = parse_ts.parseTs(work_allocator, source, path);
            if (r.errors.len > 0) {
                for (r.errors) |err| std.debug.print("  parse error: {s}\n", .{err});
                return error.ParseFailed;
            }
            break :blk r.contract orelse return error.ParseFailed;
        },
        else => {
            std.debug.print("error: unsupported format for {s}\n", .{path});
            return error.UnsupportedFormat;
        },
    };

    // Pass 2: Validate
    const val_result = try validate_pass.validate(work_allocator, contract);
    if (val_result.errors.len > 0) {
        for (val_result.errors) |diag| std.debug.print("  validation error: {s}\n", .{diag.message});
        return error.ValidationFailed;
    }
    for (val_result.warnings) |diag| std.debug.print("  warning: {s}\n", .{diag.message});

    // Pass 3: Typecheck
    const tc_result = try typecheck_pass.typeCheck(work_allocator, contract);
    if (tc_result.errors.len > 0) {
        for (tc_result.errors) |err| std.debug.print("  type error: {s}\n", .{err});
        return error.TypeCheckFailed;
    }

    // Pass 4: ANF Lower
    var program = try anf_lower.lowerToANF(work_allocator, contract);

    // Pass 4.25: Constant Fold
    if (!opts.disable_constant_folding) {
        program = try constant_fold.foldConstants(work_allocator, program);
    }

    // Pass 4.5: EC Optimize
    program = try ec_optimizer.optimize(work_allocator, program);

    // --emit-ir: output canonical ANF IR JSON and stop
    if (opts.emit_ir) {
        const canonical = try json_parser.serializeCanonicalJSON(work_allocator, program);
        const stdout = std.fs.File.stdout();
        try stdout.writeAll(canonical);
        return;
    }

    // Pass 5: Stack Lower
    const stack_program = try stack_lower.lower(work_allocator, program);
    defer stack_program.deinit(work_allocator);
    const optimized_methods = try peephole.optimize(work_allocator, stack_program.methods);
    const optimized_stack_program = types.StackProgram{
        .methods = optimized_methods,
        .contract_name = stack_program.contract_name,
        .properties = stack_program.properties,
        .constructor_params = stack_program.constructor_params,
    };

    // --hex: output hex script only
    if (opts.hex_only) {
        const stdout = std.fs.File.stdout();
        for (optimized_stack_program.methods) |method| {
            const hex = try emit.emitMethodScript(work_allocator, method.instructions);
            try stdout.writeAll(hex);
            try stdout.writeAll("\n");
        }
        return;
    }

    // Pass 6: Emit full artifact
    const artifact = try emit.emitArtifact(work_allocator, optimized_stack_program, program);

    const stdout = std.fs.File.stdout();
    try stdout.writeAll(artifact);
    try stdout.writeAll("\n");

    std.debug.print("Compiled: {s}\n", .{path});
}

const UnsupportedFormat = error{UnsupportedFormat};
const ParseFailed = error{ParseFailed};
const ValidationFailed = error{ValidationFailed};
const TypeCheckFailed = error{TypeCheckFailed};
