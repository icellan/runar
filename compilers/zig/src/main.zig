const std = @import("std");
const types = @import("ir/types.zig");
const json_parser = @import("ir/json.zig");
const stack_lower = @import("passes/stack_lower.zig");
const peephole = @import("passes/peephole.zig");
const ec_optimizer = @import("passes/ec_optimizer.zig");
const emit = @import("codegen/emit.zig");
const compiler_api = @import("compiler_api.zig");
const input_limits = @import("frontend/input_limits.zig");

const CompileOptions = struct {
    emit_ir: bool = false,
    hex_only: bool = false,
    disable_constant_folding: bool = false,
    parse_only: bool = false,
    emit_source_map_path: ?[]const u8 = null,
    /// `--emit-ir-to <path>`: write the SAME bytes `--emit-ir` would print to
    /// this file and then CONTINUE compiling, so one process yields both the
    /// ANF IR and the script hex. The conformance runner drives every tier with
    /// `--source X --hex --emit-ir-to Y` to avoid a second parse+compile of the
    /// same source (audit finding #17).
    emit_ir_to_path: ?[]const u8 = null,
};

const ParseOptionsError = error{
    UnknownFlag,
    UnsupportedFlag,
    MissingFlagValue,
    /// N-220: a second input (`--source` / `--ir`) after the first one.
    ConflictingInputs,
};

fn parseCompileOptions(args: []const []const u8, allow_disable_constant_folding: bool) ParseOptionsError!CompileOptions {
    var opts = CompileOptions{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        // N-220: the input file is already fixed by the subcommand / first
        // flag, so another --source or --ir is a second input mode. Go F-183
        // and Ruby F-335 refuse this; we used to answer "unknown flag".
        if (std.mem.eql(u8, arg, "--source") or std.mem.eql(u8, arg, "--ir")) {
            return error.ConflictingInputs;
        }
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
        if (std.mem.eql(u8, arg, "--parse-only")) {
            opts.parse_only = true;
            continue;
        }
        // --emit-source-map <PATH> writes the artifact's sourceMap field as
        // canonical {"mappings":[...]} JSON to the specified path.
        if (std.mem.eql(u8, arg, "--emit-source-map")) {
            if (i + 1 >= args.len) return error.MissingFlagValue;
            i += 1;
            opts.emit_source_map_path = args[i];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--emit-source-map=")) {
            opts.emit_source_map_path = arg["--emit-source-map=".len..];
            continue;
        }
        // --emit-ir-to <PATH> writes the canonical ANF IR JSON (byte-identical
        // to what --emit-ir prints) to PATH, then continues compiling.
        if (std.mem.eql(u8, arg, "--emit-ir-to")) {
            if (i + 1 >= args.len) return error.MissingFlagValue;
            i += 1;
            opts.emit_ir_to_path = args[i];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--emit-ir-to=")) {
            opts.emit_ir_to_path = arg["--emit-ir-to=".len..];
            continue;
        }
        return error.UnknownFlag;
    }
    return opts;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer args_list.deinit(allocator);
    var args_iter = std.process.Args.Iterator.init(init.minimal.args);
    while (args_iter.next()) |arg| {
        try args_list.append(allocator, arg);
    }
    const args = args_list.items;

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
                error.MissingFlagValue => "error: --emit-source-map requires a path argument\n",
                error.ConflictingInputs => "Error: --source and --ir are mutually exclusive; pass exactly one\n",
            };
            std.debug.print("{s}", .{message});
            std.process.exit(1);
        };
        compileFromIR(allocator, io, args[2], opts) catch |err| {
            printIrError(err);
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
                error.MissingFlagValue => "error: --emit-source-map requires a path argument\n",
                error.ConflictingInputs => "Error: --source and --ir are mutually exclusive; pass exactly one\n",
            };
            std.debug.print("{s}", .{message});
            std.process.exit(1);
        };
        compileFromSource(allocator, io, args[2], opts) catch |err| {
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
                error.MissingFlagValue => "error: --emit-source-map requires a path argument\n",
                error.ConflictingInputs => "Error: --source and --ir are mutually exclusive; pass exactly one\n",
            };
            std.debug.print("{s}", .{message});
            std.process.exit(1);
        };
        const format = detectFormat(file_path);
        const result = if (format == .anf_json)
            compileFromIR(allocator, io, file_path, opts)
        else
            compileFromSource(allocator, io, file_path, opts);
        result catch |err| {
            printIrError(err);
            std.process.exit(1);
        };
        return;
    }

    std.debug.print("Unknown command: {s}\n", .{first});
    printUsage();
    std.process.exit(1);
}

const FileFormat = enum { runar_zig, runar_ts, runar_sol, runar_move, runar_go, runar_rs, runar_py, runar_rb, runar_java, anf_json, unknown };

fn detectFormat(path: []const u8) FileFormat {
    if (std.mem.endsWith(u8, path, ".runar.zig")) return .runar_zig;
    if (std.mem.endsWith(u8, path, ".runar.ts")) return .runar_ts;
    if (std.mem.endsWith(u8, path, ".runar.sol")) return .runar_sol;
    if (std.mem.endsWith(u8, path, ".runar.move")) return .runar_move;
    if (std.mem.endsWith(u8, path, ".runar.go")) return .runar_go;
    if (std.mem.endsWith(u8, path, ".runar.rs")) return .runar_rs;
    if (std.mem.endsWith(u8, path, ".runar.py")) return .runar_py;
    if (std.mem.endsWith(u8, path, ".runar.rb")) return .runar_rb;
    if (std.mem.endsWith(u8, path, ".runar.java")) return .runar_java;
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
        \\Formats: .runar.zig, .runar.ts, .runar.sol, .runar.move, .runar.go, .runar.rs, .runar.py, .runar.rb, .runar.java, .json
        \\
    , .{});
}

fn writeStdout(io: std.Io, data: []const u8) !void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    try w.interface.writeAll(data);
    try w.interface.flush();
}

fn writeStdoutLn(io: std.Io, data: []const u8) !void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    try w.interface.writeAll(data);
    try w.interface.writeAll("\n");
    try w.interface.flush();
}

/// Compile from ANF IR JSON (passes 5-6 only)
/// N-069: the required-field check leaves its field-path message beside the
/// error name, because Zig errors carry no payload.
fn printIrError(err: anyerror) void {
    if (err == error.IROutputDelegation) {
        std.debug.print("error: {s}\n", .{stack_lower.ir_output_delegation_error});
        return;
    }
    if (err == error.IRRequiredFieldMissing or err == error.IRFieldWrongType or err == error.IRIdentifierInvalid or err == error.PublicMethodMissingTerminalAssert or err == error.ReservedName or err == error.ParentClassRuleViolation or err == error.IllegalPropertyWrite or err == error.StatefulScaffoldMismatch or err == error.SyntheticArrayChainMalformed or err == error.RabinKeyProvenance or err == error.IRRecursionDetected or err == error.IRCallDepthExceeded) {
        if (json_parser.required_fields.lastDiagnostic()) |msg| {
            std.debug.print("error: {s}\n", .{msg});
            return;
        }
    }
    std.debug.print("error: {s}\n", .{@errorName(err)});
}

fn compileFromIR(allocator: std.mem.Allocator, io: std.Io, path: []const u8, opts: CompileOptions) !void {
    // N-119: run the whole IR pipeline in one arena, exactly as
    // `compileFromSource` below already does.
    //
    // This path used to allocate from the process allocator and hand the graph
    // back via `ANFProgram.deinit`. That does not work, and cannot be made to
    // work cheaply: `deinit`/`freeBindings` (ir/types.zig) free the `if` and
    // `loop` heap nodes and recurse into their bodies, and nothing else — not
    // the binding ARRAYS, and none of the 43 `allocator.dupe` sites in
    // ir/json.zig. On the 3.2 KB `bounded-loop` golden a successful run printed
    // 55 DebugAllocator leak reports / 1145 lines to stderr.
    //
    // Exit status and bytes were always correct, so this was hygiene — but the
    // noise shares a channel with real diagnostics and buries a one-line result
    // under a kilo-line of trace, which is how a `tail -1` measurement gets
    // read off the wrong stream.
    //
    // Completing `deinit` was the alternative and is the wrong trade: the
    // parser mixes owned dupes with borrowed slices of the still-live
    // `std.json` document across a ~25-variant union, so a uniform free turns
    // stderr noise into a double-free. The arena sidesteps ownership entirely,
    // which is why the source path chose it first; `compileFromIR` was the one
    // caller that had not.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const work_allocator = arena.allocator();

    // N-105: this used to read with `.limited(10 MiB)`, so any IR file
    // between 10 MiB and json_parser.MAX_IR_BYTES (16 MiB) failed with a bare
    // `error: StreamTooLong` before parseANFProgram's own size guard ever saw
    // it, while TS (and every other tier reading the same input) accepted it.
    // Reading up to MAX_IR_BYTES+1 lets files at or under the cap reach the
    // loader; a file actually too large for std.json's own read limit still
    // surfaces as the typed `IRSizeExceeded` diagnostic rather than a raw
    // StreamTooLong, matching the diagnostic parseANFProgram gives for an
    // in-memory oversized payload (ir/json_size_guard_test.zig).
    const source = std.Io.Dir.cwd().readFileAlloc(io, path, work_allocator, .limited(json_parser.MAX_IR_BYTES + 1)) catch |err| switch (err) {
        error.StreamTooLong => return error.IRSizeExceeded,
        else => return err,
    };

    const program = try json_parser.parseANFProgram(work_allocator, source);

    if (opts.emit_ir) {
        const canonical = try json_parser.serializeCanonicalJSON(work_allocator, program);
        try writeStdout(io, canonical);
        // N-186: honour --emit-source-map here too. Stack lowering is not
        // run (--emit-ir's contract is "stop after the IR") and an IR has no
        // source locations anyway, so the map is the empty wrapper.
        if (opts.emit_source_map_path) |sm_path| {
            try writeSourceMapToPath(work_allocator, io, "", sm_path, path);
        }
        return;
    }

    // Pass 4.5: EC Optimize. The `--ir` path used to go straight from the
    // parsed ANF to stack lowering, skipping the EC optimizer entirely — the
    // ONLY tier that did. TS, Go, Rust, Python, Ruby and Java all re-run their
    // EC optimizer over `--ir` input, so any ANF containing a rewritable EC
    // shape compiled to a different script here than in the other six. Found by
    // R-034: `ecAdd(x, ecNegate(x))` fed through `--ir` emitted 26141 bytes of
    // ladder in Zig and 1808 bytes everywhere else. That is a 6-vs-1 hex
    // divergence covering every rule in optimizer/ec-rules.json, not just the
    // one R-034 was filed for.
    //
    // Byte-neutral for the conformance `--ir-parity` gate: no checked-in
    // `expected-ir.json` contains a shape any EC rule rewrites (verified over
    // all 5 fixtures whose IR mentions ecAdd/ecMul/ecMulGen/ecNegate), which is
    // precisely why the divergence went unnoticed.
    //
    // The optimizer's output shares unmodified nodes with `program`. Both now
    // live in the function-wide arena (N-119), so the sharing needs no separate
    // lifetime argument — previously this call had its own nested arena and
    // relied on `program` outliving it via a `defer program.deinit`.
    const optimized_program = try ec_optimizer.optimize(work_allocator, program);

    const stack_program = try stack_lower.lower(work_allocator, optimized_program);
    const optimized_methods = try peephole.optimize(work_allocator, stack_program.methods);
    const optimized_stack_program = types.StackProgram{
        .methods = optimized_methods,
        .contract_name = stack_program.contract_name,
        .properties = stack_program.properties,
        .constructor_params = stack_program.constructor_params,
    };

    // --hex: output the dispatch-table locking script (same bytes that
    // appear in the artifact's "script" field), matching compileFromSource
    // and the Go/Rust/Python/Ruby compilers. Per-method hex is not a valid
    // locking script on its own for multi-method contracts.
    const artifact = try emit.emitArtifact(work_allocator, optimized_stack_program, optimized_program);

    // --emit-source-map (N-186): this path never looked at the flag, so
    // `--source IR.json --emit-source-map Y` exited 0 with no Y. An ANF IR
    // carries no source locations, so the artifact has no sourceMap and
    // writeSourceMapToPath writes the empty {"mappings":[]} wrapper — the
    // same file the Go/Rust/Python/Ruby/Java CLIs write for an IR input.
    if (opts.emit_source_map_path) |sm_path| {
        try writeSourceMapToPath(work_allocator, io, artifact, sm_path, path);
    }

    if (opts.hex_only) {
        try writeStdoutLn(io, try compiler_api.extractArtifactScript(artifact));
        return;
    }

    try writeStdoutLn(io, artifact);
}

/// Report collected pass diagnostics on stderr. Warnings first, then errors,
/// matching the order the passes produced them in.
fn printDiagnostics(diag: *const compiler_api.Diagnostics) void {
    for (diag.warnings.items) |line| std.debug.print("{s}\n", .{line});
    for (diag.errors.items) |line| std.debug.print("{s}\n", .{line});
}

/// Full pipeline: source -> parse -> validate -> typecheck -> expand -> ANF ->
/// stack -> emit.
///
/// The pass sequence itself lives in `compiler_api.runPipeline`, which the
/// library entry point also runs, so there is ONE compiler rather than two
/// copies drifting apart (R-027: the library had lost `expand_fixed_arrays`
/// entirely). What stays here is CLI-only: reading the file, routing the
/// `.anf.json` / unknown extensions, printing diagnostics, and the output
/// modes (`--parse-only`, `--emit-ir`, `--emit-ir-to`, `--hex`,
/// `--emit-source-map`).
fn compileFromSource(allocator: std.mem.Allocator, io: std.Io, path: []const u8, opts: CompileOptions) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const work_allocator = arena.allocator();

    // Read every source the MAX_SOURCE_BYTES cap admits (`.limited(n)` accepts
    // fewer than n bytes). A larger file is refused with the library size
    // guard's diagnostic (actual size from stat, since it is never read whole)
    // and `error.SourceSizeExceeded` through the CLI's normal error path. This
    // read used to stop at 1 MiB, refusing a 1-4 MiB source the cap admits with
    // a bare `StreamTooLong`.
    const source = std.Io.Dir.cwd().readFileAlloc(io, path, work_allocator, .limited(input_limits.MAX_SOURCE_BYTES + 1)) catch |err| switch (err) {
        error.StreamTooLong => {
            const st = try std.Io.Dir.cwd().statFile(io, path, .{});
            const msg = try input_limits.sourceSizeExceededMessage(work_allocator, st.size);
            std.debug.print("  parse error: {s}\n", .{msg});
            return error.SourceSizeExceeded;
        },
        else => return err,
    };

    // Fail-closed on anything no surface parser claims. `.anf.json` is a
    // compiler *output*, so it is a mistake here too — `--source` routes it to
    // `compileFromIR` before this point, but the `compile` subcommand does not.
    // The library entry point falls back to the Zig parser for an unrecognised
    // extension; the CLI refuses, because `--source foo.txt` is a user typo
    // rather than a Zig contract.
    switch (detectFormat(path)) {
        .unknown, .anf_json => {
            std.debug.print("error: unsupported format for {s}\n", .{path});
            return error.UnsupportedFormat;
        },
        else => {},
    }

    // `--parse-only` stops after validate; `--emit-ir` stops after the ANF
    // optimizers — running stack lowering for either would let a later pass
    // fail a command that never asked for its output. EXCEPT when
    // --emit-source-map was also requested (F-255): the source map is only
    // populated by stack-lowering + emit, so --emit-ir alone must run the
    // full pipeline in that combination, the same way --emit-ir-to already
    // does.
    const stop_after: compiler_api.StopAfter = if (opts.parse_only)
        .validate
    else if (opts.emit_ir and opts.emit_source_map_path == null)
        .anf
    else
        .full;

    var diag: compiler_api.Diagnostics = .{};
    const pipeline = compiler_api.runPipeline(work_allocator, source, path, .{
        .disable_constant_folding = opts.disable_constant_folding,
        .stop_after = stop_after,
    }, &diag) catch |err| {
        printDiagnostics(&diag);
        return err;
    };
    printDiagnostics(&diag);

    // --parse-only: emit "parser ok" and stop after parse + validate. Used by
    // the conformance runner's --parser-only universal-frontend coverage check.
    if (opts.parse_only) {
        try writeStdoutLn(io, "parser ok");
        return;
    }

    const program = pipeline.program.?;

    // --emit-ir: output canonical ANF IR JSON, then stop — UNLESS
    // --emit-source-map was also requested (F-255, same bug as Go's F-183:
    // an unconditional return here used to silently drop the
    // --emit-source-map file with no diagnostic). When --emit-source-map is
    // also set, `stop_after` above already chose `.full`, so we fall
    // through into stack-lowering + emit below; `emit_ir_handled` then stops
    // us before the final hex/artifact output, since --emit-ir's contract
    // is "stdout carries only the IR".
    var emit_ir_handled = false;
    if (opts.emit_ir) {
        const canonical = try json_parser.serializeCanonicalJSON(work_allocator, program);
        try writeStdout(io, canonical);
        if (opts.emit_source_map_path == null) {
            return;
        }
        emit_ir_handled = true;
    }

    // --emit-ir-to <path>: write the SAME bytes --emit-ir would print, then
    // fall through and keep compiling so one process can hand back both the
    // ANF IR and the script hex (audit #17).
    if (opts.emit_ir_to_path) |ir_path| {
        const canonical = try json_parser.serializeCanonicalJSON(work_allocator, program);
        var ir_file = try std.Io.Dir.cwd().createFile(io, ir_path, .{});
        defer ir_file.close(io);
        var ir_buf: [4096]u8 = undefined;
        var ir_w = ir_file.writer(io, &ir_buf);
        try ir_w.interface.writeAll(canonical);
        try ir_w.interface.flush();
    }

    const optimized_stack_program = pipeline.stack_program.?;

    // --hex: output hex script only. Produces the full dispatch-table
    // locking script (same bytes that appear in the artifact's "script"
    // field), so downstream tools can compare byte-for-byte across
    // compilers without parsing JSON.
    // Pass 6: Emit full artifact
    const artifact = try emit.emitArtifact(work_allocator, optimized_stack_program, program);

    // --emit-source-map: extract the artifact's sourceMap object (or emit
    // the empty {"mappings":[]} wrapper if absent) and write it to PATH.
    // This runs before the --hex return below (N-186): --hex used to return
    // first, silently dropping the requested map.
    if (opts.emit_source_map_path) |sm_path| {
        try writeSourceMapToPath(work_allocator, io, artifact, sm_path, path);
    }

    // --emit-ir already printed the IR above; having fallen through only to
    // populate and write the source map, stop here rather than also print
    // the full artifact.
    if (emit_ir_handled) {
        return;
    }

    if (opts.hex_only) {
        try writeStdoutLn(io, try compiler_api.extractArtifactScript(artifact));
        return;
    }

    try writeStdoutLn(io, artifact);

    std.debug.print("Compiled: {s}\n", .{path});
}

/// GAP-011: source-map sourceFile values must be repo-relative (POSIX) so
/// goldens stay stable across worktree paths and developer machines. Walk
/// up from `src_path` looking for pnpm-workspace.yaml (the canonical repo
/// root marker); fall back to the basename if no marker is found. Returns
/// allocator-owned bytes.
///
/// Only handles absolute paths — relative paths are returned unchanged
/// (the runner always invokes the compiler with an absolute --source).
fn repoRelativeFileName(allocator: std.mem.Allocator, io: std.Io, src_path: []const u8) ![]u8 {
    if (!std.fs.path.isAbsolute(src_path)) {
        return try allocator.dupe(u8, src_path);
    }

    var dir_opt: ?[]const u8 = std.fs.path.dirname(src_path);
    while (dir_opt) |dir| {
        const marker = try std.fs.path.join(allocator, &.{ dir, "pnpm-workspace.yaml" });
        defer allocator.free(marker);
        const exists = blk: {
            const f = std.Io.Dir.cwd().openFile(io, marker, .{}) catch break :blk false;
            f.close(io);
            break :blk true;
        };
        if (exists) {
            // dir is the repo root — strip it from src_path plus the leading sep.
            if (src_path.len > dir.len + 1 and std.mem.startsWith(u8, src_path, dir) and src_path[dir.len] == std.fs.path.sep) {
                const rel = src_path[dir.len + 1 ..];
                // Normalize to POSIX separators.
                const out = try allocator.dupe(u8, rel);
                for (out) |*c| {
                    if (c.* == std.fs.path.sep_windows) c.* = '/';
                }
                return out;
            }
            break;
        }
        dir_opt = std.fs.path.dirname(dir);
    }
    return try allocator.dupe(u8, std.fs.path.basename(src_path));
}

/// Extract the `"sourceMap":{...}` substring from the emitted artifact JSON
/// (or fall back to the empty `{"mappings":[]}` wrapper) and write it to
/// `sm_path`. Replaces the absolute sourceFile string (path passed via
/// `src_path`) with its repo-relative POSIX form to keep goldens stable
/// across worktree paths.
fn writeSourceMapToPath(allocator: std.mem.Allocator, io: std.Io, artifact_json: []const u8, sm_path: []const u8, src_path: []const u8) !void {
    const marker = "\"sourceMap\":";
    var payload_raw: []const u8 = "{\"mappings\":[]}";
    if (std.mem.indexOf(u8, artifact_json, marker)) |idx| {
        const after = idx + marker.len;
        if (after < artifact_json.len and artifact_json[after] == '{') {
            // Walk to the matching close brace, respecting string literals.
            var depth: i32 = 0;
            var p: usize = after;
            var in_string = false;
            var escape = false;
            while (p < artifact_json.len) : (p += 1) {
                const c = artifact_json[p];
                if (escape) {
                    escape = false;
                    continue;
                }
                if (in_string) {
                    if (c == '\\') { escape = true; continue; }
                    if (c == '"') { in_string = false; continue; }
                    continue;
                }
                if (c == '"') { in_string = true; continue; }
                if (c == '{') depth += 1;
                if (c == '}') {
                    depth -= 1;
                    if (depth == 0) { p += 1; break; }
                }
            }
            payload_raw = artifact_json[after..p];
        }
    }

    // GAP-011: rewrite each `"sourceFile":"<abs>"` to its repo-relative form.
    // All mappings in a single compile share the same sourceFile, so a simple
    // string replace is sound.
    const rel_name = try repoRelativeFileName(allocator, io, src_path);
    defer allocator.free(rel_name);

    const needle = try std.fmt.allocPrint(allocator, "\"sourceFile\":\"{s}\"", .{src_path});
    defer allocator.free(needle);
    const replacement = try std.fmt.allocPrint(allocator, "\"sourceFile\":\"{s}\"", .{rel_name});
    defer allocator.free(replacement);

    const size = std.mem.replacementSize(u8, payload_raw, needle, replacement);
    const payload = try allocator.alloc(u8, size);
    defer allocator.free(payload);
    _ = std.mem.replace(u8, payload_raw, needle, replacement, payload);

    var file = try std.Io.Dir.cwd().createFile(io, sm_path, .{});
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var w = file.writer(io, &buf);
    try w.interface.writeAll(payload);
    try w.interface.writeAll("\n");
    try w.interface.flush();
}

const UnsupportedFormat = error{UnsupportedFormat};
const ParseFailed = error{ParseFailed};
const ValidationFailed = error{ValidationFailed};
const TypeCheckFailed = error{TypeCheckFailed};

// ---------------------------------------------------------------------------
// Tests — CLI flag plumbing
// ---------------------------------------------------------------------------
//
// GAP-015 (audits/cross-language-completeness-20260510.md, Section 4 / B8):
// the `--parse-only` flag is plumbed end-to-end through compileFromSource,
// but it had no dedicated unit test. The flag is the wire used by
// `conformance/runner/runner.ts`'s `--parser-only` universal-frontend
// coverage check, so a silent regression here breaks the all-tier
// parser-only matrix in CI. The tests below pin the CLI flag parsing wire.

test "parseCompileOptions: --parse-only sets parse_only=true" {
    const args = [_][]const u8{"--parse-only"};
    const opts = try parseCompileOptions(args[0..], true);
    try std.testing.expect(opts.parse_only);
    // Other flags must remain at their defaults.
    try std.testing.expect(!opts.emit_ir);
    try std.testing.expect(!opts.hex_only);
    try std.testing.expect(!opts.disable_constant_folding);
}

test "parseCompileOptions: default has parse_only=false" {
    const args = [_][]const u8{};
    const opts = try parseCompileOptions(args[0..], true);
    try std.testing.expect(!opts.parse_only);
}

test "parseCompileOptions: --parse-only combines with other flags" {
    // The conformance runner pairs --parse-only with no other flags, but
    // nothing in the parser prevents combinations. Pin that --parse-only
    // is composable with --disable-constant-folding (a no-op pairing,
    // since parse-only stops before the optimizer runs, but the parser
    // must still accept it without error).
    const args = [_][]const u8{ "--parse-only", "--disable-constant-folding" };
    const opts = try parseCompileOptions(args[0..], true);
    try std.testing.expect(opts.parse_only);
    try std.testing.expect(opts.disable_constant_folding);
}

test "parseCompileOptions: unknown flag rejected" {
    const args = [_][]const u8{"--parse-onlyy"}; // typo
    try std.testing.expectError(error.UnknownFlag, parseCompileOptions(args[0..], true));
}

test "parseCompileOptions: --parse-only accepted in compile-ir mode" {
    // The IR consumer mode (allow_disable_constant_folding=false in main.zig
    // when parsing args[3..] for the `compile-ir` subcommand) must still
    // accept --parse-only — even though parse-only on IR input is a no-op
    // shape, the flag must not be rejected as "unknown".
    const args = [_][]const u8{"--parse-only"};
    const opts = try parseCompileOptions(args[0..], false);
    try std.testing.expect(opts.parse_only);
}

test "parseCompileOptions: --disable-constant-folding rejected when not allowed" {
    // Mirror of the compile-ir guardrail: when the caller passes
    // allow_disable_constant_folding=false, the parser must reject the flag
    // with UnsupportedFlag (not silently accept). This keeps the IR mode's
    // optimizer-state semantics deterministic.
    const args = [_][]const u8{"--disable-constant-folding"};
    try std.testing.expectError(error.UnsupportedFlag, parseCompileOptions(args[0..], false));
}

test "CompileOptions.parse_only field default is false" {
    // Regression guard: if a future refactor changes the default value
    // of parse_only on CompileOptions, the conformance runner's expectation
    // ("plain compile must emit hex / IR, not 'parser ok'") would silently
    // break.
    const opts: CompileOptions = .{};
    try std.testing.expect(!opts.parse_only);
}
