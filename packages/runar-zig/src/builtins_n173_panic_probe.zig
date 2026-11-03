// N-173 test support: a tiny standalone executable that calls one of the
// length-gated runtime builtins in builtins.zig with a bad-length operand and
// lets it panic.
//
// A Zig `@panic` aborts the whole process (and, in-process, the whole test
// binary -- see the "Zig panic aborts the whole test binary" comments
// elsewhere in builtins.zig), so the only way to assert on the exact panic
// text is out-of-process: builtins_n173_panic_probe_test.zig spawns this
// binary with a case name as argv[1], captures its stderr, and checks the
// text.
//
// argv[1] selects the case:
//   sha256Compress-state      sha256Compress-block
//   sha256Finalize-state      sha256Finalize-remaining
//   blake3Compress-chaining   blake3Compress-block
//   blake3Hash-message
//   ecPointX                  ecPointY
//   ok                        (control: valid-length call, exits 0)
//
// Mirrors the CLI shim pattern of analyzer_cli.zig / canonicalise_cli.zig.

const std = @import("std");
const builtins = @import("builtins.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer args_list.deinit(allocator);
    var args_iter = std.process.Args.Iterator.init(init.minimal.args);
    while (args_iter.next()) |arg| try args_list.append(allocator, arg);
    const args = args_list.items;

    if (args.len < 2) {
        try writeStderr(io, "usage: runar-n173-panic-probe <case>\n");
        std.process.exit(2);
    }
    const case = args[1];

    const state32 = [_]u8{0} ** 32;
    const block64 = [_]u8{0} ** 64;
    const point64 = [_]u8{0} ** 64;

    if (std.mem.eql(u8, case, "sha256Compress-state")) {
        _ = builtins.sha256Compress(state32[0..31], &block64);
    } else if (std.mem.eql(u8, case, "sha256Compress-block")) {
        _ = builtins.sha256Compress(&state32, block64[0..63]);
    } else if (std.mem.eql(u8, case, "sha256Finalize-state")) {
        _ = builtins.sha256Finalize(state32[0..31], "", 0);
    } else if (std.mem.eql(u8, case, "sha256Finalize-remaining")) {
        const remaining_120 = [_]u8{0} ** 120;
        _ = builtins.sha256Finalize(&state32, &remaining_120, 0);
    } else if (std.mem.eql(u8, case, "blake3Compress-chaining")) {
        _ = builtins.blake3Compress(state32[0..31], &block64);
    } else if (std.mem.eql(u8, case, "blake3Compress-block")) {
        _ = builtins.blake3Compress(&state32, block64[0..63]);
    } else if (std.mem.eql(u8, case, "blake3Hash-message")) {
        const message_65 = [_]u8{0} ** 65;
        _ = builtins.blake3Hash(&message_65);
    } else if (std.mem.eql(u8, case, "ecPointX")) {
        _ = builtins.ecPointX(point64[0..63]);
    } else if (std.mem.eql(u8, case, "ecPointY")) {
        _ = builtins.ecPointY(point64[0..63]);
    } else if (std.mem.eql(u8, case, "ok")) {
        // Control: valid-length operands must not panic.
        _ = builtins.sha256Compress(&state32, &block64);
        std.process.exit(0);
    } else {
        try writeStderr(io, "unknown case\n");
        std.process.exit(2);
    }

    // Unreachable for every bad-length case above: the builtin panics before
    // returning. Reaching here means the case did NOT abort, which the test
    // must treat as a failure of the thing under test, not a probe bug.
    try writeStderr(io, "did not panic\n");
    std.process.exit(3);
}

fn writeStderr(io: std.Io, data: []const u8) !void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stderr().writer(io, &buf);
    try w.interface.writeAll(data);
    try w.interface.flush();
}
