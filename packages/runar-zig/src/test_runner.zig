const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

pub fn main() !void {
    // Zig 0.16's `std.testing.io` is a threaded Io instance declared `undefined`
    // in the stdlib and only initialized by Zig's default test runners. Tests
    // that reach for `std.testing.io` (e.g. `std.fs.cwd().readFileAlloc` via the
    // new Io-typed APIs) will deadlock on Linux if it's left uninitialized —
    // macOS happens to dodge the hang but Linux CI does not. Initialize it once
    // here, matching the stdlib's `mainSimple` runner.
    testing.io_instance = .init(testing.allocator, .{});
    defer testing.io_instance.deinit();

    var passed: usize = 0;
    var failed: usize = 0;
    var skipped: usize = 0;

    for (builtin.test_functions) |t| {
        if (t.func()) |_| {
            std.debug.print("  test {s} ... \x1b[32mok\x1b[0m\n", .{t.name});
            passed += 1;
        } else |err| {
            if (err == error.SkipZigTest) {
                std.debug.print("  test {s} ... \x1b[33mskipped\x1b[0m\n", .{t.name});
                skipped += 1;
            } else {
                std.debug.print("  test {s} ... \x1b[31mFAIL ({s})\x1b[0m\n", .{ t.name, @errorName(err) });
                failed += 1;
            }
        }
    }

    std.debug.print("\n{d} passed, {d} failed, {d} skipped ({d} total)\n", .{
        passed,
        failed,
        skipped,
        passed + failed + skipped,
    });

    if (failed > 0) {
        return error.TestsFailed;
    }
}
