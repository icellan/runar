const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

pub fn main(init: std.process.Init.Minimal) !void {
    // Zig 0.16's `std.testing.io` and `std.testing.environ` are declared
    // `undefined` in the stdlib and only initialized by Zig's default test
    // runners. Tests that reach for `std.testing.io` (e.g. `std.fs.cwd()
    // .readFileAlloc` via the new Io-typed APIs) deadlock on Linux when
    // left uninitialized; tests that reach for `std.testing.environ`
    // (e.g. helpers reading env vars without linking libc) segfault.
    // macOS happens to dodge both but Linux CI does not. Initialize them
    // here, matching the stdlib's compiler/test_runner.zig flow which
    // takes `std.process.Init.Minimal` from the caller.
    testing.environ = init.environ;
    testing.io_instance = .init(testing.allocator, .{
        .argv0 = .init(init.args),
        .environ = init.environ,
    });
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
