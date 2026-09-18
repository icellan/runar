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

    var passed: usize = 0;
    var failed: usize = 0;
    var skipped: usize = 0;
    var leaked: usize = 0;

    for (builtin.test_functions) |t| {
        // `std.testing.allocator` is a `DebugAllocator` whose leak report is
        // produced by `deinit()`. A runner that never calls it makes every
        // leak assertion in the suite vacuous, so give each test a FRESH
        // instance and tear it down straight after — that is what attributes
        // a leak to the test that made it, the same way the stdlib's
        // `mainTerminal` does.
        testing.allocator_instance = .init;
        testing.io_instance = .init(testing.allocator, .{
            .argv0 = .init(init.args),
            .environ = init.environ,
        });

        const result = t.func();

        // `io_instance` allocates from `testing.allocator`, so it has to be
        // torn down BEFORE the leak check or its own live bookkeeping is
        // reported as the test's leak.
        testing.io_instance.deinit();
        const leak = testing.allocator_instance.deinit() == .leak;
        if (leak) leaked += 1;

        if (result) |_| {
            if (leak) {
                std.debug.print("  test {s} ... \x1b[31mFAIL (memory leak)\x1b[0m\n", .{t.name});
                failed += 1;
            } else {
                std.debug.print("  test {s} ... \x1b[32mok\x1b[0m\n", .{t.name});
                passed += 1;
            }
        } else |err| {
            if (err == error.SkipZigTest) {
                if (leak) {
                    std.debug.print("  test {s} ... \x1b[31mFAIL (memory leak while skipping)\x1b[0m\n", .{t.name});
                    failed += 1;
                } else {
                    std.debug.print("  test {s} ... \x1b[33mskipped\x1b[0m\n", .{t.name});
                    skipped += 1;
                }
            } else {
                const leak_note = if (leak) " + memory leak" else "";
                std.debug.print("  test {s} ... \x1b[31mFAIL ({s}{s})\x1b[0m\n", .{ t.name, @errorName(err), leak_note });
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
    if (leaked > 0) {
        std.debug.print("{d} test(s) leaked memory through std.testing.allocator\n", .{leaked});
    }

    if (failed > 0) {
        return error.TestsFailed;
    }
}
