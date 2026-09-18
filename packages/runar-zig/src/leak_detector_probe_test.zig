//! Self-test for the leak detector in `src/test_runner.zig`.
//!
//! Every `std.testing.allocator` assertion in this package depends on the
//! runner calling `std.testing.allocator_instance.deinit()` and failing the
//! test on `.leak`. It did not, so the check was vacuous: a test could leak
//! through the testing allocator and still report `ok` with exit 0, and no
//! leak had ever been detected here.
//!
//! The probe below leaks on purpose, but only when `RUNAR_ZIG_LEAK_PROBE=1`
//! is set, so an ordinary run stays green. To confirm the detector is still
//! armed:
//!
//!     RUNAR_ZIG_LEAK_PROBE=1 zig build test   # MUST exit non-zero
//!     zig build test                          # MUST exit 0
//!
//! A green run under `RUNAR_ZIG_LEAK_PROBE=1` means the leak check has been
//! disarmed again and every leak assertion in the package is worthless.

const std = @import("std");

test "leak detector is armed (opt-in: RUNAR_ZIG_LEAK_PROBE=1)" {
    const enabled = std.testing.environ.getPosix("RUNAR_ZIG_LEAK_PROBE") orelse return;
    if (!std.mem.eql(u8, enabled, "1")) return;

    const leaked = try std.testing.allocator.alloc(u8, 32);
    _ = leaked; // deliberately never freed — the runner must fail this test
}
