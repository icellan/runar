const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main compiler executable
    const exe = b.addExecutable(.{
        .name = "runar-zig",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(exe);

    // Run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the Runar Zig compiler");
    run_step.dependOn(&run_cmd.step);

    // Unit tests
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test_main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Conformance tests
    const conformance_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test_conformance.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_conformance = b.addRunArtifact(conformance_tests);
    const conformance_step = b.step("conformance", "Run conformance test suite");
    conformance_step.dependOn(&run_conformance.step);

    // Byte-identical golden diff harness — runs the built runar-zig binary
    // against each `conformance/tests/*/` fixture and asserts IR + hex match
    // the goldens. Depends on the install step so `zig-out/bin/runar-zig`
    // exists before the test subprocess tries to invoke it.
    const conformance_goldens_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests/conformance_goldens.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_conformance_goldens = b.addRunArtifact(conformance_goldens_tests);
    run_conformance_goldens.step.dependOn(b.getInstallStep());
    const conformance_goldens_step = b.step(
        "conformance-goldens",
        "Run byte-identical golden diff harness against every conformance fixture",
    );
    conformance_goldens_step.dependOn(&run_conformance_goldens.step);
}
