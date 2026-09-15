const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // bsvz dependency (same as runar-zig SDK)
    const bsvz_dep = b.dependency("bsvz", .{
        .target = target,
        .optimize = optimize,
    });
    const bsvz_module = bsvz_dep.module("bsvz");

    // Zig compiler frontend module (for compiling contracts natively)
    const frontend_module = b.createModule(.{
        .root_source_file = b.path("../../compilers/zig/src/frontend_api.zig"),
        .target = target,
        .optimize = optimize,
    });

    // runar-zig SDK module
    const runar_module = b.createModule(.{
        .root_source_file = b.path("../../packages/runar-zig/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    runar_module.addImport("runar_frontend", frontend_module);
    runar_module.addImport("bsvz", bsvz_module);

    // Build options for runar (it checks for bsvz_runar_harness)
    const build_options = b.addOptions();
    build_options.addOption(bool, "has_bsvz_runar_harness", false);
    runar_module.addOptions("build_options", build_options);

    // Create root module for the integration tests
    const test_module = b.createModule(.{
        .root_source_file = b.path("src/main_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_module.addImport("bsvz", bsvz_module);
    test_module.addImport("runar", runar_module);
    test_module.addImport("runar_frontend", frontend_module);

    // Integration test executable
    const tests = b.addTest(.{
        .root_module = test_module,
    });

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run Zig integration tests");
    test_step.dependOn(&run_tests.step);

    // Phase A residual-only suite (clearer PASS evidence for residual goal)
    const phase_a_module = b.createModule(.{
        .root_source_file = b.path("src/phase_a_only_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    phase_a_module.addImport("bsvz", bsvz_module);
    phase_a_module.addImport("runar", runar_module);
    phase_a_module.addImport("runar_frontend", frontend_module);
    const phase_a_tests = b.addTest(.{
        .root_module = phase_a_module,
    });
    const run_phase_a = b.addRunArtifact(phase_a_tests);
    const phase_a_step = b.step("test-phase-a", "Run Phase A residual Zig integration tests only");
    phase_a_step.dependOn(&run_phase_a.step);

    // Negative-assertion guard suite. Needs no node: it proves the
    // broadcast-attempt counter discriminates a node rejection from an
    // SDK-side failure, and ratchets the test sources against the absolute
    // (vacuous) form of the assertion.
    const guard_module = b.createModule(.{
        .root_source_file = b.path("src/negative_assertion_guard_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    guard_module.addImport("bsvz", bsvz_module);
    guard_module.addImport("runar", runar_module);
    guard_module.addImport("runar_frontend", frontend_module);
    const guard_tests = b.addTest(.{
        .root_module = guard_module,
    });
    const run_guard = b.addRunArtifact(guard_tests);
    const guard_step = b.step("test-guard", "Run the node-free negative-assertion guard suite");
    guard_step.dependOn(&run_guard.step);
}
