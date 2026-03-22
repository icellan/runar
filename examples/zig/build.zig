const std = @import("std");

fn createRunarModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    frontend_module: *std.Build.Module,
    bsvz_module: *std.Build.Module,
) *std.Build.Module {
    const runar_module = b.createModule(.{
        .root_source_file = b.path("../../packages/runar-zig/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    runar_module.addImport("runar_frontend", frontend_module);
    runar_module.addImport("bsvz", bsvz_module);
    return runar_module;
}

fn createExampleModule(
    b: *std.Build,
    path: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    runar_module: *std.Build.Module,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path(path),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("runar", runar_module);
    return module;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const frontend_module = b.createModule(.{
        .root_source_file = b.path("../../compilers/zig/src/frontend_api.zig"),
        .target = target,
        .optimize = optimize,
    });
    const bsvz_module = b.createModule(.{
        .root_source_file = b.path("../../../bsvz/src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const runar_module = createRunarModule(b, target, optimize, frontend_module, bsvz_module);

    const assert_probe = b.addExecutable(.{
        .name = "assert_probe",
        .root_module = createExampleModule(b, "assert_probe.zig", target, optimize, runar_module),
    });
    b.installArtifact(assert_probe);

    const tests = b.addTest(.{
        .root_module = createExampleModule(b, "examples_test.zig", target, optimize, runar_module),
    });

    const run_tests = b.addRunArtifact(tests);
    run_tests.step.dependOn(b.getInstallStep());
    const test_step = b.step("test", "Run Zig example tests");
    test_step.dependOn(&run_tests.step);
}
