const std = @import("std");

fn createConfiguredRootModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    frontend_module: *std.Build.Module,
    bsvz_module: *std.Build.Module,
    bsvz_runar_harness_module: ?*std.Build.Module,
) *std.Build.Module {
    const root_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    root_module.addImport("runar_frontend", frontend_module);
    root_module.addImport("bsvz", bsvz_module);
    if (bsvz_runar_harness_module) |harness_module| {
        root_module.addImport("bsvz_runar_harness", harness_module);
    }
    return root_module;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const frontend_module = b.createModule(.{
        .root_source_file = b.path("../../compilers/zig/src/frontend_api.zig"),
        .target = target,
        .optimize = optimize,
    });
    const bsvz_dep = b.dependency("bsvz", .{
        .target = target,
        .optimize = optimize,
    });
    const bsvz_module = bsvz_dep.module("bsvz");

    const has_bsvz_runar_harness = blk: {
        const harness_path = b.pathFromRoot("../../../bsvz/tests/support/runar_harness.zig");
        std.fs.cwd().access(harness_path, .{}) catch |err| switch (err) {
            error.FileNotFound => break :blk false,
            else => break :blk false,
        };
        break :blk true;
    };

    var bsvz_runar_harness_module: ?*std.Build.Module = null;
    if (has_bsvz_runar_harness) {
        const harness_module = b.createModule(.{
            .root_source_file = b.path("../../../bsvz/tests/support/runar_harness.zig"),
            .target = target,
            .optimize = optimize,
        });
        harness_module.addImport("bsvz", bsvz_module);
        bsvz_runar_harness_module = harness_module;
    }

    const build_options = b.addOptions();
    build_options.addOption(bool, "has_bsvz_runar_harness", has_bsvz_runar_harness);

    const root_module = createConfiguredRootModule(
        b,
        target,
        optimize,
        frontend_module,
        bsvz_module,
        bsvz_runar_harness_module,
    );
    root_module.addOptions("build_options", build_options);

    const runar_module = b.addModule("runar", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    runar_module.addImport("runar_frontend", frontend_module);
    runar_module.addImport("bsvz", bsvz_module);
    runar_module.addOptions("build_options", build_options);

    const tests = b.addTest(.{
        .root_module = root_module,
    });
    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run runar-zig tests");
    test_step.dependOn(&run_tests.step);
}
