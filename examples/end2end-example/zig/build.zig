const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const frontend_module = b.createModule(.{
        .root_source_file = b.path("../../../compilers/zig/src/frontend_api.zig"),
        .target = target,
        .optimize = optimize,
    });
    const bsvz_dep = b.dependency("bsvz", .{
        .target = target,
        .optimize = optimize,
    });
    const bsvz_module = bsvz_dep.module("bsvz");

    const runar_module = b.createModule(.{
        .root_source_file = b.path("../../../packages/runar-zig/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    runar_module.addImport("runar_frontend", frontend_module);
    runar_module.addImport("bsvz", bsvz_module);

    const test_module = b.createModule(.{
        .root_source_file = b.path("price_bet_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_module.addImport("runar", runar_module);

    const tests = b.addTest(.{ .root_module = test_module });
    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run PriceBet end-to-end tests");
    test_step.dependOn(&run_tests.step);
}
