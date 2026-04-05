const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const runar_dep = b.dependency("runar_zig", .{
        .target = target,
        .optimize = optimize,
    });

    const root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    root_module.addImport("runar", runar_dep.module("runar"));

    const exe = b.addExecutable(.{
        .name = "zig-sdk-tool",
        .root_module = root_module,
    });

    b.installArtifact(exe);
}
