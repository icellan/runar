rootProject.name = "java-anf-driver"

// Consume the local runar-java SDK as an included build so the driver
// always builds against the current worktree rather than a published
// artifact. Mirrors the relative-path pattern used by the SDK-output
// java driver (`conformance/sdk-output/tools/java-driver`).
includeBuild("../../../../packages/runar-java") {
    dependencySubstitution {
        substitute(module("build.runar:runar-java")).using(project(":"))
    }
}
