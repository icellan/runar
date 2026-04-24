rootProject.name = "runar-integration-java"

// Pull the runar-java SDK in as a composite build so integration tests
// always run against the source in this repo (not a published artifact).
includeBuild("../../packages/runar-java")
