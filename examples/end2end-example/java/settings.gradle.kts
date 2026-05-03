rootProject.name = "runar-end2end-example-java"

// Pull the runar-java SDK in as a composite build so the example always
// runs against the source in this repo (not a published artifact).
includeBuild("../../../packages/runar-java")
