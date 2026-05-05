// Rúnar Java end-to-end PriceBet example.
//
// Mirrors the TypeScript / Go / Rust / Python / Ruby / Zig PriceBet
// examples under examples/end2end-example/. Compiles the contract
// against the runar-java SDK source (composite build) and runs the
// business-logic tests via the ContractSimulator and the Rúnar
// CompileCheck frontend.
//
// To run:
//
//     cd examples/end2end-example/java
//     gradle test
//
// See also examples/end2end-example/{ts,go,rust,python,ruby,zig} for
// equivalent flows in the other primary SDK languages.

plugins {
    java
}

group = "build.runar.end2end"
version = "0.5.0"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

repositories {
    mavenCentral()
}

// Contract source files use the .runar.java extension to signal they
// are Rúnar contracts, not generic Java. Wire them into the `main`
// source set alongside conventional .java files so `gradle build`
// compiles them against the runar-java SDK.
sourceSets {
    main {
        java {
            include("**/*.java")
            include("**/*.runar.java")
        }
    }
}

dependencies {
    implementation("build.runar:runar-java:0.5.0")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.named<Test>("test") {
    useJUnitPlatform()

    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = false
    }
}
