plugins {
    java
}

group = "build.runar.examples"
version = "1.0.0-rc.1"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

repositories {
    mavenCentral()
}

// Contract source files use the .runar.java extension to signal they are
// Rúnar contracts, not generic Java. Wire them into the `main` source set
// alongside conventional .java files so `gradle build` compiles them against
// the runar-java SDK.
sourceSets {
    main {
        java {
            include("**/*.java")
            include("**/*.runar.java")

            // byte-builtins is a Rúnar frontend input, not a Java compilation
            // unit — the same posture the Go port states with `//go:build
            // ignore`. ONE signature is why javac rejects it, and it is the
            // same unresolved question wearing a third face:
            //
            //   `split` is specified as returning a PAIR, and the language has
            //   no way to name the left element. No surface parser accepts
            //   array destructuring, and the typechecker's own signature
            //   returns a single ByteString — the RIGHT half.
            //
            // Three symptoms, one root, and whoever decides what the builtin
            // actually returns resolves all three:
            //   1. the compiler ORPHANS the left half — the stack model carries
            //      a `push(null)` for it that nothing ever drops;
            //   2. `runar.lang.Builtins.split` models the pair honestly as
            //      `ByteString[]`, so it disagrees with the language — this
            //      exclusion;
            //   3. `substr` escapes only because it NIPs its left half, which
            //      is a workaround rather than an answer.
            //
            // Everything else in the file is valid Java. Its Rúnar-side coverage
            // is untouched, and that is checked rather than asserted:
            // conformance/tests/byte-builtins reads this exact file for the
            // `.runar.java` surface in the multi-format and parser-only
            // matrices, its compiled bytes are spent in
            // conformance/byte_builtins_execution_test.go, and
            // javac-source-set.test.ts holds this list to EXACTLY one entry so a
            // second exclusion has to justify itself.
            exclude("**/byte-builtins/**")
        }
    }
}

// R-210: lock the dependency graph so `osv-scanner` in dependency-audit.yml can
// see it. Five of the seven Gradle projects in this repo had no lock state, so
// the audit job scanned two lockfiles and the CI comment described the repo as
// having exactly those two. With lock state present, Gradle fails any ordinary
// build if a declared version changes without `gradle dependencies
// --write-locks`, so the scanned lockfile cannot drift from the real graph.
dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    implementation("build.runar:runar-java:1.0.0-rc.1")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
