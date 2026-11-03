plugins {
    `java-library`
    application
}

group = "build.runar"
version = "1.0.0-rc.1"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
    withSourcesJar()
    withJavadocJar()
}

application {
    // Default entry point: the static-analyzer CLI. Other entry points
    // (CompileCheck, etc.) ship as library APIs and are not invoked via
    // `gradle run`.
    mainClass.set("runar.lang.analyzer.AnalyzerCli")
    applicationName = "runar-analyzer"
}

// Convenience task: `gradle runAnalyzer --args="<hex-path>"` invokes the
// analyzer CLI. Used by tools/analyzer-runner/java.sh.
tasks.register<JavaExec>("runAnalyzer") {
    description = "Run the Bitcoin Script static analyzer on a hex-encoded script file."
    group = "application"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("runar.lang.analyzer.AnalyzerCli")
}

// Convenience task: `gradle -q runCanonicalise` with a JSON request on stdin.
// Used by conformance/fuzzer/canonical-json-differential.ts.
tasks.register<JavaExec>("runCanonicalise") {
    description = "Run the canonicalJson CLI shim (stdin JSON request -> stdout canonical bytes)."
    group = "application"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("runar.lang.sdk.CanonicaliseShim")
    standardInput = System.`in`
}

// Batched peer of `runCanonicalise`: newline-delimited requests in, one
// response line out per request, all in ONE JVM. Used by the deterministic
// Java canonicalJson PR gate (conformance/fuzzer/canonical-java-gate.ts) so a
// whole fixed corpus is byte-compared against the TS reference without paying a
// JVM cold-start per case.
tasks.register<JavaExec>("runCanonicaliseBatch") {
    description = "Batch canonicalJson CLI shim (newline-delimited requests -> newline-delimited responses, one JVM)."
    group = "application"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("runar.lang.sdk.CanonicaliseBatchShim")
    standardInput = System.`in`
}

repositories {
    mavenCentral()
}

// Lock all configurations so the resolved dependency graph is committed as
// gradle.lockfile. The Dependency Audit CI workflow scans that lockfile with
// osv-scanner; regenerate with `gradle dependencies --write-locks` whenever
// a dependency version changes.
dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    // secp256k1 ECDSA + SHA-256 / RIPEMD-160 / BIP-143 sighash.
    api("org.bouncycastle:bcprov-jdk18on:1.85")

    // Frontend-only access to the Rúnar Java compiler so CompileCheck can
    // run parse → validate → expand-fixed-arrays → typecheck without
    // shelling out. Composite-build via settings.gradle.kts pulls the sources
    // from compilers/java in dev and CI.
    implementation("build.runar:runar-java-compiler:1.0.0-rc.1")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.named<Test>("test") {
    useJUnitPlatform()
    // Surface full test-failure stack traces on the console so failures
    // are diagnosable from CI logs without hunting through the HTML report.
    testLogging {
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        events("failed")
        showStackTraces = true
    }
}

tasks.withType<Javadoc>().configureEach {
    // SDK classes reference compiler-side names in prose; disable doclint
    // so a broken link in a Javadoc tag doesn't fail the build, and keep
    // the tool quiet.
    (options as StandardJavadocDocletOptions).apply {
        addStringOption("Xdoclint:none", "-quiet")
        addBooleanOption("quiet", true)
    }
}
