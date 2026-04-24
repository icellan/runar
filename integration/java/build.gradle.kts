// Rúnar Java integration tests (M13).
//
// End-to-end tests that deploy compiled contracts to a running Bitcoin SV
// regtest node (or Teranode) and exercise the runar-java SDK's deploy /
// call / broadcast path with real ECDSA signatures.
//
// Tests are gated behind the -Drunar.integration=true system property so
// a plain `gradle test` invocation inside CI does not attempt to reach a
// node that is not running. Enable explicitly with:
//
//     cd integration/java
//     gradle test -Drunar.integration=true
//
// Or via the shared driver:
//
//     ./integration/run-all.sh           # runs every language, including java
//
// Backend selection:
//
//     BSV_BACKEND=svnode    gradle test    # default (bitcoind regtest, port 18332)
//     BSV_BACKEND=teranode  gradle test    # Teranode Docker Compose stack (port 19292)

plugins {
    java
}

group = "build.runar.integration"
version = "0.4.4"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("build.runar:runar-java:0.4.4")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.named<Test>("test") {
    useJUnitPlatform()

    // Long-running (multi-minute) tests: broadcasting SPHINCS+ ~200 KB
    // scripts can take several minutes per tx on a loaded runner.
    timeout.set(java.time.Duration.ofMinutes(30))

    // Surface JUnit output so flaky nodes are debuggable from CI logs.
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
    }

    // Forward the gating property so `@EnabledIfSystemProperty` is
    // honoured inside the forked test JVM.
    systemProperty(
        "runar.integration",
        System.getProperty("runar.integration", "false")
    )

    // Forward node-config env vars (mirror of the Python / Go / Rust
    // suites: RPC_URL / RPC_USER / RPC_PASS override the backend-specific
    // defaults below; BSV_BACKEND selects svnode vs teranode).
    listOf("BSV_BACKEND", "NODE_TYPE", "RPC_URL", "RPC_USER", "RPC_PASS").forEach { key ->
        System.getenv(key)?.let { environment(key, it) }
    }
}
