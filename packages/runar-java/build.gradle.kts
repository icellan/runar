plugins {
    `java-library`
}

group = "build.runar"
version = "0.4.4"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
    withSourcesJar()
    withJavadocJar()
}

repositories {
    mavenCentral()
}

dependencies {
    // secp256k1 ECDSA + SHA-256 / RIPEMD-160 / BIP-143 sighash.
    api("org.bouncycastle:bcprov-jdk18on:1.78")

    // Frontend-only access to the Rúnar Java compiler so CompileCheck can
    // run parse → validate → expand-fixed-arrays → typecheck without
    // shelling out. Composite-build via settings.gradle.kts pulls the sources
    // from compilers/java in dev and CI.
    implementation("build.runar:runar-java-compiler:0.4.4")

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
