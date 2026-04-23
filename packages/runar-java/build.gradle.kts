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
    // Placeholder deps. Real crypto / HTTP / JSON land in milestones 8-10.
    // api("org.bouncycastle:bcprov-jdk18on:1.78")
    // implementation("com.fasterxml.jackson.core:jackson-core:2.17.1")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
