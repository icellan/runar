plugins {
    java
}

group = "build.runar.examples"
version = "0.4.4"

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
        }
    }
}

dependencies {
    implementation("build.runar:runar-java:0.4.4")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
