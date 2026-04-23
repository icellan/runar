plugins {
    java
    application
}

group = "build.runar"
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
    // Placeholder deps. Populated in milestone 3 (parse/validate/typecheck).
    // implementation("com.github.javaparser:javaparser-core:3.25.10")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application {
    mainClass = "runar.compiler.Cli"
    applicationName = "runar-java"
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

tasks.named<Jar>("jar") {
    manifest {
        attributes(
            "Main-Class" to "runar.compiler.Cli",
            "Implementation-Title" to "Rúnar Java Compiler",
            "Implementation-Version" to project.version,
        )
    }
}
