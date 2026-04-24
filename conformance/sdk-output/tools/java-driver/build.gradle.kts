plugins {
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
    implementation("build.runar:runar-java:0.4.4")
}

application {
    mainClass.set("runar.sdkdriver.Driver")
}

// Produce a fat jar so the runner can invoke `java -jar` without
// fiddling with the classpath. Mirrors the Rust driver's single-binary
// release artifact.
tasks.register<Jar>("fatJar") {
    archiveClassifier.set("all")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
        attributes["Main-Class"] = "runar.sdkdriver.Driver"
    }
    from(sourceSets.main.get().output)
    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get()
            .filter { it.name.endsWith(".jar") }
            .map { zipTree(it) }
    })
    // BouncyCastle jars ship signed. Strip signature files so the JVM
    // doesn't reject the shaded jar with SecurityException at startup.
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/*.EC")
}

tasks.named("build") {
    dependsOn("fatJar")
}
