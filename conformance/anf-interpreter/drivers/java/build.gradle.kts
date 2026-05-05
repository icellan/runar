plugins {
    application
}

group = "build.runar"
version = "0.5.0"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("build.runar:runar-java:0.5.0")
}

application {
    mainClass.set("runar.anfdriver.Driver")
}

// Produce a fat jar so the runner can invoke `java -jar` without
// fiddling with the classpath. Mirrors the SDK-output Java driver's
// single-binary release artifact.
tasks.register<Jar>("fatJar") {
    archiveBaseName.set("runar-anf-driver")
    archiveClassifier.set("")
    archiveVersion.set("")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
        attributes["Main-Class"] = "runar.anfdriver.Driver"
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
