# Changelog

All notable changes to Rúnar are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Java as the seventh native compiler + SDK tier. In-progress across
  milestones M1–M18 in [`docs/java-tier-plan.md`](docs/java-tier-plan.md).
  Landed so far:
  - M1: design plan at `docs/java-tier-plan.md`.
  - M2: project skeleton under `compilers/java/`, `packages/runar-java/`,
    and `examples/java/` (Gradle Kotlin DSL, CLI stub, base types and
    annotations `@Readonly` / `@Public` / `@Stateful`, `SmartContract`
    and `StatefulSmartContract` base classes).
  - Early M3/M4 groundwork: Rúnar AST + ANF IR Java schemas and a
    hand-rolled RFC 8785 JCS canonical JSON serializer
    (`compilers/java/src/main/java/runar/compiler/canonical/Jcs.java`),
    plus a `.runar.java` parser built on `javax.tools` with zero
    external dependencies
    (`compilers/java/src/main/java/runar/compiler/frontend/JavaParser.java`).

Validator, typechecker, Stack IR, emit, cross-compiler `.runar.java`
parsers, Java SDK, and examples are still outstanding — see the
milestone list in `docs/java-tier-plan.md`.

## [0.4.4] — prior state (no changelog before this entry)

First changelog entry; prior versions are documented via git history.
Run `git log --oneline v0.4.4` for the pre-changelog release notes.
