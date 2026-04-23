# runar-java

Rúnar language runtime and deployment SDK for Java. Parallel to
`runar-go`, `runar-rs`, `runar-py`, `runar-zig`, and `runar-rb`.

## Status

**Phase 1 — skeleton.** Exposes the minimum surface required for a
native Java contract to compile against: `SmartContract` /
`StatefulSmartContract` base classes, a handful of domain types, the
`@Public` / `@Readonly` / `@Stateful` annotations, and stubbed
`Builtins` static methods (`assertThat`, `hash160`, `checkSig`). All
methods throw at runtime — the real implementations arrive in
milestone 8.

See [`docs/java-tier-plan.md`](../../docs/java-tier-plan.md) for the
full roadmap.

## Requirements

- JDK 17 (compile target). JDK 21 LTS works for local development.
- Gradle 8.5+.

## Build & Test

```bash
cd packages/runar-java
gradle build
```

## Package Layout

- `runar.lang` — base classes, `Builtins`, `CompileCheck` (later).
- `runar.lang.annotations` — `@Public`, `@Readonly`, `@Stateful`.
- `runar.lang.types` — `Addr`, `Sig`, `PubKey`, `ByteString`, and
  peers. Mirrors the branded types in `packages/runar-lang/src/types.ts`.
- `runar.lang.runtime` — off-chain simulator (milestone 11).
- `runar.lang.sdk` — deployment SDK: `RunarContract`, `Provider`,
  `Signer`, transaction builders, `PreparedCall` (milestones 8–10).
