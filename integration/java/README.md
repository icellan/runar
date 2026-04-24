# Java integration tests

End-to-end regtest / Teranode tests for the `runar-java` SDK. Ported from
`integration/python/` and `integration/go/` — same contracts, same node
backends, same invariants.

## Status (M13)

Skeleton landed with the following contracts covered:

| Contract    | Deploy | Call            | Source                                              |
|-------------|--------|-----------------|-----------------------------------------------------|
| P2PKH       | yes    | `unlock`        | `examples/ts/p2pkh/P2PKH.runar.ts`                  |
| Counter     | yes    | `increment/decrement` | `examples/ts/stateful-counter/Counter.runar.ts` |
| MathDemo    | yes    | every math builtin    | `examples/ts/math-demo/MathDemo.runar.ts`       |
| Escrow      | yes    | `release/refund`      | `examples/ts/escrow/Escrow.runar.ts`           |
| BitwiseOps  | yes    | `testShift/testBitwise` | `examples/java/.../BitwiseOps.runar.java`    |

Every test also verifies that the `.runar.java` source for the same
contract (where one exists) produces a byte-identical locking script to
the TypeScript reference — proving the Java frontend parser is in sync
with the other six compilers.

## Running

All tests are gated behind the `runar.integration=true` system property
so a bare `gradle test` inside CI without a live node is a no-op (the
wiring smoke tests still run). To actually hit a node:

### Regtest (SV Node)

```bash
cd integration
./regtest.sh start
cd java
gradle test -Drunar.integration=true
```

### Teranode

```bash
cd integration
./teranode.sh start        # ~5 min on first boot (pre-mines 10,101 blocks)
cd java
BSV_BACKEND=teranode gradle test -Drunar.integration=true
```

### Full matrix

```bash
./integration/run-all.sh --start --stop      # every language, including java
```

## Environment variables

| Variable       | Default      | Description                                |
|----------------|--------------|--------------------------------------------|
| `BSV_BACKEND`  | `svnode`     | `svnode` or `teranode`                     |
| `NODE_TYPE`    | `svnode`     | Legacy alias for `BSV_BACKEND`             |
| `RPC_URL`      | auto         | Override the default RPC endpoint URL      |
| `RPC_USER`     | `bitcoin`    | JSON-RPC basic-auth user                   |
| `RPC_PASS`     | `bitcoin`    | JSON-RPC basic-auth password               |

## Implementation notes

- **Artifact compilation.** The TS reference compiler is invoked via
  `npx tsx packages/runar-cli/src/bin.ts compile` to produce the full
  artifact JSON (ABI, stateFields, constructorSlots, ...). The native
  Java compiler CLI in `compilers/java/` only emits ANF and raw
  Bitcoin Script hex today; full-artifact emission lands in milestone
  M8 and will replace the subprocess shell-out here.
- **RpcProvider.** The Java SDK ships only `MockProvider` today; this
  test harness supplies an `RpcProvider` in-tree so tests can deploy
  and spend. Once the SDK adds a first-class on-chain provider the
  harness copy will be deleted in favour of it.
- **Gradle composite build.** `integration/java/settings.gradle.kts`
  pulls `packages/runar-java` in via `includeBuild(...)` so tests
  always run against the source tree, not a published artifact.
