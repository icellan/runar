# `conformance/analyzer/` — Bitcoin Script Analyzer Conformance Subsuite

This is a sibling subsuite to the main Stack-IR / hex conformance flow.
It verifies that every Rúnar tier's Bitcoin Script static analyzer
produces byte-identical output for the same input hex script.

## Layout

```
conformance/analyzer/
  README.md
  scripts/
    generate-goldens.ts        # one-shot golden generator (TS reference)
  <fixture>/
    expected-analyzer-report.json   # canonical golden, one per fixture
```

Input hex is **shared** with the main conformance suite — it is read
verbatim from `../tests/<fixture>/expected-script.hex`. No hex
duplication.

## Fixtures (8)

The canonical fixture set is:

| Name              | Why                                                  |
|-------------------|------------------------------------------------------|
| `basic-p2pkh`     | Smallest realistic locking script (P2PKH template)  |
| `escrow`          | Multi-arg signature flow                             |
| `stateful-counter`| Stateful contract — exercises CODESEPARATOR finding |
| `auction`         | Branching, multiple paths, stateful                 |
| `covenant-vault`  | Covenant patterns                                    |
| `ec-demo`         | EC primitives — large script, paths truncated       |
| `schnorr-zkp`     | Schnorr ZKP — large script, many branches           |
| `if-else`         | Minimal IF/ELSE — exercises path analysis           |

(`multisig` is intentionally deferred and will land as a 9th fixture
after BUG-009 lands and regenerates that fixture's hex output.)

## Spec

The cross-tier contract is `spec/script-analyzer-format.md`. The TS
implementation at `packages/runar-testing/src/analyzer/` is the
reference and produced these goldens.

## Regenerating goldens

The goldens are generated from the TS reference via:

```bash
./node_modules/.pnpm/node_modules/.bin/tsx \
  conformance/analyzer/scripts/generate-goldens.ts
```

This regenerates **all 8 goldens** from the current TS reference.
Any change must be paired with a spec update.

## Running the conformance suite

(Driver lands once at least one non-TS tier ships its analyzer.)

```bash
# planned
pnpm --filter runar-conformance test:analyzer
```

The driver iterates over `(fixture, tier)` pairs and diffs each tier's
JSON output against the golden. Any byte-level mismatch is a failure.
