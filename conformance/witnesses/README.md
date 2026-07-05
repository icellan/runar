# Per-fixture spend witnesses (TS-GAP-004)

Each `<fixture>.json` declares concrete spend attempts for the differential
execution oracle (`packages/runar-testing/src/oracle/differential-execution.ts`).
The oracle compiles the fixture to its **fold-ON deployed bytes**, runs the
declared spend through the ANF interpreter (source semantics) *and* through the
`@bsv/sdk`-backed `ScriptVM` (script semantics), and asserts both engines agree
on accept/reject — catching a bug all seven compilers share (byte-identical but
wrong). Every non-crypto conformance fixture SHOULD have one.

Schema:

    {
      "fixture": "arithmetic",
      "constructorArgs": { "target": "27n" },
      "spends": [
        { "method": "verify", "args": ["3n", "7n"], "expect": "accept",
          "note": "10 + (-4) + 21 + 0 = 27" },
        { "method": "verify", "args": ["3n", "6n"], "expect": "reject",
          "note": "near-miss: result 24 != target 27" }
      ]
    }

- `fixture` — the directory name under `conformance/tests/`. The `.runar.ts`
  source is resolved from that fixture's `source.json` (`sources[".runar.ts"]`).
- `args` and `constructorArgs` use the trailing-`n` convention for bigints
  (`"27n"`, `"-4n"`), `true`/`false` for booleans, and `"0x…"` for byte strings.
- `method` — a `public` method of the contract (a spending entry point).
- Each fixture MUST have ≥1 `accept` and ≥1 `reject` (near-miss) spend.
- Crypto-bearing fixtures (checkSig / EC / PQ / hash-preimage) cannot be spent
  by the in-process oracle with synthesised witnesses; they are covered by the
  Go `script_execution_test.go` real-crypto path instead and are listed in
  `crypto-exempt.json` with a reason. A fixture is either witnessed here or
  listed there — `completeness.test.ts` enforces that no fixture is silently
  absent.
