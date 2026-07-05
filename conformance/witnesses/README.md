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
- `method` — a `public` method of the contract (a spending entry point). For a
  contract with more than one public method, the oracle appends the compiled
  method-selector index automatically; witness authors only list the method's
  own args.
- Each fixture SHOULD have ≥1 `accept` and ≥1 `reject` (near-miss) spend, where
  a rejecting witness exists. A few contracts have only tautological asserts
  (`x >= 0 || x < 0`) or are anyone-can-spend, so no rejecting witness exists;
  those carry accept-only spends and say so in each `note`.

## Exemptions — every fixture is witnessed OR exempt

`completeness.test.ts` fails CI if any `conformance/tests/<fixture>` is neither
witnessed here nor listed in one of the two exemption files:

- **`crypto-exempt.json`** — fixtures whose spend needs a REAL cryptographic
  witness (ECDSA/Schnorr checkSig, secp256k1 / NIST-P EC, SHA-256 / BLAKE3 /
  RIPEMD / Merkle hash-preimage, Rabin, or a post-quantum SLH-DSA / WOTS+
  signature). The in-process oracle synthesises witnesses from plain args and
  cannot forge a signature or hash preimage, so these are covered by the Go
  `script_execution_test.go` real-crypto path and the per-family codegen
  goldens. Each entry names the primitive.
- **`harness-inapplicable.json`** — non-crypto fixtures the oracle cannot
  execute for a structural reason: (1) **stateful** — a `StatefulSmartContract`
  auto-injects `checkPreimage` + a state-continuation output, which need a
  tx-context BIP-143 sighash preimage witness the tx-less TS `ScriptVM` cannot
  synthesise (covered by the Go `executeScriptWithTx` tx-context path);
  (2) **go-only** — `compilers:[go]` fixtures have no TypeScript codegen;
  (3) **interpreter-unsupported** — the ANF interpreter does not model the
  raw-script (`asm`) intrinsic. Each entry states its cause and reason.
