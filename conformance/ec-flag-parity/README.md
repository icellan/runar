# EC codegen flag parity

`expected.json` pins, for every EC / NIST-curve emitter and every combination of
the experimental size flags, the **exact serialized script** the TypeScript
reference compiler produces — as a byte count plus a SHA-256 of the script
bytes.

## Why this file exists

The size optimizations (`constantPool`, `reductionSinking`, `fixedBaseComb`)
default OFF, so the ordinary cross-tier conformance suite — which compiles with
defaults — cannot see them at all. Seven tiers could each ship a *different*
`--ec-constant-pool` and the suite would stay green.

That matters because the flags are not cosmetic: they change which reduction
form is emitted and which addition formula each ladder round uses. A tier that
ports the constant pool but not the sign lattice's `Reduced` precondition
produces a script that is smaller, passes its own tests, and is wrong on
`ecAdd((0,1), (2^256-1,1))`. Byte-identical output against a single reference is
the only cheap check that catches that.

## Regenerating

`expected.json` is derived, never hand-edited:

```
npm run --prefix conformance ec-flag-parity:generate
```

`ec-flag-parity.test.ts` re-derives it in-process and fails if the checked-in
file has drifted, so a deliberate codegen change shows up as a fixture diff to
review rather than as a silently stale pin.

## Consuming it from a tier

Each compiler's test suite reads this file and asserts that its own emitters,
under the same flags, hash to the same value. See
`compilers/go/codegen/ec_flag_parity_test.go` for the reference consumer.

## Raw vs post-peephole

Each entry carries two measurements:

- the top-level `bytes` / `sha256` — the **raw emitter output**, before the
  peephole pass;
- `postPeephole` — the same script after `optimizeStackIR`, i.e. what the
  compiler actually ships.

Six tiers reproduce the raw output op for op, so they assert the raw SHA-256:
the sharpest gate available. The **Zig tier cannot**, in exactly one place.
`emitEcMul` there emits `k + 3n` pre-folded, because that tier's peephole
reassociates only `i64` `push_int` chains (`peephole.zig` rule 27) and a 256-bit
constant is a `push_data` blob in Zig's IR. The reference emits three `+n` steps
that its own peephole collapses to the same thing — identical shipped bytes,
different pre-peephole spelling.

So the Zig consumer gates on the raw byte COUNT with that one divergence
asserted exactly (`ec_flag_parity_test.zig#allowedDelta`), and whole-script byte
identity is covered end to end by compiling the same contract through the Zig
CLI and the TypeScript one and diffing the hex.
