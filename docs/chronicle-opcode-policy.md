# The Chronicle Opcode Policy

Rúnar compiles for **Chronicle**, the BSV node opcode policy introduced by SV Node
v1.2.0. Scripts this compiler produces can contain opcodes that only carry their
intended meaning under that policy. This page says which opcodes, which contract
shapes, and what happens if a script reaches something that has not upgraded.

## Activation status

Chronicle activated on **BSV mainnet at block height 943,816 on 7 April 2026**. It
was a mandatory node upgrade: operators had to run SV Node v1.2.0 or later before
that height.

So this is a **compatibility** note, not a "do not deploy" warning. Contracts
compiled by Rúnar are spendable on mainnet today. What is still worth knowing is
that not every piece of *tooling* around the network follows the node's policy —
see [Pre-Chronicle tooling](#pre-chronicle-tooling) below — and a library still on
the old policy will not evaluate these scripts the way a miner does.

If you are deploying to a private network, a regtest node, or an older node
build, check its policy before you fund anything.

## The opcodes

The emitter's opcode table (`packages/runar-compiler/src/passes/06-emit.ts`)
carries seven Chronicle codepoints:

| Opcode | Byte | Pre-Chronicle meaning | Emitted by Rúnar today |
|---|---|---|---|
| `OP_2MUL` | `0x8d` | disabled | yes |
| `OP_2DIV` | `0x8e` | disabled | yes |
| `OP_SUBSTR` | `0xb3` | `OP_NOP4` | no |
| `OP_LEFT` | `0xb4` | `OP_NOP5` | no |
| `OP_RIGHT` | `0xb5` | `OP_NOP6` | no |
| `OP_LSHIFTNUM` | `0xb6` | `OP_NOP7` | yes |
| `OP_RSHIFTNUM` | `0xb7` | `OP_NOP8` | yes |

`OP_SUBSTR`, `OP_LEFT` and `OP_RIGHT` are present in the table for completeness;
no codegen path emits them. Note that the ordinary `<<` and `>>` operators
compile to `OP_LSHIFT` (`0x98`) and `OP_RSHIFT` (`0x99`), which are Genesis-era
opcodes and are **not** affected by any of this.

## Which contracts are affected

**Every stateful contract.** `StatefulSmartContract` methods carry a 428-byte
`checkPreimage` binding blob (`packages/runar-compiler/src/passes/oppushtx-codegen.ts`)
that binds the spend to the transaction. Its low-S normalisation step uses
`OP_2MUL`. The blob is emitted as raw script bytes, so it does not show up as
`OP_2MUL` in `--asm` output — it appears as `<raw 428 bytes>` — but the byte is
there, at a real opcode boundary.

**Any contract using EC, NIST P-256/P-384, or Merkle primitives.** `ecMul`,
`ecMulGen`, the P-256/P-384 verifiers and `merkleRootSha256` emit `OP_2MUL`,
`OP_2DIV` and `OP_RSHIFTNUM` in their scalar ladders and index arithmetic. This
applies whether or not the contract is stateful.

**Not affected:** plain stateless contracts that stick to hashing, signatures,
arithmetic, bitwise and shift operators, and byte-string manipulation. P2PKH,
multisig, escrow, oracle feeds, BSV-20/BSV-21 tokens, ordinals, the SHA-256 and
BLAKE3 helpers, and the WOTS+ / SLH-DSA post-quantum verifiers all compile to
scripts with no Chronicle codepoint in them.

To check a specific contract, compile it and look for the bytes `8d`, `8e` and
`b3`–`b7` at opcode boundaries, or check whether its script embeds the
`checkPreimage` binding blob.

## What a pre-Chronicle evaluator does

The two groups fail differently, and the difference matters.

**`OP_2MUL` and `OP_2DIV` are disabled opcodes pre-Chronicle.** Evaluating one
aborts the script with a `disabled opcode` error. This is a clean, loud
rejection — you get an error, not a wrong answer. Since post-Genesis the check
fires only on the branch actually executed, a disabled opcode sitting in an
untaken branch does not abort.

**`0xb3`–`0xb7` are upgradable NOPs pre-Chronicle.** `OP_RSHIFTNUM` decodes as
`OP_NOP8`, `OP_LSHIFTNUM` as `OP_NOP7`, and so on. At the consensus layer a NOP
is a **no-op: it does nothing and execution continues**. It aborts only when the
evaluator applies the `DISCOURAGE_UPGRADABLE_NOPS` flag, which is a relay-policy
rule rather than a consensus rule.

That asymmetry is the important part. A stale evaluator that hits `OP_2MUL`
tells you something is wrong. A stale evaluator that hits only `OP_RSHIFTNUM`
can run the script to completion and hand back a **silently incorrect result** —
the shift never happens, and whatever the script computed from it is garbage.
Do not read "it executed without error" from a pre-Chronicle tool as "it is
correct".

In today's codegen, every primitive that emits `OP_LSHIFTNUM` or `OP_RSHIFTNUM`
also emits `OP_2MUL` or `OP_2DIV` nearby, so in practice a pre-Chronicle
evaluator aborts before the silent-NOP case can bite. That is a property of the
current code, not a guarantee, and it depends on which branch executes first.
Do not build on it.

Both behaviours are pinned upstream in the Go SDK's port of the SV Node
Chronicle functional tests (`script/interpreter/chronicle_opcodes_test.go`):
`OP_2MUL` / `OP_2DIV` yield `ErrDisabledOpcode`, while `0xb3`–`0xb7` yield
`ErrDiscourageUpgradableNOPs` *only* when that flag is set.

## Pre-Chronicle tooling

The policy is a property of each evaluator, not of the chain alone:

- **Go** — `github.com/bsv-blockchain/go-sdk` supports both. Rúnar's Go-tier
  tests opt in with `interpreter.WithAfterChronicle()`, which is also what lifts
  the 520-byte element cap.
- **TypeScript** — `@bsv/sdk` implements the Chronicle opcodes, so
  `ScriptVM` and the differential oracles evaluate these scripts correctly.
- **Rust** — the `bsv-sdk` crate still implements the pre-Chronicle policy and
  hard-disables `OP_2MUL` with no configuration escape, so it cannot
  script-validate a Rúnar covenant; those inputs are bucketed `unvalidatable`.
  This is documented and pinned in
  [`docs/audit/upstream-bsv-sdk-op2mul-chronicle.md`](audit/upstream-bsv-sdk-op2mul-chronicle.md).

If you validate Rúnar output with any other library, confirm it implements the
Chronicle policy before trusting a pass or a fail.

## Local test nodes

`integration/regtest.sh` sets `chronicleactivationheight=1` in the generated
`bitcoin.conf`, alongside `genesisactivationheight=1`. That makes the regtest
node enforce the same post-Chronicle rules mainnet enforces today, which is what
you want from an integration node — a regtest node left on the pre-Chronicle
policy would reject spends that mainnet accepts.

If you run your own node for Rúnar contracts, set the same option, or use a node
already past the mainnet activation height.

## See also

- [`docs/language-reference.md`](language-reference.md) — shift and bitwise operator semantics
- [`docs/audit/upstream-bsv-sdk-op2mul-chronicle.md`](audit/upstream-bsv-sdk-op2mul-chronicle.md) — why the Rust tier cannot replay covenants
- [`spec/opcodes.md`](../spec/opcodes.md) — the full opcode surface
- SV Node v1.2.0 release notes — the authoritative activation record
