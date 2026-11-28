# security-lab — attacker's view of the Rúnar TypeScript reference compiler

Goal: assume the compiler is the adversary's attack surface. Take the shipped
example contracts, spend their real compiled Script with witnesses an attacker
chooses, and see which spends the consensus engine accepts that should not have
been — or refuses spends that must work.

Everything runs the **compiled bytes** through `@bsv/sdk`'s production `Spend`
(real secp256k1, real BIP-143 sighash, real opcode rules). The ANF interpreter is
used only as a cross-check, never as the verdict. Anything involving time, fees,
finality or standardness is additionally re-checked against a **real Bitcoin SV
regtest node** (`onchain/`).

Results and code pointers: **[`FINDINGS.md`](./FINDINGS.md)**. Current standing
against `main`: F-1, F-2 and the acute form of F-3 are **fixed** and this suite is
their regression coverage; **F-4 (sighash mode not pinned on stateless contracts)
is still open** — all six hashTypes are still accepted by a 2-of-2 escrow.
**Starting the next round? Read [`PLAYBOOK.md`](./PLAYBOOK.md) first** — bring-up
commands, helper map, the traps that cost time last round, and the evidence format
a finding has to follow.

## Run

```bash
npx vitest run security-lab                 # offline (Spend-based) suite
npx vitest run security-lab --silent=false  # ... and keep the per-attack evidence lines
npx vitest run security-lab/freeze.attack.test.ts -v
npx tsc -p security-lab                     # types (vitest only transpiles; see PLAYBOOK §1.1)
```

Vitest 5 hides `console.log` from passing tests, and almost every attack here
reports by logging what the engine said. `--silent=false` is what CI passes; add
it whenever you are reading output rather than a pass/fail count.

All three commands run in CI: `npx tsc -p security-lab` and
`npx vitest run security-lab --silent=false` in the `ts-compiler` job, and the
on-chain suite in the `integration` job right after the TypeScript integration
tests, where the regtest node is already up.

### On-chain — real regtest node

```bash
cd integration && ./regtest.sh start      # bitcoinsv/bitcoin-sv, RPC :18332
cd ../security-lab && npx vitest run      # onchain/** only, serialized
npx vitest run onchain/locktime.onchain.test.ts   # one file (from security-lab/)
cd ../integration && ./regtest.sh status  # or: stop | clean | restart
```

`security-lab/vitest.config.ts` scopes the on-chain run to `onchain/**`, reuses
the `runar-*` source aliases plus `integration/ts/helpers`, keeps
`fileParallelism: false` (workers mining on one tip in parallel drop
transactions — 10-of-16 vs 0-of-16, per `integration/ts/vitest.config.ts`), and
`onchain-setup.ts` refuses to run unless the chain is `regtest`. Note that this
node runs `acceptnonstdtxn=0`, so it enforces post-Genesis standardness at mempool
acceptance: a witness the `Spend` harness accepts can still be refused as
non-standard, and the RPC error code tells you which kind of finding you have.

`vitest` picks this directory up from the repo-root `vitest.config.ts` aliases,
so the tests import `runar-compiler` / `runar-sdk` / `runar-testing` from source,
not from `dist`.

One environment note: this checkout's top-level `node_modules/*` symlinks pointed
at a sibling directory (`../runar-grok/…`) that no longer has a `.pnpm` store, so
nothing resolved. Eight dangling links were re-pointed at this tree's own
`node_modules/.pnpm` store. No package versions changed.

## Files

| file | what it does |
| --- | --- |
| `harness.ts` | attacker-side toolkit: compile, hand-build unlocking scripts, real BIP-143 signatures for an arbitrary tx context and sighash scope, single-input spend, full deploy→call chains with several signers, real-engine validation of one tx input, state readback off the wire. |
| `escrow.attacks.test.ts` | 2-of-2 dual-sig escrow: arity, junk, selector probing, sighash downgrade, signature/output mixing, method-crossing. |
| `multisig.attacks.test.ts` | `OP_CHECKMULTISIG` layout: key order, duplicate keys, extra/missing sigs, sighash downgrade, cross-UTXO witness replay. |
| `auction.attacks.test.ts` | stateful auction: pot drain, fictitious bids, the whole nLockTime gate, wrong-signer and `newState` positive controls, negative/oversized bid amounts. |
| `locktime.attacks.test.ts` | signed-uint32 extraction: unsatisfiable post-2038 deadline, and the #131 sequence guard proven vacuous. |
| `numeric.attacks.test.ts` | numeric domain of preimage fields and of 8-byte state words; what the SDK refuses to serialize. |
| `pot.attacks.test.ts` | "state is a number, not coins": TicTacToe prize-pool drain over a real multi-move game, and deposit/withdraw ledger divergence with negative and oversized arguments. |
| `varlen.attacks.test.ts`, `varlen.boundary.test.ts` | variable-length state field splice, mapped over a 15×15 grid of field lengths. |
| `freeze.attack.test.ts`, `freeze.boundary.test.ts`, `freeze.tamper.test.ts` | the 129–255 byte freeze: exact window, drive-by on `MessageBoard`, and proof that verification below the window is still sound. |
| `sweep.test.ts` | classifies all 84 `examples/ts` contracts by exposure (timelock, anyone-can-spend, money-in-state, multi-output, script size). |
| `varlen-exposure.test.ts` | which examples let an **unauthenticated** caller write an attacker-chosen byte string into state. |
| `onchain/freeze.onchain.test.ts` | **live node**, now a regression guard for F-2: the 200-byte post is mined, and the follow-up spend of that same UTXO is accepted and mined too, with the new 8-byte message read back off the chain. Was: mined, then every later spend rejected `Invalid OP_SPLIT range`. |
| `onchain/locktime.onchain.test.ts` | **live node**, guards F-1/D26: a locked withdrawal is held out of every block until its deadline; a satisfied one goes straight into a block; a withdrawal that leaves its input final is rejected `mandatory-script-verify-flag-failed`; a post-2038 timestamp locktime is parked as non-final rather than failing the script. Also documents that the parked transaction cannot be re-sent (`Transaction already in the mempool`). |
| `tsconfig.json` | strict typecheck for this directory (extends the repo base: strict + `noUncheckedIndexedAccess` + `noUnusedLocals`). Needed because there is no `package.json` here, so `pnpm run typecheck` skips it and vitest only transpiles. CI runs it. |
| `PLAYBOOK.md` | instructions for the next round: bring-up, helper map, attack catalogue with ✔/⚑/✖, documentation format, suggested first five tasks. |

## Rules this suite had to learn the hard way

Two of them are now enforced by the compiler itself, so a contract written
before them simply does not compile:

* **A locktime gate must name its domain and pin its sequence.**
  `assert(extractLocktime(p) < 500000000n)` for a height gate (or `>=` for a
  timestamp gate) and `assert(extractSequence(p) !== 0xffffffffn)`, or D26
  refuses the contract.
* **A stateful continuation must carry at least the satoshis of the UTXO it
  spends** (D25). In this harness that means an explicit
  `callOptions.satoshis` *below* the contract input is an attack, and the spend
  is supposed to fail: honest paths go through `fundingFor()` in `harness.ts`,
  which pads the signing UTXOs instead of shrinking the continuation. The
  auction's `continuationAmount() >= extractAmount(p) + bidAmount` makes the
  auction stricter still, so auction paths fund `pot + bid`.
* **On-chain time travel is expensive.** Finality for a timestamp `nLockTime` is
  judged against the median time past of the previous 11 blocks, so mining a
  post-2038 locktime needs 12 blocks on a mocked clock — and rolling those back
  with `invalidateblock` put the node into safe mode and starved everything else
  sharing it. Timestamp-domain claims are proved offline; the node covers the
  height domain.

## Attack catalogue used

Used to keep the exploration systematic; ✔ = exercised here, ⚑ = verified against
the regtest node, ✖ = not yet.

1. **Witness shape** — wrong arity, extra junk above/below the real witness,
   empty pushes, non-minimal number encodings, out-of-range and negative method
   selectors. ✔
2. **Signature semantics** — wrong party, wrong order, replay across methods,
   replay across UTXOs, duplicate public keys in a threshold, sighash-type
   downgrade (`NONE`, `SINGLE`, `ANYONECANPAY`), a signature taken over a
   different output set. ✔ — and the downgrade is the one high-severity finding
   still open on main (malleability / low-S: ✖)
3. **Numeric domain** — negative amounts, amounts ≥ 2^31 and ≥ 2^63, basis
   points > 10 000, division by a witness zero, overflow in `mulDiv`/`percentOf`,
   signed-vs-unsigned reading of the uint32 preimage fields. ✔
4. **Time and finality** — nLockTime as an attacker-chosen field, missing
   sequence guard, block-height vs timestamp confusion, post-2038 deadlines.
   ✔ ⚑ (both directions confirmed on-chain; relative locktime / CSV still ✖. The
   node also showed that a parked non-final transaction is **not** auto-mined once
   it becomes final, and that re-sending the same bytes is refused as
   `Transaction already in the mempool` — so a client has to re-*issue* the spend,
   not re-broadcast it)
5. **Value binding** — is the "amount" in state tied to the satoshis in the
   UTXO, to the input value, to the change output's owner; can a caller shrink
   the pot mid-lifecycle. ✔
6. **State serialization** — variable-length fields across push-encoding
   boundaries, fields whose neighbour is a fixed-width word, two-step round
   trips, tampered continuations. ✔ ⚑ (the 129–255 freeze was node-confirmed and
   is fixed — the on-chain test now guards its absence; OP_PUSHDATA2 lengths and
   >10 000-byte generated scripts still ✖)
7. **Dispatch and branch coverage** — selector reachability, per-branch checks,
   private-helper inlining, assertion dropped on one path. ✔ partially
   (branch-arm soundness under constant folding is still a gap: ✖)
8. **Deployment-time footguns** — duplicate keys, oversized fields, a readonly
   property baked as `OP_0`, a script over consensus size limits. ✔ partially
   (script-size and stack-element limits for the post-quantum examples: ✖)

## Extending

`harness.ts` is deliberately low-level: `spendStateless` takes any list of stack
items (or raw script bytes) plus a full transaction context, and
`validateInput` re-checks any input of any transaction against its real parent,
with an optional mutation callback. To add an attack, write the spend, and let
the engine be the judge — if it returns `true`, the funds move.
