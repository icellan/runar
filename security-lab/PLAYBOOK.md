# PLAYBOOK — how to run a Rúnar security round (next round: start here)

Written by the previous round's agent, for the next one. It records what worked,
what the tooling actually does (verified on this machine, not from the docs), and
the rules that keep the output usable.

---

## 0. Hard rules

1. **Work only inside `security-lab/`.** Do not edit `packages/`, `compilers/`,
   `conformance/`, `examples/`, or `integration/`. You may *read* anything and
   *import* `integration/ts/helpers/*` from your tests. A finding is a bug
   report, not a patch — if you think you know the fix, write it in
   `FINDINGS.md` under **Fix** and leave the code alone. Anyone's one-line fix
   that lands while you are measuring invalidates your baseline.
2. **The verdict comes from an engine, never from an opinion.** Offline that
   means `@bsv/sdk`'s `Spend`; for anything involving time, fees, finality,
   standardness or relay, it means the **regtest node**. If you cannot make the
   engine say yes/no, you have a question, not a finding.
3. **Every attack test needs its control.** An attack that "succeeds" on a
   harness which would also accept an obviously-invalid witness proves nothing.
   Pair each accept-should-fail attack with a reject-must-hold control, and label
   it in the test name (`P1`, "control", "positive control").
4. **Never print-only.** Each test either asserts, or is named
   `informational:` and is understood by the reader to be a measurement. If a
   test passes on an assertion that can never be false, that is a bug in the
   test (see the vacuous-guard example in §5).
5. `npx vitest run security-lab` **and** `npx tsc -p security-lab` must both be
   green when you finish. Red gets fixed or deleted, not left dangling. CI runs
   both (`ts-compiler` job: "Typecheck security lab", then "Security lab —
   attacker-vs-compiled-script suite"), so a yellow typecheck is a broken build,
   not a suggestion.
7. Document as you go, in the same commit mindset as code — see §6. Do not
   leave a "I'll write it up later" step; the write-up *is* the deliverable.

---

## 1. Environment bring-up

### 1.1 Offline suite (no Docker)

```bash
cd <repo root>
npx vitest run security-lab            # Spend-based suite
npx vitest run security-lab -t "freeze" # one family
npx tsc -p security-lab                # types (see the note below)
```

This uses the repo-root `vitest.config.ts` aliases, so `runar-compiler`,
`runar-sdk`, `runar-testing` resolve to **source**, not `dist`. No build step is
required, and you must not need one.

`tsc` needs its own command: `security-lab/` has no `package.json`, so turbo's
per-package `pnpm run typecheck` skips it, and vitest transpiles with esbuild
which strips types without checking them. `security-lab/tsconfig.json` extends the
repo base config (strict, `noUncheckedIndexedAccess`, `noUnusedLocals`) —
stricter than `integration/ts/tsconfig.json`, deliberately, because this directory
asserts on engine internals where a wrong field name otherwise reads as a pass.
It also typechecks the `integration/ts/helpers` the on-chain tests import, so an
error in those files lands on you: fix it there (it is a real bug, and it is
small) rather than loosening this config.

**Known trap on this machine:** the top-level `node_modules/*` symlinks pointed at
a sibling checkout (`../runar-grok/node_modules/.pnpm/...`) that no longer
exists, so nothing resolved and `npx vitest`/`npx tsx` died with
`Cannot find module`. Fix (8 links at the time of writing): walk
`node_modules/**`, and for any symlink whose target contains `runar-grok`,
re-point it at the same path under this checkout if that path exists. `node
--import tsx` is still broken; run scripts as vitest tests instead.

### 1.2 Regtest node (required for the on-chain round)

```bash
cd integration && ./regtest.sh start          # docker, ~5 s if the image is cached
curl -s -u bitcoin:bitcoin -X POST http://localhost:18332 \
  -d '{"jsonrpc":"1.0","id":"1","method":"getblockcount","params":[]}'
cd ../security-lab && npx vitest run          # onchain/** only
```

Facts about this node, verified here (they change how you must test):

- Image `bitcoinsv/bitcoin-sv:latest`, container `runar-integration-regtest`,
  RPC 18332 / P2P 18333 / ZMQ 28332, data in `integration/regtest-data/n1`.
  Multi-instance: `./regtest.sh start <name>` allocates hashed ports — then pass
  `RPC_URL=http://localhost:<port>` in the environment.
- `setup.ts` / `onchain-setup.ts` refuse to run unless `getblockchaininfo.chain
  === 'regtest'`, and mine to height 101 so coinbase is spendable. Keep that
  guard; it is what stops an attack round from spending real money.
- **`fileParallelism: false` is mandatory.** Two vitest workers mining on the
  same tip build competing blocks and the loser's transactions are dropped —
  measured in `integration/ts/vitest.config.ts`: 10 of 16 funding txs unconfirmed
  in parallel, 0 of 16 serialized. Never "fix" a slow on-chain suite by turning
  this back on.
- `integration/regtest.sh` writes `acceptnonstdtxn=0` plus
  `genesisactivationheight=1`, so the node **enforces post-Genesis standardness
  at mempool acceptance**: CLEANSTACK, NULLFAIL, NULLDUMMY, minimal-push. Two
  consequences:
  - a witness your `Spend` harness happily accepted can be rejected by
    `sendrawtransaction` for a *policy* reason. Always record which one happened
    (`mandatory-script-verify-flag-failed` = consensus; anything else = policy) —
    a policy reject is still a real-world blocker but not a consensus bug, and a
    miner can still include it.
  - the reverse is also true: a consensus-valid non-standard tx is a finding,
    just a "needs a cooperative miner" finding. Say so.
- `minminingtxfee=0.00000001`, and — documented in `helpers/node.ts` and seen
  first-hand — a zero-fee tx sits in the mempool for ~1000 blocks without ever
  entering a block. Hand-built transactions must carry a fee.
- **Non-final transactions go to a third pool** (`getrawnonfinalmempool`) and are
  *not visible to `getrawtransaction`*. Measured: a tx with `nLockTime` 60 blocks
  ahead and `sequence=0xfffffffe` was still sitting in that pool two blocks after
  its deadline passed, unmined. The pool is not a scheduler, so a broadcaster must
  re-send after finality — and a "never mined" result there is an SDK finding, not
  a consensus one. Any
  timelock/sequence finding has to state this.
- regtest halves every 150 blocks; if `getbalance` drops below ~1 BTC,
  `./regtest.sh clean && ./regtest.sh start` (this wipes chain state — say so
  before you do it to someone else's node).
- Do **not** `clean` or `docker rm` the node mid-investigation; you lose the
  UTXOs your findings reference. Note txids in your test output so a finding can
  be re-checked on the running chain.

---

## 2. What already exists in `security-lab/`

`harness.ts` (offline, Spend-based) — the pieces worth reusing:

| helper | use it for |
| --- | --- |
| `build(source, fileName, bake)` | compile + fail loudly; `bake` supplies readonly constructor values by name, or the compiler errors with "would carry an OP_0 placeholder" |
| `push`, `scriptNum(n, {bytes, negative})`, `hex`, `encodeStackItem` | hand-built pushes, non-minimal and negative script numbers |
| `spendStateless(compiled, { stack, raw, ctx })` | arbitrary unlocking script against an arbitrary tx context; returns `{ ok, error, asm }` with the engine's real opcode error |
| `signFor(keyName, lockingHex, ctx, scope)` | real DER signature over a chosen BIP-143 scope (this is how sighash downgrade gets tested) |
| `preimageFor(lockingHex, ctx)` | the exact preimage bytes `Spend` will build |
| `deployAndCall(...)`, `callChain(...)` | deploy → N calls, each signed by a different key; `callOptions` exposes every caller-side knob (`satoshis`, `changePubKey`, `newState`, `locktime`, `sequence`) |
| `validateInput(tx, i, sourceTx, outIdx, mutate?)` | re-validate one input of a real transaction, with an optional mutation (tamper the amount, corrupt the continuation output) |
| `stateOf(artifact, tx)`, `asm(hex)` | read the state section and disassembly back off the wire |
| `key(name)` | `TEST_KEYS` (alice/bob/charlie) — real curve points |
| `Compiled` (return type of `build`) | `CompileResult` narrowed so `scriptHex`/`artifact` are `string`/`RunarArtifact`, not optional — `build` already ran that guard, so call sites must not re-prove it |
| `outSats(tx, i=0)`, `inSeq(tx, i=0)` | output satoshis / input nSequence with the SDK's optional fields resolved; `tx.outputs[0]!.satoshis` is `number \| undefined` and cannot be compared or logged as a number |
| `fundingFor(requested, floor)` | signing-UTXO amounts that satisfy the caller's `callOptions.satoshis` **and** D25's rule that a continuation carries at least its input. Use it whenever a test pins an explicit output amount; `deployAndCall`/`callChain` already do. |
| `inputSatoshis(input)` | satoshis behind an input, via its `sourceTransaction`. Returns `'?'` for a tx parsed from hex (no parents attached) — when the number matters, read `outSats(r.deployTx)` instead |
| `firstLine(msg, max=110)` | first line of a diagnostic. `msg.split('\n')[0]` is `string \| undefined` under `noUncheckedIndexedAccess`; without this, typing an error message becomes a reason to log less |

**Trap (new since D25):** a `callOptions.satoshis` below the contract UTXO is no
longer a neutral way to set an output amount — it is refused by the covenant and
by `MockProvider` before broadcast. When a control path fails with
`OP_VERIFY requires the top stack value to be truthy` or a fee-floor complaint,
check the funding before believing you found a bug.

**Trap:** `spendStateless` takes `stack` items as *payloads* and adds the push
prefix itself. Passing a raw signature as an already-encoded push (a mistake made
twice last round) produces nonsense like `OP_XOR requires the top two stack
items to be the same size`, because a DER byte executes as an opcode. Use
`{ raw }` only for pre-encoded scripts.

**Trap:** fake pubkeys like `03` + `bb`×32 are not curve points. `Spend` fails
with `The public key is in an unknown format`, which looks like a layout bug and
is not. Use `key('alice').pubKey`.

On-chain plumbing (`security-lab/onchain/*`, reusing `integration/ts/helpers`):

- `security-lab/vitest.config.ts` — on-chain run config: same `runar-*` aliases,
  600 s timeouts, `fileParallelism: false`, `include: ['onchain/**/*.test.ts']`,
  `globalSetup: ./onchain-setup.ts`, `env.RUNAR_ONCHAIN='1'`.
- `onchain/gate.ts` — `onchain(name, fn)` wraps every on-chain `describe`. The
  repo-root config also collects `security-lab/onchain/**`, and it does *not*
  serialize workers, so without the gate `npx vitest run security-lab` would mine
  two suites against one tip and report scheduling races as attack results. When
  the var is absent the suite skips with a message telling the reader the right
  command. Keep it: any new `onchain/*.test.ts` must use `onchain(...)`, not
  `describe(...)`. Run it with `cd security-lab && npx vitest
  run`; the offline suite keeps running from the repo root unchanged.
- `onchain-setup.ts` — node reachability + `chain === 'regtest'` + mine to 101 +
  balance floor.
- helpers you should import rather than reimplement: `compileContract`
  (repo-relative path) / `compileSource` (inline source), `createWallet`,
  `createFundedWallet`, `createProvider` (`autoMine: true`),
  `createBatchProvider` (`autoMine: false` — use this whenever height matters),
  `rpcCall`, `mine`, `mineUntilConfirmed(txid, maxBlocks)`, `describeUnmined`,
  `readOnChainState`, `assertOnChainState`.
- `readOnChainState` exists for a reason: `contract.state` is the SDK's off-chain
  ANF prediction, and a miscompile can make the on-chain script commit a wrong
  state that the off-chain prediction agrees with (PALMER-1). Decode the
  broadcast script bytes instead.
- `createFundedWallet` hands back an `ExternalSigner` whose callback hardcodes
  `sigHashType ?? 0x41`. For sighash experiments write your own signer (copy
  `wallet.ts`'s 10 lines) — do not assume you can pick the scope through the SDK.

---

## 3. The loop, step by step

1. Pick an attack class (§4 catalogue) and a contract — examples first, then a
   minimal synthetic contract in a template string (that is how the locktime and
   variable-length findings became crisp: `compileSource(VAULT, 'Vault.runar.ts')`
   with a 12-line contract instead of a 1.8 KB auction script).
2. Write the offline test. Print the ASM (`asm(scriptHex)`) and the engine's
   exact error text. Read the error, do not paraphrase it.
3. Locate the mechanism in the compiler. `grep -n` the emitted opcode sequence in
   `packages/runar-compiler/src/passes/05-stack-lower.ts` / `04-anf-lower.ts` and
   put `file:line` in the finding. A finding without a code pointer is a
   reproduction request, and a finding whose mechanism you guessed wrong gets
   "fixed" the wrong way.
4. Prove it on the node (§3.1). Note the RPC reject code and/or the block height
   it landed in.
5. Check breadth: which examples carry the same exposure? `sweep.test.ts`
   classifies all 75 `examples/ts` contracts; `varlen-exposure.test.ts` shows the
   pattern for "who can write this field, and must they sign?".
6. Write it up (§6), keep the suite green, and record what you did *not* cover.

### 3.1 Turning an offline finding into an on-chain one

Map each claim to the node question that settles it:

| offline claim | node question | how |
| --- | --- | --- |
| "the covenant accepts this witness" | does `sendrawtransaction` accept it, and does it get mined? | `createBatchProvider()`, `mineUntilConfirmed` |
| "this spend is now impossible" | is the rejection `mandatory-script-verify-flag-failed`, i.e. consensus? | catch the RPC error, assert on the code |
| "a timelock is bypassed" | was the tx mined at a height/time before the deadline? | log `getBlockCount()` before/after (measured: deadline 686, mined at 638) |
| "a timelock is enforced" | is it parked in `getrawnonfinalmempool` and unseen by `getrawtransaction`? | poll both pools across `mine(n)` |
| "funds are stranded" | are the sats still on that UTXO, confirmed, unspendable? | `getrawtransaction … true` for confirmations, `gettxout` for the value |
| "state is wrong but accepted" | what does the *chain's* script say? | `readOnChainState`, never `contract.state` |

---

## 4. Attack catalogue (state of play)

Legend: ✔ covered offline, ⚑ confirmed on the node, ✖ not touched.

1. **Witness shape** — arity, junk above/below, empty pushes, non-minimal
   numbers, out-of-range/negative selectors. ✔ / ✖⚑ — *nothing from the escrow
   and multisig shape tests has been put on a node yet, and
   `acceptnonstdtxn=0` is exactly the setting that could invalidate the
   "junk accepted" and "non-minimal selector" results. Do that first.*
2. **Signature semantics** — wrong party, wrong order, method-crossing,
   cross-UTXO replay, duplicate threshold keys, sighash downgrade. ✔ / ⚑ for the
   freeze case only. ✖ **ECDSA malleability (third-party tx malleation, high-S,
   DER encoding variants), NULLDUMMY specifics, sighash downgrade on a live
   node** (needs a custom signer, §2).
3. **Numeric domain** — negatives, ≥ 2^31 / ≥ 2^63, bps > 10 000, witness
   division by zero, `mulDiv`/`percentOf` overflow vs the SDK's 8-byte state
   guard. ✔ / ⚑ (before the fix, a post-2038 deadline was rejected by the node;
   it is now read unsigned and parked as merely non-final —
   `onchain/locktime.onchain.test.ts` C). ✖ whether the *script's*
   int64 arithmetic wraps where BigInt would not — i.e. force a `mulDiv` whose
   off-chain answer differs from the on-chain one and see which one the chain
   accepts.
4. **Time and finality** — ✔⚑ height domain end to end on a node (held until the
   deadline; mined after; final-sequence bypass now a consensus reject). Remaining:
   CSV/relative locktime (`sequence` bits 31/22, `OP_CHECKSEQUENCEVERIFY`), a
   timestamp gate actually *satisfied* on a node (needs the 12-block clock trip
   described in §1.2), RBF-ish sequence games beyond the finality guard, and
   whether the SDK should re-issue a parked spend automatically.
5. **Value binding** — ✔ offline: D25 refuses the drain on the auction and the
   TicTacToe board. ✖ on-chain: the floor is enforced by `MockProvider` before
   broadcast, so a node-level demonstration needs the raw
   `createRawFundedWallet`/`sendRaw` path to get the bad transaction actually
   broadcast, and then both outputs read back.
6. **State serialization** — ✔⚑ the 129–255 byte freeze, now fixed: the node
   accepts the 200-byte post *and* the spend after it. ✖ OP_PUSHDATA2 lengths
   ≥ 32768 (unreachable under the 520-byte stack-element cap — confirm that on a
   node rather than assuming it), state fields that make the script cross
   10 000 bytes, and the interaction of a variable-length field with
   `addOutput`/data-output ordering.
7. **Dispatch and branch coverage** — ✔ partially. ✖ assertion-dropped-on-a-branch
   under constant folding (fold-ON vs fold-OFF on the *same* attack witness),
   peephole rewrites in asymmetric branches, private-helper inlining where the
   helper asserts.
8. **Deployment-time footguns** — ✔ duplicate multisig keys. ✖ script size / stack
   element limits for the post-quantum examples (788 KB scripts: do they even
   relay under `acceptnonstdtxn=0`?), `constructorSlots` splicing a value into the
   wrong byte offset, a readonly property baked as `OP_0`.
9. **Cross-tier** (out of scope for a TS-only round, but note anything you find):
   the conformance suite guarantees cross-compiler byte equality, *not* that the
   bytes are right — every bug found this round was agreed by all seven tiers.

---

## 5. Reading results honestly

- A `Spend` accept is **not** "the network accepts it". Node first.
- An RPC error naming `mandatory-script-verify-flag-failed` is consensus.
  Anything else (`min-fee-not-met`, `nonstandard`, `txn-mempool-conflict`,
  `missing-inputs`) is policy or plumbing — report it as such and separately.
- "Never mined" and "rejected" are different findings with different fixes. The
  non-final-pool result (§1.2) is the model: enforced as designed, useless in
  practice, fix belongs in the SDK's rebroadcast loop.
- Check that your guard can fail. Last round the compiler's own recommended
  `extractSequence(p) < 0xffffffffn` guard accepted all four sequence values
  tried — because 0xffffffff is read as −1 — so the guard could never reject
  anything. If your control passes for every input, you have not tested it.
- Fix the harness before believing a surprise. Both "weird" failures last round
  (`OP_XOR requires the top two stack items…`, `public key is in an unknown
  format`) were harness mistakes, not compiler bugs.

---

## 6. Documentation requirements

Two files, both in `security-lab/`, both updated in the same sitting as the test.

**`README.md`** — the index. For every test file: one line saying what it attacks
and what verdict it produced. Keep the "Run" section truthful. Keep the attack
catalogue with ✔/⚑/✖ marks current — the gaps are the next round's assignment,
so a stale catalogue costs a whole round.

**`FINDINGS.md`** — one section per finding, fixed template:

```
## F-n <one-line claim, with the number that matters>
Severity + one sentence on why it matters to someone holding money.
Mechanism: the codegen path, with file:line, and what it does wrong.
Evidence: the actual test output, in a fenced block, verbatim. Quote the
          engine/node error string exactly, and name the test file.
Exposure: which shipped examples carry it, and who can trigger it
          (anonymous caller? counterparty? deployer?).
On-chain: the node verdict, with the reject code / height / txid, or the
          explicit line "not yet verified on-chain".
Fix: the smallest change, plus the fixture that would have caught it.
Status: offline-confirmed | on-chain-confirmed | needs-review
```

Also keep the **confirmed-good table** (the attacks that were correctly rejected).
Those are regression candidates for the real test suites, and they are what tells
the next round the harness is discriminating.

When a finding is upgraded from offline to on-chain, change **Status** and paste
the node output under **On-chain** — do not overwrite the offline evidence; the
pair is more useful than either alone.

---

## 7. Suggested starting point for the next round

D25 and D26 have landed since the last round and closed the two codegen bugs at
the top of this list, along with the acute form of the value-binding hole. Current
standing (`FINDINGS.md` ⇒ "What changed when this was re-run against main"):

| | status |
| --- | --- |
| F-1 signed uint32 preimage fields | **fixed** (D26) — guarded offline and on-chain |
| F-2 129–255 byte state freeze | **fixed** — guarded offline and on-chain |
| F-3 pot drain via caller-picked continuation amount | **mostly fixed** (D25) — guarded on the auction and TicTacToe |
| F-4 sighash mode not pinned on stateless contracts | **open** — all six hashTypes still accepted |

Suggested order for the next round, highest value first:

1. **F-4, the open one.** Pin the sighash mode for stateless `checkSig` /
   `checkMultiSig`: assert the last byte of each signature against the declared
   (or default `ALL|FORKID`) mode. Write the failing test first —
   `multisig.attacks.test.ts` A6 and `escrow.attacks.test.ts` S2 already
   demonstrate the hole and currently assert that it exists; they should flip to
   asserting that `NONE|FORKID` and the `ANYONECANPAY` variants are refused while
   `ALL|FORKID` still works, plus a negative control proving a valid `ALL|FORKID`
   signature is still accepted.
2. **F-3's residual forms.** D25 billed the shrink; it does not bill an
   *orthogonal* change — `deposit(1_000_000)` on `FunctionPatterns` still records
   a balance the UTXO does not hold (`pot.attacks.test.ts` W1). Build the
   multi-input / multi-continuation cases D25 papers over, and the stateless
   contracts that have no continuation to bind to at all.
3. **Signature malleability / low-S** (catalogue 2, still ✖). Whether a
   third-party-mutated witness still satisfies a Rúnar contract, and whether any
   contract hashes a signature it later compares.
4. **Relative locktime / sequence semantics** (catalogue 4, still ✖). D26 made
   `extractSequence` mandatory and unsigned; what does a contract do with
   `0xfffffffe` vs a real CSV relative distance, and does anything read sequence
   for anything but the finality guard?
5. **Constant folding on branch arms** (catalogue 7). Fold-ON vs fold-OFF hex,
   which the conformance runner already has machinery for
   (`RUNAR_DISABLE_CONSTANT_FOLDING=0`), aimed at this suite's contracts rather
   than the fixtures.
6. **State size ceiling** (catalogue 6). OP_PUSHDATA2 lengths, and what a real
   `MessageBoard` or `StateMachine` does near the 10 000-byte consensus script
   limit.

Housekeeping the suite owes itself:

* `sweep.test.ts` reports `money-in-state-no-amount-check` against ~20 shipped
  examples; with D25 in place, re-classify which of those are actually exposed
  now, and split `oracle-silent` from `oracle-incomplete` (a machine-checkable
  criterion for "this contract's invariant is verifiable" is worth more than
  another finding).
* `examples/*/` non-TypeScript tiers: D25/D26 live in the TypeScript reference
  compiler's passes. Confirm the Go/Rust/Python/Zig/Ruby/Java frontends emit the
  same unsigned reads and the same two D26 diagnostics — a tier that skipped D26
  compiles contracts this suite would reject, which is exactly the kind of
  divergence the conformance suite is meant to catch and currently does not
  (`conformance/` has no locktime-domain fixture).
