# Rúnar security lab — findings

Everything below was produced by executing the **real compiled Bitcoin Script**
through `@bsv/sdk`'s production `Spend` interpreter (real secp256k1, real
BIP-143 sighash, real consensus opcode errors). Nothing here relies on the ANF
interpreter's mocked crypto. Reproduce with:

```bash
npx vitest run security-lab            # offline suite (Spend-based)
cd integration && ./regtest.sh start && cd ../security-lab && npx vitest run   # on-chain suite
```

Each finding names the test that demonstrates it. **On-chain** means the verdict
came from a running Bitcoin SV regtest node (`bitcoinsv/bitcoin-sv`, RPC :18332),
not from the in-process interpreter.

| # | finding | severity | offline | on-chain | status on current main |
| --- | --- | --- | --- | --- | --- |
| F-1 | `extractLocktime`/`extractSequence` sign-extend an unsigned uint32 | high | ✔ | ✔ both directions | **fixed** (D26), guarded here |
| F-2 | `OP_PUSHDATA1` length decoded signed → 129–255 byte state freezes the UTXO | high | ✔ | ✔ mined, then stranded | **fixed**, guarded on-chain here |
| F-3 | state "amounts" are not tied to the satoshis in the UTXO | high | ✔ | ✔ (continuation floor) | **mostly fixed** (D25), gaps listed |
| F-4 | `checkSig`/`checkMultiSig` do not pin the sighash type | high | ✔ | pending | **open** — all six hashTypes still accepted |
| F-5 | smaller findings + confirmed-good properties | medium/low | ✔ | partly | mixed, see the section |

## What changed when this was re-run against main

The findings were produced on an earlier snapshot. Re-run against `main`
(`dbcc426`), three of the four highs are fixed and this suite has been recut into
regression guards for the fixes; F-4 is unchanged. The evidence below is kept as
written, because it explains what each fix had to cover.

| | enforcement now in the compiler | guard in this suite |
| --- | --- | --- |
| F-1 | `extractLocktime` / `extractSequence` pad with `OP_0 OP_CAT` before `OP_BIN2NUM`, and D26 refuses to compile a locktime gate that does not pin its domain or assert `extractSequence !== 0xffffffffn` | `locktime.attacks.test.ts` (matrix over 2^31−1 / 2^31 / 2.5e9, both domains), `auction.attacks.test.ts` A4, `onchain/locktime.onchain.test.ts` |
| F-2 | every variable-length prefix is read unsigned (`05-stack-lower.ts:1152`: "Every length is UNSIGNED — `emitPushDataDecode` reads it back that way") | `freeze.boundary.test.ts`, `freeze.attack.test.ts`, `onchain/freeze.onchain.test.ts` |
| F-3 | D25 binds each state continuation to the input being spent; `MockProvider` and the node also refuse a continuation that pays out less than the input | `auction.attacks.test.ts` A1–A3, `pot.attacks.test.ts` T1, `freeze.attack.test.ts` |
| F-4 | nothing | `multisig.attacks.test.ts` A6 asserts the hole is still open |

Two things D26 requires that a pre-D26 contract did not, both discovered by
trying to compile the old test contracts against main:

```text
method 'withdraw' compares extractLocktime against a lower bound without pinning
the locktime domain: … assert(extractLocktime(preimage) < 500000000n) for a
block-height gate, or assert(extractLocktime(preimage) >= 500000000n) for a
timestamp gate

method 'withdraw' reads extractLocktime but does not assert extractSequence is
not 0xffffffff; a locktime gate is not consensus-enforceable without it
```

That is the right pair of requirements — and the second one is now visible on a
node rather than in a comment: a withdrawal that ignores it and leaves every
input final is rejected by the node with
`mandatory-script-verify-flag-failed (Script failed an OP_VERIFY operation)`
instead of being mined early for a free fee (`onchain/locktime.onchain.test.ts` B).


---

## F-1 `extractLocktime` / `extractSequence` sign-extend an unsigned uint32 — funds locked forever

**Severity: high (loss of liveness on a contract that looks correct); medium
(theft in the inverted direction).**

nLockTime and nSequence are **unsigned** uint32 on the wire. The compiler reads
4 bytes and hands them to `OP_BIN2NUM`, which is a **signed** sign-magnitude
decode:

| nLockTime          | consensus value | value the script compares |
| ------------------ | --------------- | ------------------------- |
| `0x00000000`–`0x7FFFFFFF` | 0 … 2147483647 | same (correct) |
| `0x80000000`–`0xFFFFFFFF` | 2147483648 … 4294967295 | **−2147483648 … −1** |

Codegen: `packages/runar-compiler/src/passes/05-stack-lower.ts:3936`
(`extractLocktime`) — `… 4 OP_SPLIT OP_DROP OP_BIN2NUM`, no high-byte padding.
Same shape for `extractSequence`.

### Evidence A — unsatisfiable timelock (`security-lab/locktime.attacks.test.ts`, B1)

```
class Vault … assert(extractLocktime(this.txPreimage) >= this.deadline);
deadline = 2_500_000_000  (a Unix deadline in 2049)

  lockTime=         0 (epoch)                             -> reject
  lockTime=2499999999 (one second early)                  -> reject
  lockTime=2500000000 (EXACTLY the deadline, honest spend)-> reject
  lockTime=2500000001 (one second late)                   -> reject
  lockTime=4294967295 (uint32 max)                        -> reject
B1 accepted 0/8 nLockTime values — the honest spend at the deadline itself FAILS
```

No nLockTime whatsoever satisfies `>= 2.5e9`, because the largest value the
script can read is 2147483647. **A vault with a post-2038 timestamp deadline
accepts deposits and can never spend them.** `compile()` succeeds with no
diagnostic, the deploy succeeds, the first `withdraw()` fails forever. Same
result for `within(extractLocktime(p), 2.5e9, 2.6e9)` — every value rejected.

### Evidence B — the compiler's own locktime-finality guard is vacuous (B3)

`02-validate.ts:1037+` (#131) warns when a method reads `extractLocktime`
without asserting `extractSequence(preimage) < 0xffffffff`, and accepts exactly
that spelling as the fix. Measured on a contract that contains the guard:

```
  seq=0xffffffff (FINAL — consensus ignores nLockTime entirely) -> ACCEPT
  seq=0xfffffffe (non-final, locktime enforced)                 -> ACCEPT
  seq=0x80000001 (relative-locktime flag set)                   -> ACCEPT
  seq=0x00000000 (sequence 0)                                   -> ACCEPT
```

0xffffffff reads as −1, and −1 < 4294967295 is always true, so the guard can
**never** reject — including the one case it exists to catch. The recommended
remediation for #131 does not close the hole it describes.

### Evidence C — inverted deadline on a shipped example (`security-lab/auction.attacks.test.ts`, A4)

`Auction.bid` asserts `extractLocktime(preimage) < deadline(500000)`:

```
A4 nLockTime=0:         ACCEPT (tx.lockTime=0, seq=ffffffff)
A4 nLockTime=499999:    ACCEPT
A4 nLockTime=500000:    reject
A4 nLockTime=4294967295: ACCEPT      <-- reads as −2147483647
```

Combined with the missing sequence guard, the auction deadline is decorative:
an honest-looking transaction with `nLockTime = 0` (or `0xFFFFFFFF`) and all
sequences final keeps out-bidding **forever**, years past the advertised close.
`examples/ts/intent-current-block-height` is flagged the same way by
`security-lab/sweep.test.ts`.

### On-chain confirmation (`security-lab/onchain/locktime.onchain.test.ts`)

Run against a live regtest node, with `autoMine` off so height moves only on
explicit `mine()` calls:

```
deadline height 686, mined at height 638 (<= deadline: true), confirmations 1
right after broadcast      (height 640): non-final-pool=true  relaying-pool=false  confirmations=not visible to getrawtransaction
after 3 blocks             (height 643): non-final-pool=true  relaying-pool=false  confirmations=not visible to getrawtransaction
after mining past deadline (height 701): non-final-pool=true  relaying-pool=false  confirmations=not visible to getrawtransaction
verdict: nLockTime was enforced (never mined before the deadline); broadcast at height 640,
  now at height 701 which is past deadline 699, yet the tx is STILL in the non-final pool,
  unmined — the pool is not a scheduler, so the broadcaster must re-send after finality

withdraw with nLockTime=2500000000: rejected — 16: mandatory-script-verify-flag-failed (Script failed an OP_VERIFY operation)
withdraw with nLockTime=2500000010: rejected — 16: mandatory-script-verify-flag-failed (Script failed an OP_VERIFY operation)
withdraw with nLockTime=4294967295: rejected — 16: mandatory-script-verify-flag-failed (Script failed an OP_VERIFY operation)
```


Three separate confirmations:

1. **The bypass is real.** A withdrawal with `nLockTime = 686` and final
   sequences was accepted and **mined at height 638** — 48 blocks before its own
   deadline. Nothing at the consensus layer noticed.
2. **The guard would work if the compiler emitted it.** With `sequence =
   0xfffffffe` the identical transaction was not mined: it went to the *non-final*
   mempool. The missing sequence guard is the whole difference, so a codegen fix
   has an observable effect.
3. **The post-2038 lock-up is consensus-level, not a harness artifact.** Every
   withdrawal was rejected by the node with a *mandatory* script-verify failure —
   including the honest case where the client set `nLockTime` to its own target.
   The funds are unspendable by anyone, forever, and because the failure is a
   rejected transaction rather than a wrong output it survives unit tests that
   only ask "did the assertion pass".

**Operational sub-finding (new).** The node does **not** mine a parked non-final
transaction once it becomes final: two blocks past the deadline the transaction
was still sitting in `getrawnonfinalmempool`, still invisible to
`getrawtransaction`, and the chain had moved on. A client that broadcasts one timelock-gated spend and then
waits for confirmation waits forever — the SDK must re-broadcast after finality.
Worth documenting regardless of how the codegen guard lands.

### Fix

Pad unsigned 4-byte preimage fields with a 0x00 high byte before decoding:
`… 4 OP_SPLIT OP_DROP OP_0 OP_CAT OP_BIN2NUM`. Add a compile-time diagnostic
when a `bigint` constant compared against `extractLocktime` / `extractSequence`
exceeds 2^31−1. Add a conformance fixture whose deadline is a post-2038
timestamp (the current fixtures all use small block heights, which is why this
has stayed invisible).

**Landed as D26**, including both parts: the extraction pads with
`<0x00> OP_CAT` before `OP_BIN2NUM`, and the two compile-time diagnostics quoted
above mean a contract cannot even be built with an ambiguous or unenforceable
gate. `locktime.attacks.test.ts` now passes at every value across the 2^31
boundary in both domains, and `onchain/locktime.onchain.test.ts` shows a height
gate actually holding a transaction out of blocks until its deadline.

---

## F-2 `OP_PUSHDATA1` length byte is decoded signed → 129–255 byte state fields freeze the UTXO

**Severity: high (drive-by freeze, funds stranded).**

`emitPushDataDecode()` (`packages/runar-compiler/src/passes/05-stack-lower.ts:929`,
PUSHDATA1 branch at `:1006`–`:1019`) walks a variable-length state field:

```
… OP_1 OP_SPLIT OP_SWAP OP_BIN2NUM OP_SPLIT
                        ^^^^^^^^^^ 1-byte length, signed
```

For a field of 129…255 bytes the stored prefix is `4c 81`…`4c ff`; `OP_BIN2NUM`
turns `0x81` into −127, and the following `OP_SPLIT` aborts the script with
`OP_SPLIT requires the first stack item to be a non-negative number`.

The **write** side (`emitPushDataEncode`, `:839`) is correct and unsigned, so the
value is stored fine — it is the *next* spend that dies.

### Evidence (`security-lab/freeze.boundary.test.ts`)

```
  len=127 | store=ok | next spend from it=ok               | prefix: 4c7fabab
  len=128 | store=ok | next spend from it=ok               | prefix: 4c80abab
  len=129 | store=ok | next spend from it=FROZEN           | prefix: 4c81abab
  len=200 | store=ok | next spend from it=FROZEN           | prefix: 4cc8abab
  len=255 | store=ok | next spend from it=FROZEN           | prefix: 4cffabab
  len=256 | store=ok | next spend from it=ok (PUSHDATA2)   | prefix: 4d0001abab
```

The whole grid `security-lab/varlen.boundary.test.ts` shows the same: any state
holding a 129–255 byte ByteString fails on **every** transition, including a
write of the identical length and a method that only touches a `bigint` field.

### Drive-by on a shipped example (`security-lab/freeze.attack.test.ts`)

`examples/ts/message-board/MessageBoard.runar.ts` — `post()` is documented
"Anyone can call this method — no signature required":

```
attacker post landed; the next honest post aborted:
  Script evaluation error: OP_SPLIT requires the first stack item to be a non-negative number
```

One anonymous 200-byte post and the board stops accepting posts. The owner can
still `burn()` (that branch never parses the field, so it survives), so the
coins are recoverable **if** the contract happens to ship an escape hatch that
reads nothing. `security-lab/varlen-exposure.test.ts` lists the other examples
with unauthenticated writers into a mutable byte field:

```
message-board/MessageBoard        post(newMessage: ByteString)          UNAUTHORISED
terminal-varlen-read/…            post(newMessage: ByteString)          UNAUTHORISED
branched-readonly-len/…           spend(scratch: ByteString)            UNAUTHORISED
state-covenant/StateCovenant      advanceState(newStateRoot: ByteString, …)  UNAUTHORISED
```

Note the neighbouring property of this bug: nothing in the compiler, the SDK, or
the docs states a maximum length for a `ByteString` state field, so a developer
has no reason to suspect 200 bytes is a cliff.

Related: verification below the cliff is still sound — tampering the
continuation output at 4/75/127/128 bytes is rejected
(`security-lab/freeze.tamper.test.ts`), so this is a freeze, not a bypass.

### On-chain confirmation (`security-lab/onchain/freeze.onchain.test.ts`)

Deployed `MessageBoard` to a live regtest node and spent it through
`sendrawtransaction` + `mine`, not just through `Spend`:

```
post 200 bytes: accepted, txid 1938ecfe1644… (differs per run)   confirmations=1 value=546 scriptBytes=111
  on-chain message length: 200   (new messageStateHash …)
post again, same contract: REJECTED by the node —
  Error: RPC sendrawtransaction failed (592):
  RPC sendrawtransaction: 16: mandatory-script-verify-flag-failed (Invalid OP_SPLIT range)
frozen UTXO confirmations: 1      (still confirmed, still ours, permanently unspendable)
control post 127 bytes: mined, and the follow-up post mined too (2 confirmations)
```

What the node adds over the offline result: the first spend is not merely
*accepted by an interpreter*, it is **mined and confirmed**, so the victim's
contract really is in the chain holding the poisoned state; and the rejection is
`mandatory-script-verify-flag-failed`, i.e. consensus-level, so **no miner and no
policy change can recover the funds.** The offline "this is a freeze, not a
bypass" conclusion is confirmed end to end.

### Fix

Same padding trick in the PUSHDATA1 branch (`OP_0 OP_CAT` before `OP_BIN2NUM`),
or read the length as `OP_1 OP_SPLIT OP_SWAP OP_BIN2NUM` with an explicit
`OP_7f OP_MIN`-style mask. Whatever the fix, `security-lab/onchain/freeze.onchain.test.ts` should keep passing unchanged — its second assertion (that the 200-byte
message can be posted *again*) is the one that fails today and is the regression
guard. Add a fixture that round-trips a 128/129/255/256-byte
state field through two spends on the real engine, and surface a length limit in
`serializeState` if the team would rather cap the field than fix the codegen.

**Landed.** The prefixes are read unsigned, and the assertion that used to fail —
post 200 bytes, then post again — now passes both offline and on the node:
the 200-byte post is mined and the follow-up spend of that same UTXO is accepted
and mined with the new 8-byte message readable back out of the output. The test
in `onchain/freeze.onchain.test.ts` was rewritten from "expect the freeze" to
"expect no freeze", which is the version that will catch a regression.

---

## F-3 Nothing ties "the amount in state" to "the satoshis in the UTXO" — callers can drain pots

**Severity: high on the examples as written (theft); the mechanism is by design.**

Every state-mutating public method gets `_changePKH`, `_changeAmount`,
`_newAmount` injected (`04-anf-lower.ts:216-224`). The covenant binds those
numbers to the transaction's outputs, but nothing binds them to

* the value of the input being spent, or
* the `bigint` fields the contract keeps as "money".

The caller — who is by definition whoever is spending, not necessarily the
funds' owner — picks them.

### Evidence: TicTacToe prize pool drained on an ordinary move (`security-lab/pot.attacks.test.ts`, T1)

```
T1 pot after join (tx1 output0):        100000
T1 covenant verdict on the draining move: true
T1 outputs of the draining tx:          [ 546, 596549 ]
T1 state still says status=1 turn=2, betAmount unchanged
T1 satoshis left in the game: 546 of 100000
```

A player plays one legal move, leaves dust in the game, and pockets the other
99 454 sats. The game continues, and the winner then has to fund the
`2 * betAmount` payout out of their own pocket (T2/T3: `moveAndWin` with
`changeAmount = 0` cannot even be built by the SDK when the pot exactly equals
the payout, because the fee forces a second input and therefore a change output
the contract was told is zero).

### Evidence: the auction pot (`security-lab/auction.attacks.test.ts`, A1/A2/A3)

```
A1 covenant verdict: true
A1 outputs: [ 546, 298841 ]        (contract output 546, everything else to caller)
A2 state.highestBid: 95000 while the contract UTXO holds 546 satoshis
A3 leaving 1 000 of a 100 000 pot: ACCEPT
```

A bidder can out-bid with a number, leave dust, and take the previous bidders'
deposits as change. The recorded winning bid and the money backing it are
completely independent.

### Evidence: ledger diverges with negative and oversized arguments (`security-lab/pot.attacks.test.ts`, W3/W4/W5/W6)

```
W3 withdraw(10 000, feeBps = -250):  ACCEPT  balance 100 000 -> 90 250 (paid 10 000, debited 9 750)
W4 withdraw(10 000, feeBps = 25 000):ACCEPT  balance -> 65 000 (no cap on basis points)
W5 deposit(1 000 000) with no extra funding: ACCEPT  balance -> 1 100 000, contract holds 100 000
W6 scale(-1, 1):                     ACCEPT  balance -> -100 000
```

W5 is the dangerous one for a custodial pattern: the ledger can be inflated by
any amount the caller *declares*, so a wallet contract believes it holds 11× what
it holds. (Positive control: `withdraw(-10 000)` is rejected — the example's own
`assert(amount > 0n)` catches it. Nothing catches the fee or the deposit.)

### Fix

Not a codegen bug, but the framework should make the safe pattern the default:

* emit a warning when a method writes a `bigint` state field whose name is in a
  money-ish set (`amount`, `balance`, `bid`, `price`, `sat*`) and the method
  never calls `extractAmount` / `requireOutputP2PKH` — the same advisory style
  as the #131 locktime warning;
* or expose a first-class `this.utxoValue` invariant the compiler wires to
  `extractAmount(preimage)`, and document `_newAmount <= extractAmount(p)` as the
  canonical "no drift" assertion;
* and consider bounding `percentOf`/`mulDiv` basis points (W4) and rejecting
  negative arguments to parameters used in money positions.

`security-lab/sweep.test.ts` flags 20+ shipped examples as
`money-in-state-no-amount-check`, i.e. every one of them carries this exposure
today.

**Landed as D25**, and stronger than the first proposal above: each state
continuation is bound to the input it came from, so the caller can no longer pick
the continuation amount out of thin air. On the auction the emitted check is

```
require(extractOutputScriptHash(p, 0) == contractHash
        && continuationAmount() >= extractAmount(p) + newAmount)
```

which is the inverse of the old leak — the continuation must carry *at least* the
input, where before the same `bid()` accepted a continuation paying 546 sats while
recording a 95 000-sat bid. `MockProvider` enforces the same floor before
broadcast, so the shape fails fast with
`OP_VERIFY requires the top stack value to be truthy` rather than drifting
quietly. Still open, and worth keeping in view:

* an orthogonal change is still unbilled (the `amount` ledger field in
  `pot.attacks.test.ts` W1/W2 diverging from the UTXO's satoshis);
* multi-input / multi-continuation contracts, and the case where a caller spends
  the contract UTXO to a *different* outpoint and rebuilds state;
* stateless contracts have no continuation at all, so nothing at all ties their
  notion of "balance" to anything (F-4's territory).

---

## F-4 `checkSig` / `checkMultiSig` do not pin the sighash type on stateless contracts

**Severity: medium (signature reuse across transactions; can be turned into theft
by a counterparty who assembles the tx). STILL OPEN on `dbcc426`.**

Re-run against main, unchanged:

```
A6 ALL|FORKID: accepted=true             A6 ALL|ANYONECANPAY|FORKID: accepted=true
A6 NONE|FORKID: accepted=true            A6 NONE|ANYONECANPAY|FORKID: accepted=true
A6 SINGLE|FORKID: accepted=true          A6 SINGLE|ANYONECANPAY|FORKID: accepted=true
```

`multisig.attacks.test.ts` M6 shows the same on the shipped `MultiSig2of3`
example, with one addition: under the `ANYONECANPAY` modes the other signers'
inputs leave the digest, so a single keyholder can carry a witness meant for a
cooperative spend into a transaction where they are the only contributor. Both
tests assert the hole rather than only printing it, so pinning the mode will turn
them red and force an intentional update.

There is still no `extractTime` or `extractBlockNumber` builtin either (neither
name exists in the compiler), so a contract that wants a timestamp gate has to
write `extractLocktime(p) >= 500000000n` and mean it — which D26 now makes it say
explicitly, but the mode itself is still not pinned for stateless methods.

Stateful methods already pin it — the ANF injects
`assert(extractSigHashType(txPreimage) === declaredMode)`
(`04-anf-lower.ts:242-252`; visible in the emitted script as
`… OP_BIN2NUM 41 OP_NUMEQUALVERIFY`). Stateless `SmartContract` methods do not:

```
ESCROW  (security-lab/escrow.attacks.test.ts, A6)
A6 ALL|FORKID:               accepted=true
A6 NONE|FORKID:              accepted=true
A6 SINGLE|FORKID:            accepted=true
A6 ALL|ANYONECANPAY|FORKID:  accepted=true
A6 NONE|ANYONECANPAY|FORKID: accepted=true
A6 SINGLE|ANYONECANPAY|FORKID: accepted=true

MULTISIG (security-lab/multisig.attacks.test.ts, M6) — same.
```

Consequence for the shipped Escrow: the arbiter is the party who must co-sign
both paths. If the arbiter signs with `SIGHASH_NONE`, the outputs are not
committed, so the seller can take that same arbiter signature and put it on a
transaction that pays 100 % to the seller. The arbiter approved a 50/50 release
and consents to a 100/0 one. `@sighash` declares a mode for the SDK's preimage
builder and for the field-usage validator; it is not enforced on-chain for
stateless contracts.

### Fix

For stateless methods carrying a `@sighash` directive (or unconditionally, with
`ALL|FORKID` as the default), emit
`<sig> <pk> OP_CHECKSIG` … plus a check on the signature's hashType byte, or
`OP_CAT`-style assert that the last byte of each `Sig` equals the declared mode.

---

## F-5 Smaller findings and confirmed-good properties

Degenerate multisig (informational, `security-lab/multisig.attacks.test.ts`):

```
M2 charlie alone on a pk1==pk3 vault: ACCEPT
M3 charlie-only 2-of-3:               ACCEPT  (script size 116)
```

`checkMultiSig([sig1,sig2],[this.pk1,this.pk2,this.pk3])` with duplicated keys
degrades to 1-of-N and nothing warns at compile, deploy, or SDK level. One
mis-wired deployment argument and a "2-of-3 vault" is a single-key wallet.

Witness shape is not constrained (informational): extra junk below the witness is
accepted (`escrow.attacks.test.ts` A3), and 2-of-3 accepts a third signature
(`multisig.attacks.test.ts` M4 — the extra item shifts which *pair* is checked,
not the strictness). Selector equality is numeric, so an empty push and a 4-byte
zero both select method 0 (`escrow.attacks.test.ts` A5). All benign, but worth
documenting because tooling that assumes "exactly N pushes" is wrong.

Tooling bug surfaced by typechecking the lab (`integration/ts/helpers/compile.ts`):

`compileContract` / `compileSource` reported failures as
`${JSON.stringify(result.errors)}`, but `CompileResult` has no `errors` field —
it is `diagnostics`. Every compile-failure message this helper produced printed
`... : undefined`, which is a small thing until it is the only output standing
between you and a fixture that stopped compiling. Fixed to `result.diagnostics`
(2 lines). Worth recording here because it is the same failure mode as the
contract-level findings: a field name that never existed, read through a type
nobody checked. `integration/ts` has no typecheck step (its `tsconfig.json` is
`moduleResolution: bundler` and CI only runs `npx vitest run` there, which
transpiles without checking), so this survived for a long time.

Also in that helper: `createFundedWallet(provider, …)` never used `provider` —
funding goes straight to the node over RPC. Renamed to `_provider` with a comment
rather than dropped, since every caller passes it positionally.

Confirmed good — these attacks were **rejected**, so they are regression-worthy:

| Attack | Result |
| --- | --- |
| wrong party's signature on escrow release / refund | rejected |
| buyer's sig in the seller's slot, and vice versa | rejected |
| release signatures replayed under the refund selector | rejected |
| out-of-range / negative method selector | rejected |
| arbiter's sig taken over a different output set (`ALL`) | rejected |
| caller-supplied `newState` that differs from the method's computed state | rejected (auction P1) |
| signature from the wrong bidder on `Auction.bid` | rejected (P2) |
| multisig witness replayed onto another UTXO (different input amount) | rejected (M7) |
| missing signature in a 2-of-3 | rejected |
| empty / malformed signature | rejected |
| negative `withdraw` amount where the contract asserts `> 0` | rejected |
| division by zero via a witness denominator (`scale(x, 1, 0)`) | rejected |
| state bigint outside the 8-byte word | SDK refuses to serialize (fails closed) |
| tampered continuation output amount | rejected |
| non-final sequence really gates `nLockTime` | **on the node**: `sequence=0xfffffffe` + `nLockTime=318` left unmined across 3 blocks (F-1 evidence) |
| standardness of the generated witness | the mined and stranded freeze UTXO passed `acceptnonstdtxn=0` CLEANSTACK/minimal-push checks, so the generated unlocking scripts are standard as the SDK builds them |

---

## Suggested priority, as of this re-run

Fixed and now guarded by this suite, so the list has moved on:

* ~~F-2 (129–255 byte freeze)~~ — fixed; guarded offline and on-chain.
* ~~F-1 (signed uint32 preimage fields)~~ — fixed as D26, including the two
  compile-time diagnostics; guarded across the 2^31 boundary in both domains.
* ~~F-3 in its acute form~~ — fixed as D25; guarded on the auction and the
  TicTacToe pot.

What is left:

1. **F-4, sighash mode not pinned for stateless contracts.** The only high-severity
   item still open, and the fix is small: assert the last byte of each signature
   against the declared (or default `ALL|FORKID`) mode.
2. **F-3's residual forms** — orthogonal state changes that are not billed, and
   multi-input contracts, where "the amount in state" and "the satoshis in the
   UTXO" can still disagree.
3. **The non-final pool is not a scheduler.** A time-locked spend broadcast before
   its deadline is parked, is *not* mined automatically once the chain passes the
   deadline, and cannot be re-sent — `sendrawtransaction` answers
   `Transaction already in the mempool` (both verified again on main in
   `onchain/locktime.onchain.test.ts` A). So an app either broadcasts a locked
   spend only once the deadline has passed, or must re-issue it as a *new*
   transaction. A re-broadcast loop over the same bytes will not work, which is
   worth correcting wherever the earlier recommendation of "the SDK needs a
   re-broadcast loop" has been written down.
4. **`regtest` and timestamp gates do not mix well in CI.** Making a timestamp
   nLockTime final means 11+ blocks at a mocked clock (finality is judged against
   the median time past), and unwinding those blocks with `invalidateblock` left
   this node in safe mode — `Safe mode: We do not appear to fully agree with our
   peers!` — which then broke every other job sharing it. The on-chain suite
   therefore proves the timestamp domain offline and keeps the node in the
   height domain.
5. F-5 — duplicate-key warning in `checkMultiSig`, and a documented ceiling on
   variable-length state fields.
