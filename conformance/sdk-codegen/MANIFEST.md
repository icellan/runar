# Cross-SDK codegen conformance manifest

This file is the contract every SDK's typed-wrapper codegen must satisfy.
It exists because the bug fixed in commit `c00cfe7` (Rust codegen emitted
`vec![SdkValue::BigInt(count)]` instead of `vec![SdkValue::BigInt(args.count)]`)
slipped through every SDK's per-language string-pattern tests — *none* of
them tried to compile the generated wrapper. The shared fixtures here, plus
each SDK's per-language conformance runner under `runners/`, prevent that
class of drift from recurring.

## Fixtures

Five artifact JSONs cover the surface every typed wrapper has to lower:

| Fixture | Statefulness | Sig param | Terminal? | Why it exists |
| --- | --- | --- | --- | --- |
| `fixtures/p2pkh.json` | stateless | yes (`unlock(sig, pubKey)`) | yes | exercises the `prepare<Method>` / `finalize<Method>` companions and the constructor-args record |
| `fixtures/counter.json` | stateful | no (auto-injected `SigHashPreimage` only) | mixed (`increment` non-terminal, `reset` terminal) | exercises the `<Name>StatefulCallOptions` record, terminal-output handling, and state accessors |
| `fixtures/simple.json` | stateless | no | yes | exercises the no-constructor-args path (no `*ConstructorArgs` record) |
| `fixtures/stateful-escrow.json` | stateful | yes (single Sig on non-terminal `claim`, multi-Sig on terminal `release`) | mixed | exercises `prepare<Method>` / `finalize<Method>` on **stateful** methods (the dimension `counter.json` does not cover) and multi-`Sig` finalization (`finalizeRelease(prepared, buyerSig, sellerSig)`) |
| `fixtures/inscribed.json` | stateless | yes (`transfer(sig, pubKey, newOwner)`) | yes | exercises the inscription-attach path: every wrapper must expose `attachInscription(insc)` so a 1sat ordinals envelope can be spliced into the locking script before deploy. Used by runners to compile-check that calling `attachInscription` on the generated wrapper type-checks against the SDK's `Inscription` value type. |

If you add a new fixture, add a row above and a section below.

## Required structural elements

Every SDK's generated wrapper for each fixture **must** contain the
elements below. Per-SDK runners assert each one. Naming follows the
TypeScript reference (`packages/runar-sdk/src/codegen/gen-typescript.ts`)
modulo language-idiomatic case (camelCase → snake_case in Ruby/Python,
`<Name>Contract` everywhere).

### `p2pkh.json`

- A `P2PKHConstructorArgs` record / struct / hash with one field
  `pubKeyHash` typed as the language's bytes-equivalent.
- A `P2PKHContract` wrapper with:
  - constructor / `init` taking `(artifact, args)` (or equivalent)
  - `static fromUtxo(artifact, utxo)` factory
  - `static fromTxId(artifact, txid, output_index, provider)` factory
  - `connect(provider, signer)`
  - `attachInscription(insc)` (or `attach_inscription`)
  - `getLockingScript()` (or `get_locking_script`)
  - `deploy(satoshis_or_options)`
  - `unlock(pubKey, ...)` — **must not** declare a `Sig` parameter
    (auto-resolved by SDK)
  - `prepareUnlock(pubKey, ...)` returning the SDK's `PreparedCall` type
  - `finalizeUnlock(prepared, sig)` returning the SDK's call-result type
- A `TerminalOutput` record (because `unlock` is terminal).
- **Must not** emit a `*StatefulCallOptions` record (stateless contract).

### `counter.json`

- A `CounterConstructorArgs` record with one `count` field (`bigint` /
  `BigInteger` / `i64` / `Integer` per language).
- A `CounterStatefulCallOptions` record with at least the fields
  `satoshis`, `change_address` (or `changeAddress`), `change_pub_key`,
  `new_state`, `outputs` — names follow language-idiomatic case.
- An `OutputSpec` (or equivalent) record for items in
  `CounterStatefulCallOptions.outputs`.
- A `TerminalOutput` record (because `reset` is terminal).
- A `CounterContract` wrapper with:
  - constructor / `init` taking `(artifact, args)` or per-field args
  - factories + delegations as above
  - `increment(amount, options?)` (non-terminal, accepts options)
  - `reset(outputs)` (terminal stateful, requires outputs list)
  - typed state accessor `count()` returning the language's bigint type

### `simple.json`

- **Must not** emit a `SimpleConstructorArgs` record (no params).
- A `SimpleContract` wrapper whose primary constructor / `init` takes
  only `(artifact)`.
- `execute()` method.

### `stateful-escrow.json`

- An `EscrowConstructorArgs` record with three fields (`buyer`, `seller`,
  `amount`).
- An `EscrowStatefulCallOptions` record (because `claim` is non-terminal
  stateful), `OutputSpec`, and `TerminalOutput`.
- An `EscrowContract` wrapper with:
  - `claim(amountToClaim, options?)` — stateful non-terminal, hides the
    `Sig` and `SigHashPreimage` parameters from the user signature.
  - `prepareClaim(amountToClaim, options?)` returning `PreparedCall`
    (because `claim` has a `Sig` parameter — this is the dimension that
    `counter.json` does not cover).
  - `finalizeClaim(prepared, buyerSig)` taking exactly one signature.
  - `release(outputs)` — stateful terminal.
  - `prepareRelease(outputs)` returning `PreparedCall`.
  - `finalizeRelease(prepared, buyerSig, sellerSig)` — multi-`Sig`
    finalize. The signature parameters appear in the same order as the
    `Sig` arguments in the ABI.
- `amount()` state accessor returning the language's bigint type.

### `inscribed.json`

- An `InscribedHolderConstructorArgs` record with one `owner` field.
- An `InscribedHolderContract` wrapper that exposes `attachInscription(insc)`
  (or `attach_inscription(insc)`) accepting the SDK's `Inscription` value
  type. The runner must compile-check that calling `attachInscription`
  on the generated wrapper type-checks — generation alone is not
  sufficient (the bug class this suite exists to catch is "compiles in
  isolation, breaks at the call site").
- `transfer(pubKey, newOwner)` (stateless terminal) plus
  `prepareTransfer` / `finalizeTransfer` companions.

## Compile-check requirement

A pure structural assertion is not enough — the Rust bug shipped through
exactly that kind of test. **Each SDK's runner must compile the generated
wrapper end-to-end** (in-memory `javac`, `cargo check`, `tsc --noEmit`,
`zig build-obj`, `python -c "compile(src, 'gen.py', 'exec')"`, etc.) and
fail loudly if the output does not parse / type-check. The runner under
`runners/<lang>/` documents exactly how it does so.

## Adding a new SDK to the suite

1. Create `runners/<lang>/<lang>_codegen_conformance_test.<ext>` mirroring
   the existing runner pattern for that language's test framework.
2. Make it load all three fixtures from `fixtures/`, run the SDK's
   codegen on each, and assert (a) every required element from the
   relevant section above is present, and (b) the generated source
   compiles cleanly.
3. Wire it into the SDK's main test suite so it runs by default.
