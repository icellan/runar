/**
 * F-350 (closes the Ripemd160 half of CL-GAP-021, the remainder of which
 * F-291 already closed inside `05-stack-lower-state-types.test.ts`).
 *
 * `05-stack-lower-state-types.test.ts` pins the exact Stack-IR opcodes the
 * TS compiler emits for a mutable Ripemd160 state field (the
 * `OP_SIZE 20 OP_SUB OP_SPLIT nip` extractor and the `OP_SIZE 20
 * OP_NUMEQUALVERIFY` write-side width guard — F-291), and
 * `n045-state-fixed-width-spend.test.ts` proves every tier emits that same
 * width guard as a static byte pattern for Ripemd160 (among six other
 * fixed-width types) — but, by that file's own "what it does NOT prove"
 * note, never actually EXECUTES a Ripemd160 continuation: only its Sha256
 * case is driven through a real spend. So nothing in the suite proves a
 * Ripemd160 state value survives compile -> deploy -> update -> read back
 * through a real transaction, as opposed to merely compiling without an
 * exception or matching a byte pattern in the emitted script.
 *
 * This test closes that gap for the TS tier (this item's scope — Tier:
 * compiler:ts in the brief): it deploys a stateful contract with a single
 * mutable Ripemd160 property, spends it with a fresh 20-byte value, and
 * checks BOTH that the real `@bsv/sdk` Spend engine accepts the spend and
 * that the SDK's own (independently-implemented) state decoder reads back
 * exactly the new 20-byte value — a genuine round trip, not a byte-pattern
 * match on the compiler's own output.
 *
 * Oracle: `@bsv/sdk`'s production Spend via `validateContractInput`
 * (`real-crypto-execution.ts`), the same oracle `n045-state-fixed-width-
 * spend.test.ts` and `curve-point-state-roundtrip.test.ts` use. Never
 * TestContract / the ANF interpreter.
 *
 * Verified by hand against two one-line production mutations in
 * `05-stack-lower.ts` (reverted after each check):
 *   1. `case 'Ripemd160': propSizes.push(20);` (the deserialize_state field
 *      extractor width, ~line 4053) changed to `push(21)`. This file's
 *      single property is unconditionally overwritten and never read back
 *      inside `update`, so the mis-sized decode is dead on this exact
 *      contract shape and this test stays GREEN — only `05-stack-lower-
 *      state-types.test.ts`'s Stack-IR-level assertion (which inspects the
 *      extractor opcode directly, not the contract's execution) catches it.
 *      Recorded here so the gap is visible rather than silently assumed
 *      closed: a contract that reads `this.h` before overwriting it would
 *      be needed to make THIS test sensitive to that mutation too.
 *   2. `case 'Ripemd160': return 20;` (`fixedWidthStateBytes`, the N-045
 *      write-side width guard's single source of truth, ~line 6806)
 *      changed to `return 21`. This makes the continuation's `OP_SIZE 21
 *      OP_NUMEQUALVERIFY` guard check a value that is actually 20 bytes, so
 *      the honest update below is rejected by the real Spend engine
 *      (`OP_NUMEQUALVERIFY requires the top stack item to be truthy`); this
 *      test goes RED. Reverting restores GREEN.
 *
 * What this proves: a mutable Ripemd160 state field, compiled by the TS
 * reference compiler, round-trips an honest new 20-byte value through a
 * real deploy + spend + read-back on `@bsv/sdk`'s consensus-faithful Spend
 * engine.
 * What this does NOT prove: the other six tiers (out of this item's scope;
 * each has its own conformance/cross-tier coverage); adversarial
 * wrong-width inputs for Ripemd160 specifically (covered statically, not
 * executed, by `n045-state-fixed-width-spend.test.ts`); anything about
 * `addOutput`-based continuations (only the auto-continuation writer is
 * exercised here); or a wrong-width DESERIALIZE-side extractor on a
 * property that is read before being overwritten (mutation 1 above) — this
 * contract's single property is always fully replaced, so that mutation is
 * dead code on this exact shape and only `05-stack-lower-state-types.
 * test.ts`'s Stack-IR assertion catches it.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner, buildP2PKHScript } from 'runar-sdk';
import { Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { testKey, validateContractInput } from '../oracle/real-crypto-execution.js';

const SOURCE = `import { StatefulSmartContract } from 'runar-lang';
import type { Ripemd160 } from 'runar-lang';

class HashCarrier extends StatefulSmartContract {
  h: Ripemd160;

  constructor(h: Ripemd160) {
    super(h);
    this.h = h;
  }

  public update(next: Ripemd160) {
    this.h = next;
  }
}
`;
const FILE = 'HashCarrier.runar.ts';

const OWNER = testKey('alice');
const H0 = '11'.repeat(20);
const H1 = '99'.repeat(20);
const DEPLOY_SATS = 100_000;

function compileOrThrow(): RunarArtifact {
  const r = compile(SOURCE, { fileName: FILE });
  if (!r.success || !r.artifact) throw new Error(JSON.stringify(r.diagnostics));
  return r.artifact as unknown as RunarArtifact;
}

describe('F-350: stateful Ripemd160 property round-trips through a real spend', () => {
  it('update(next) is ACCEPTED by the real Spend engine and state reads back the new 20-byte value', async () => {
    const artifact = compileOrThrow();
    const provider = new MockProvider();
    const signer = new LocalSigner(OWNER.privKey);
    provider.addUtxo(await signer.getAddress(), {
      txid: OWNER.privKey.slice(0, 64),
      outputIndex: 0,
      satoshis: 5_000_000,
      script: buildP2PKHScript(OWNER.pubKey),
    });

    const contract = new RunarContract(artifact, [H0]);
    await contract.deploy(provider, signer, { satoshis: DEPLOY_SATS });
    const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

    await contract.call('update', [H1], provider, signer, {
      dryRun: true,
      satoshis: DEPLOY_SATS,
    });
    const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);

    const accepted = validateContractInput(callTx, 0, deployTx, 0);
    expect(accepted, 'honest Ripemd160 update must be accepted by the real Spend engine').toBe(true);
    expect(contract.state).toEqual({ h: H1 });
  }, 60_000);
});
