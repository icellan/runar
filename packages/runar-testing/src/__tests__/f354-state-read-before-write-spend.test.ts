/**
 * F-354 (closes the execution-level half of CX-GAP-028, the compiler-unit
 * half of which F-291 already closed inside `05-stack-lower-state-types.test.ts`).
 *
 * CX-GAP-028's literal complaint: "the comment says the mutation seeds a
 * `load_prop`, but `this.v = newV` does not read the old property" — every
 * `it(...).not.toThrow()` test in `05-stack-lower-state-types.test.ts` used a
 * method body that unconditionally OVERWRITES its single mutable property
 * without reading it first, so nothing in that file (even after F-291 pinned
 * the exact Stack-IR opcodes each type's deserializer and write-side width
 * guard emit) proves those opcodes are read by a REAL transaction, as opposed
 * to merely present in the emitted script. The same gap exists one layer up:
 * every other execution-level test for these five types also fully
 * overwrites its property without reading the old value first —
 * `f350-ripemd160-state-roundtrip.test.ts` says so explicitly in its own
 * "what this does NOT prove" note (its mutation-1 case is dead code on that
 * contract shape for exactly this reason); `curve-point-state-roundtrip.
 * test.ts`'s `CurvePointState.update` and `f035-rabin-state-spend.test.ts`'s
 * `RabinState.rotate` (for `oracleKey`/`lastSig`; only its unrelated `count`
 * field is read-modify-written) have the identical shape.
 *
 * This file closes that gap for all five types F-291/CX-GAP-028 named
 * (Ripemd160, P256Point, P384Point, RabinSig, RabinPubKey), for the TS tier
 * (this item's scope — Tier: compiler:ts in the brief): each contract's
 * `update(prev, next)` method does
 *
 *     assert(this.v == prev);
 *     this.v = next;
 *
 * which forces `05-stack-lower.ts`'s `lowerDeserializeState` to emit a real
 * `load_prop` field extractor whose output feeds a comparison that gates
 * whether the spend is valid at all — not a dead read. Two things are then
 * proven on the real `@bsv/sdk` Spend engine (never `TestContract` / the ANF
 * interpreter):
 *
 *   1. an HONEST update, where `prev` is the value actually deployed, is
 *      ACCEPTED and the resulting state reads back `next` byte-exactly; and
 *   2. a call with a WRONG `prev` (anything other than the deployed value)
 *      is REJECTED — proving the on-chain comparison is against bytes the
 *      script actually decoded off the previous output, not a free pass.
 *
 * Verified by hand against a one-line production mutation in
 * `05-stack-lower.ts`'s `lowerDeserializeState` (the `propSizes.push(<width>)`
 * call for each type, ~line 4045-4059: `case 'Ripemd160': propSizes.push(20)`
 * etc.), changed to push one byte more or less than the type's true width.
 * Where `f350-ripemd160-state-roundtrip.test.ts`'s equivalent mutation stays
 * GREEN (its single property is unconditionally overwritten, never read),
 * this file's HONEST-update case (1 above) goes RED for every one of the
 * five types: the mis-sized extractor hands `this.v` the wrong bytes, the
 * `assert(this.v == prev)` gate fails even though `prev` is the real
 * deployed value, and the real Spend engine rejects the honest spend.
 * Reverting the mutation restores GREEN. Captured output lives in
 * remediation-logs/F-354/.
 *
 * What this proves: for Ripemd160, P256Point, P384Point, RabinSig, and
 * RabinPubKey, the TS reference compiler's deserialize_state extractor for a
 * mutable property of that type decodes the value actually committed by the
 * previous spend — not merely a byte pattern that compiles without throwing
 * — and that decoded value participates correctly in a real on-chain
 * comparison, with the mutation reserializing to the byte-exact new value.
 * What this does NOT prove: the other six tiers (out of this item's scope —
 * the brief's Tier is compiler:ts); the `addOutput`-based continuation writer
 * (only the auto-continuation writer is exercised here, matching F-350's
 * scope); whether a numeric field's BIN2NUM conversion is present (that is
 * F-291's job, at the Stack-IR level, via explicit opcode assertions — a
 * dropped BIN2NUM does not necessarily change the integer value OP_NUMEQUAL
 * computes from an already num2bin-encoded byte string, so this execution
 * test has no reason to be sensitive to it); or adversarial wrong-width
 * INPUTS (covered, statically, by `n045-state-fixed-width-spend.test.ts`).
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner, buildP2PKHScript } from 'runar-sdk';
import { Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { testKey, validateContractInput } from '../oracle/real-crypto-execution.js';

const OWNER = testKey('alice');
const DEPLOY_SATS = 100_000;

function source(propType: string): string {
  return `import { StatefulSmartContract } from 'runar-lang';
import type { ${propType} } from 'runar-lang';

class StateCarrier extends StatefulSmartContract {
  v: ${propType};

  constructor(v: ${propType}) {
    super(v);
    this.v = v;
  }

  public update(prev: ${propType}, next: ${propType}) {
    assert(this.v == prev);
    this.v = next;
  }
}
`;
}
const FILE = 'StateCarrier.runar.ts';

function compileOrThrow(propType: string): RunarArtifact {
  const r = compile(source(propType), { fileName: FILE });
  if (!r.success || !r.artifact) throw new Error(JSON.stringify(r.diagnostics));
  return r.artifact as unknown as RunarArtifact;
}

interface CaseDef {
  type: string;
  v0: string | bigint;
  v1: string | bigint;
  wrongPrev: string | bigint;
}

const CASES: CaseDef[] = [
  { type: 'Ripemd160', v0: '11'.repeat(20), v1: '99'.repeat(20), wrongPrev: '22'.repeat(20) },
  { type: 'P256Point', v0: '11'.repeat(64), v1: '22'.repeat(64), wrongPrev: '33'.repeat(64) },
  { type: 'P384Point', v0: 'cc'.repeat(96), v1: 'dd'.repeat(96), wrongPrev: 'ee'.repeat(96) },
  { type: 'RabinSig', v0: 0x1234567890abcdefn, v1: -1000000007n, wrongPrev: 7n },
  { type: 'RabinPubKey', v0: 0x0badc0ffee123456n, v1: -42n, wrongPrev: 99n },
];

async function deployAndCall(
  propType: string,
  v0: string | bigint,
  args: [string | bigint, string | bigint],
): Promise<{ accepted: boolean; reachedEngine: boolean; error?: string; state?: unknown }> {
  const artifact = compileOrThrow(propType);
  const provider = new MockProvider();
  const signer = new LocalSigner(OWNER.privKey);
  provider.addUtxo(await signer.getAddress(), {
    txid: OWNER.privKey.slice(0, 64),
    outputIndex: 0,
    satoshis: 5_000_000,
    script: buildP2PKHScript(OWNER.pubKey),
  });

  const contract = new RunarContract(artifact, [v0]);
  await contract.deploy(provider, signer, { satoshis: DEPLOY_SATS });
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);

  try {
    await contract.call('update', args, provider, signer, {
      dryRun: true,
      satoshis: DEPLOY_SATS,
    });
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    return {
      accepted: false,
      reachedEngine: error.includes('local pre-broadcast dry-run rejected the primary contract input'),
      error: error.slice(0, 400),
    };
  }
  const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
  const accepted = validateContractInput(callTx, 0, deployTx, 0);
  return { accepted, reachedEngine: true, state: contract.state };
}

describe('F-354: the real Spend engine deserializes the OLD state value before the write', () => {
  for (const c of CASES) {
    describe(c.type, () => {
      it('HONEST update(deployedValue, next): ACCEPTED, and state reads back next byte-exactly', async () => {
        const r = await deployAndCall(c.type, c.v0, [c.v0, c.v1]);
        expect(r.reachedEngine, `never reached Spend: ${r.error ?? '(accepted)'}`).toBe(true);
        expect(r.accepted, `honest update must be accepted: ${r.error}`).toBe(true);
        expect((r.state as Record<string, unknown>).v).toBe(c.v1);
      }, 60_000);

      it('WRONG prev (does not match the deployed value): REJECTED', async () => {
        const r = await deployAndCall(c.type, c.v0, [c.wrongPrev, c.v1]);
        expect(r.reachedEngine, `never reached Spend: ${r.error ?? '(accepted)'}`).toBe(true);
        expect(r.accepted, 'a mismatched prev must be rejected by the on-chain assert').toBe(false);
      }, 60_000);
    });
  }
});
