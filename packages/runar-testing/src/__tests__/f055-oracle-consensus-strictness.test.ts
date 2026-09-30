/**
 * F-055 (CL-BUG-073): the off-chain acceptance oracles must judge a spend by
 * the rules a real node applies to the transactions this SDK builds.
 *
 * `@bsv/sdk`'s `Spend.isRelaxed()` is `isRelaxed || transactionVersion > 1`
 * (the Chronicle rule: a version > 1 transaction opts out of the unlocking-
 * script malleability restrictions). The SDK builds VERSION-1 transactions
 * (`new Transaction()`), so a real broadcast of an SDK-built spend faces the
 * STRICT rule set: push-only unlocking, clean stack, minimal push, minimal
 * script number, low-S and NULLDUMMY. `runStatelessSigned` and
 * `ScriptExecutionContract` built their `Spend` at version 2 and so judged
 * every spend under the relaxed set — a witness no node would relay was
 * reported as accepted.
 *
 * What this proves: each oracle entry point (`runStatelessSigned`,
 * `ScriptExecutionContract.execute` / `.executeSigned`, `validateContractInput`
 * — which is also `runStatefulSpend`'s engine — and the tri-modal `Spend` leg's
 * shared constructor) rejects a spend that is logically valid but violates ONE
 * malleability rule, for that rule's reason, while the honest spend of the same
 * contract is still accepted; and a version-2 transaction handed to
 * `validateContractInput` is refused rather than silently judged relaxed.
 *
 * What this does not prove: that the strict rule set is exactly a given node
 * release's policy (it is `@bsv/sdk`'s model of it), or anything about
 * version-2 transactions on a real node — none of this SDK's builders emit one.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  BigNumber,
  Hash,
  LockingScript,
  PrivateKey,
  Transaction,
  TransactionSignature,
  UnlockingScript,
} from '@bsv/sdk';
import { runStatelessSigned, validateContractInput, testKey } from '../oracle/index.js';
import { ScriptExecutionContract } from '../script-execution.js';
import { newConsensusSpend, CONSENSUS_SPEND_CONTEXT } from '../consensus-spend.js';

const CONFORMANCE = resolve(__dirname, '../../../../conformance/tests');

function readContract(name: string): { source: string; fileName: string } {
  const manifest = JSON.parse(
    readFileSync(resolve(CONFORMANCE, name, 'source.json'), 'utf8'),
  ) as { sources: Record<string, string> };
  const rel = manifest.sources['.runar.ts']!;
  return { source: readFileSync(resolve(CONFORMANCE, name, rel), 'utf8'), fileName: rel.split('/').pop()! };
}

const hexBytes = (hex: string): Uint8Array => Uint8Array.from(Buffer.from(hex, 'hex'));

const SECP256K1_N = new BigNumber(
  'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',
  16,
);

/** Re-encode a `<len><DER||sighash>` signature push with s' = n - s: the same
 *  signature, still valid ECDSA, but the malleated high-S form. */
function highSPush(sigPushHex: string): string {
  const len = parseInt(sigPushHex.slice(0, 2), 16);
  const body = Array.from(hexBytes(sigPushHex.slice(2)));
  expect(body.length).toBe(len);
  const sig = TransactionSignature.fromChecksigFormat(body);
  expect(sig.hasLowS()).toBe(true);
  const high = new TransactionSignature(sig.r, SECP256K1_N.sub(sig.s), sig.scope);
  expect(high.hasLowS()).toBe(false);
  const bytes = high.toChecksigFormat();
  return bytes.length.toString(16).padStart(2, '0') + Buffer.from(bytes).toString('hex');
}

/** Four single-rule malleations of a `<sig> <pubKey>` P2PKH unlocking script.
 *  Each keeps the spend LOGICALLY valid: only the consensus/standardness rule
 *  named in `reason` is broken. */
const P2PKH_MALLEATIONS: {
  name: string;
  tamper: (pushes: string[]) => string;
  reason: RegExp;
}[] = [
  {
    // The brief's shape: an extra OP_1 after the sig/pubkey pushes. OP_1 alone
    // is a push opcode and would sit on top of the pubkey, breaking the P2PKH
    // logic in either mode; `OP_1 OP_DROP` keeps the logic intact and makes the
    // unlocking script non-push-only.
    name: 'non-push-only unlocking (extra OP_1 OP_DROP after the pushes)',
    tamper: (p) => p.join('') + '5175',
    reason: /push operations/,
  },
  {
    name: 'non-clean stack (an extra OP_1 below the sig)',
    tamper: (p) => '51' + p.join(''),
    reason: /clean stack/,
  },
  {
    name: 'non-minimal push (33-byte pubkey pushed with OP_PUSHDATA1)',
    tamper: (p) => p[0]! + '4c' + p[1]!,
    reason: /minimally-encoded/,
  },
  {
    // @bsv/sdk raises "must have a low S value" inside a try whose catch
    // rethrows it as "The signature format is invalid." — the red run showed the
    // relaxed engine ACCEPTING this exact signature, so the rejection is low-S.
    name: 'high-S signature',
    tamper: (p) => highSPush(p[0]!) + p[1]!,
    reason: /low S|signature format is invalid/,
  },
];

// ---------------------------------------------------------------------------
// runStatelessSigned
// ---------------------------------------------------------------------------

describe('F-055: runStatelessSigned applies the consensus malleability rules', () => {
  const { source, fileName } = readContract('basic-p2pkh');
  const alice = testKey('alice');
  const base = {
    source,
    fileName,
    method: 'unlock',
    args: [{ signWith: 'alice' }, hexBytes(alice.pubKey)],
    constructorArgs: { pubKeyHash: alice.pubKeyHash },
    checkInterpreter: false,
  };

  it('control: the honest spend is accepted', () => {
    const r = runStatelessSigned(base);
    expect(r.vmAccepted, r.vmError).toBe(true);
  });

  for (const m of P2PKH_MALLEATIONS) {
    it(`rejects a ${m.name}`, () => {
      const r = runStatelessSigned({ ...base, tamperUnlocking: m.tamper });
      expect(r.reachedEngine).toBe(true);
      expect(r.vmAccepted).toBe(false);
      expect(r.vmError).toMatch(m.reason);
    });
  }
});

// ---------------------------------------------------------------------------
// ScriptExecutionContract
// ---------------------------------------------------------------------------

describe('F-055: ScriptExecutionContract applies the consensus malleability rules', () => {
  describe('executeSigned (P2PKH)', () => {
    const { source } = readContract('basic-p2pkh');
    const alice = testKey('alice');
    const pk = PrivateKey.fromHex(alice.privKey);
    const c = ScriptExecutionContract.fromSource(source, { pubKeyHash: alice.pubKeyHash }, 'P2PKH.runar.ts');

    it('control: the honest spend is accepted', () => {
      const r = c.executeSigned('unlock', ['placeholder', alice.pubKey], 0, pk);
      expect(r.success, r.error).toBe(true);
    });

    for (const m of P2PKH_MALLEATIONS) {
      it(`rejects a ${m.name}`, () => {
        const r = c.executeSigned('unlock', ['placeholder', alice.pubKey], 0, pk, {
          tamperUnlocking: m.tamper,
        });
        expect(r.success).toBe(false);
        expect(r.error).toMatch(m.reason);
      });
    }
  });

  describe('execute (arithmetic, target 27 for a=3 b=7)', () => {
    const { source } = readContract('arithmetic');
    const c = ScriptExecutionContract.fromSource(source, { target: 27n }, 'arithmetic.runar.ts');

    it('control: the honest spend is accepted', () => {
      const r = c.execute('verify', [3n, 7n]);
      expect(r.success, r.error).toBe(true);
    });

    it('rejects a non-minimal push (3 pushed as a 1-byte data push instead of OP_3)', () => {
      const r = c.execute('verify', [3n, 7n], { tamperUnlocking: (p) => '0103' + p[1]! });
      expect(r.success).toBe(false);
      expect(r.error).toMatch(/minimally-encoded/);
    });

    it('rejects a non-minimal script number (3 encoded as 0x0300)', () => {
      const r = c.execute('verify', [3n, 7n], { tamperUnlocking: (p) => '020300' + p[1]! });
      expect(r.success).toBe(false);
      expect(r.error).toMatch(/minimal/i);
    });

    it('rejects a non-clean stack (an extra OP_1 below the args)', () => {
      const r = c.execute('verify', [3n, 7n], { tamperUnlocking: (p) => '51' + p.join('') });
      expect(r.success).toBe(false);
      expect(r.error).toMatch(/clean stack/);
    });

    it('rejects a non-push-only unlocking script (OP_1 OP_DROP appended)', () => {
      const r = c.execute('verify', [3n, 7n], { tamperUnlocking: (p) => p.join('') + '5175' });
      expect(r.success).toBe(false);
      expect(r.error).toMatch(/push operations/);
    });
  });
});

// ---------------------------------------------------------------------------
// validateContractInput (runStatefulSpend's engine) — a real transaction
// ---------------------------------------------------------------------------

describe('F-055: validateContractInput judges a real transaction strictly', () => {
  const { source, fileName } = readContract('basic-p2pkh');
  const alice = testKey('alice');
  const alicePriv = PrivateKey.fromHex(alice.privKey);
  const lockHex = ScriptExecutionContract.fromSource(source, { pubKeyHash: alice.pubKeyHash }, fileName).scriptHex;
  // A bare 1-of-1 CHECKMULTISIG output, to exercise NULLDUMMY.
  const multisigHex = '5121' + alice.pubKey + '51ae';

  function sourceTx(): Transaction {
    const t = new Transaction();
    t.addInput({ sourceTXID: 'ab'.repeat(32), sourceOutputIndex: 0, unlockingScript: new UnlockingScript(), sequence: 0xffffffff });
    t.addOutput({ satoshis: 10_000, lockingScript: LockingScript.fromHex(lockHex) });
    t.addOutput({ satoshis: 10_000, lockingScript: LockingScript.fromHex(multisigHex) });
    return t;
  }

  /** Spend `src`'s output `vout` in a transaction of the given version, with a
   *  real BIP-143 signature by alice, then let `unlock` build the unlocking
   *  script from the encoded sig push. */
  function spendTx(src: Transaction, vout: number, version: number, unlock: (sigPush: string) => string): Transaction {
    const t = new Transaction(version);
    t.addInput({ sourceTXID: src.id('hex'), sourceOutputIndex: vout, unlockingScript: new UnlockingScript(), sequence: 0xffffffff });
    t.addOutput({ satoshis: 9_000, lockingScript: LockingScript.fromHex('51') });
    const scope = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID;
    const preimage = TransactionSignature.formatBytes({
      sourceTXID: src.id('hex'),
      sourceOutputIndex: vout,
      sourceSatoshis: 10_000,
      transactionVersion: version,
      otherInputs: [],
      outputs: t.outputs,
      inputIndex: 0,
      subscript: src.outputs[vout]!.lockingScript,
      inputSequence: 0xffffffff,
      lockTime: 0,
      scope,
    });
    const s = alicePriv.sign(Hash.sha256(Array.from(preimage)));
    const bytes = new TransactionSignature(s.r, s.s, scope).toChecksigFormat();
    const sigPush = bytes.length.toString(16).padStart(2, '0') + Buffer.from(bytes).toString('hex');
    t.inputs[0]!.unlockingScript = UnlockingScript.fromHex(unlock(sigPush));
    return t;
  }

  const pubPush = '21' + alice.pubKey;

  it('control: the honest version-1 P2PKH spend is accepted', () => {
    const src = sourceTx();
    expect(validateContractInput(spendTx(src, 0, 1, (s) => s + pubPush), 0, src, 0)).toBe(true);
  });

  for (const m of P2PKH_MALLEATIONS) {
    it(`rejects a version-1 spend with a ${m.name}`, () => {
      const src = sourceTx();
      const tx = spendTx(src, 0, 1, (s) => m.tamper([s, pubPush]));
      expect(() => validateContractInput(tx, 0, src, 0)).toThrow(m.reason);
    });
  }

  it('control: the honest CHECKMULTISIG spend with a null dummy is accepted', () => {
    const src = sourceTx();
    expect(validateContractInput(spendTx(src, 1, 1, (s) => '00' + s), 0, src, 1)).toBe(true);
  });

  it('rejects a CHECKMULTISIG spend whose dummy is not null (NULLDUMMY)', () => {
    const src = sourceTx();
    const tx = spendTx(src, 1, 1, (s) => '51' + s);
    expect(() => validateContractInput(tx, 0, src, 1)).toThrow(/dummy/i);
  });

  it('refuses a version-2 transaction instead of silently judging it under the relaxed rule set', () => {
    const src = sourceTx();
    // Non-push-only: accepted by a version-2 (relaxed) Spend.
    const tx = spendTx(src, 0, 2, (s) => s + pubPush + '5175');
    expect(() => validateContractInput(tx, 0, src, 0)).toThrow(/version/i);
  });
});

// ---------------------------------------------------------------------------
// The shared constructor every oracle Spend goes through (incl. tri-modal)
// ---------------------------------------------------------------------------

describe('F-055: newConsensusSpend refuses to build a relaxed Spend', () => {
  it('rejects a non-push-only unlocking script at version 1', () => {
    const spend = newConsensusSpend({
      ...CONSENSUS_SPEND_CONTEXT,
      lockingScript: LockingScript.fromHex('51'),
      unlockingScript: UnlockingScript.fromHex('5175'),
      otherInputs: [],
      outputs: [],
    });
    expect(() => spend.validate()).toThrow(/push operations/);
  });

  it('throws on transactionVersion > 1', () => {
    expect(() =>
      newConsensusSpend({
        ...CONSENSUS_SPEND_CONTEXT,
        transactionVersion: 2,
        lockingScript: LockingScript.fromHex('51'),
        unlockingScript: UnlockingScript.fromHex(''),
        otherInputs: [],
        outputs: [],
      }),
    ).toThrow(/version/i);
  });

  it('throws on an explicit isRelaxed', () => {
    expect(() =>
      newConsensusSpend({
        ...CONSENSUS_SPEND_CONTEXT,
        isRelaxed: true,
        lockingScript: LockingScript.fromHex('51'),
        unlockingScript: UnlockingScript.fromHex(''),
        otherInputs: [],
        outputs: [],
      } as Parameters<typeof newConsensusSpend>[0]),
    ).toThrow(/relax/i);
  });
});
