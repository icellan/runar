import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LockingScript, Spend, UnlockingScript, Utils } from '@bsv/sdk';
import type { ANFProgram } from 'runar-ir-schema';

import { executeOnChainAuthoritative, AssertionFailureError } from '../anf-interpreter.js';

// ---------------------------------------------------------------------------
// F-242 (CL-BUG-160): strict DER (BIP66) signatures.
//
// `conformance/sdk-der/vectors.json` is the cross-tier vector set. Every
// ok=false entry re-encodes a valid signature's (r, s) — a missing 0x00 sign
// pad, a superfluous 0x00, bytes left inside or after the SEQUENCE, BER
// long-form lengths — so the encoding is the only thing wrong with it. The TS
// tier delegates DER parsing to @bsv/sdk `Signature.fromDER`, which accepts an
// INTEGER whose top bit is set without the sign pad, so the ANF interpreter's
// real-crypto checkSig verified three of these as valid.
//
// Proves: (1) the fixture is what it claims — each malformed vector carries
// its control's (r, s), and @bsv/sdk's consensus interpreter (`Spend`) refuses
// it on signature ENCODING while letting every control past the encoding
// check; (2) executeOnChainAuthoritative's checkSig reaches the fixture verdict
// on every vector. Does not prove anything about the envelope path (see
// envelope.test.ts) or about curve arithmetic.
// ---------------------------------------------------------------------------

interface DerVector {
  id: string;
  digest: string;
  sig: string;
  ok: boolean;
  canonical_sig: string;
}

const fixture = JSON.parse(
  readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), '../../../../conformance/sdk-der/vectors.json'),
    'utf8',
  ),
) as { pubkey: string; vectors: DerVector[] };

/** Loose TLV read (any length form, trailing data ignored) → (r, s) as BigInt. */
function looseRS(hex: string): [bigint, bigint] {
  const b = Utils.toArray(hex, 'hex');
  let i = 0;
  const readLen = (): number => {
    const first = b[i++]!;
    if (first < 0x80) return first;
    let n = 0;
    for (let k = 0; k < (first & 0x7f); k++) n = (n << 8) | b[i++]!;
    return n;
  };
  i++; // 0x30
  readLen();
  const readInt = (): bigint => {
    i++; // 0x02
    const len = readLen();
    const v = BigInt('0x' + (Utils.toHex(b.slice(i, i + len)) || '0'));
    i += len;
    return v;
  };
  const r = readInt();
  return [r, readInt()];
}

/** Run `<sig> | <pubkey> OP_CHECKSIG` through @bsv/sdk's consensus interpreter. */
function spendError(sigHex: string): string {
  const b = Utils.toArray(sigHex, 'hex');
  const checksig = b.length === b[1]! + 3 ? b : [...b, 0x41];
  const spend = new Spend({
    sourceTXID: '00'.repeat(32),
    sourceOutputIndex: 0,
    sourceSatoshis: 100000,
    lockingScript: LockingScript.fromASM(`${fixture.pubkey} OP_CHECKSIG`),
    transactionVersion: 1,
    otherInputs: [],
    outputs: [],
    unlockingScript: new UnlockingScript([{ op: checksig.length, data: checksig }]),
    inputIndex: 0,
    inputSequence: 0xffffffff,
    lockTime: 0,
    isRelaxed: false,
  });
  try {
    spend.validate();
    return '';
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

function guardANF(): ANFProgram {
  return {
    contractName: 'Guard',
    properties: [{ name: 'value', type: 'bigint', readonly: false }],
    methods: [{
      name: 'unlock',
      params: [
        { name: 'sig', type: 'Sig' },
        { name: 'pk', type: 'PubKey' },
      ],
      body: [
        { name: 'sigArg', value: { kind: 'load_param', name: 'sig' } },
        { name: 'pkArg', value: { kind: 'load_param', name: 'pk' } },
        { name: 'sigOk', value: { kind: 'call', func: 'checkSig', args: ['sigArg', 'pkArg'] } },
        { name: 'assertSig', value: { kind: 'assert', value: 'sigOk' } },
        { name: 'one', value: { kind: 'load_const', value: 1n } },
        { name: 'upd', value: { kind: 'update_prop', name: 'value', value: 'one' } },
      ],
      isPublic: true,
    }],
  };
}

describe('strict DER signatures (F-242)', () => {
  it('fixture: every malformed vector re-encodes its control, and a node refuses only the malformed ones', () => {
    expect(fixture.vectors.some((v) => v.ok)).toBe(true);
    expect(fixture.vectors.some((v) => !v.ok)).toBe(true);
    for (const v of fixture.vectors) {
      expect(looseRS(v.sig), `${v.id}: (r, s) must match canonical_sig`).toEqual(looseRS(v.canonical_sig));
      const err = spendError(v.sig);
      if (v.ok) {
        expect(err, `${v.id}: control must pass the encoding check`).not.toMatch(/signature format is invalid/);
      } else {
        expect(v.sig, `${v.id}: must differ from its control`).not.toBe(v.canonical_sig);
        expect(err, `${v.id}: node must refuse the encoding`).toMatch(/signature format is invalid/);
      }
    }
  });

  for (const v of fixture.vectors) {
    it(`executeOnChainAuthoritative checkSig ${v.ok ? 'accepts' : 'refuses'} ${v.id}`, () => {
      const run = () =>
        executeOnChainAuthoritative(
          guardANF(),
          'unlock',
          { value: 0n },
          { sig: v.sig, pk: fixture.pubkey },
          [],
          { sighash: v.digest },
        );
      if (v.ok) {
        expect(run().state.value).toBe(1n);
      } else {
        // N-197: a non-strict-DER signature ABORTS OP_CHECKSIG (the Spend
        // check above refuses it on encoding), so the interpreter refuses it
        // with the abort error, not with an assert on a pushed false.
        let err: unknown;
        try { run(); } catch (e) { err = e; }
        expect(err).toBeInstanceOf(Error);
        expect(err).not.toBeInstanceOf(AssertionFailureError);
        expect((err as Error).message).toMatch(/not strict DER — OP_CHECKSIG aborts/);
      }
    });
  }
});
