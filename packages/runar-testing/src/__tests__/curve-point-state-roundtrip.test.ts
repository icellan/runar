/**
 * ACCEPTANCE TEST for N-066. RED until the SDK width tables carry
 * `P256Point` (64) and `P384Point` (96).
 *
 * A `P256Point` / `P384Point` state field must survive a real spend.
 *
 * All seven COMPILERS serialize both types raw and fixed-width — 64 and 96
 * bytes — byte-identically to each other, and `P256Point` byte-identically to
 * `Point`. (Locked by
 * `packages/runar-compiler/src/__tests__/curve-point-state-width.test.ts` and
 * by the `P256State*` / `P384State*` cases in `cross-compiler.test.ts`.)
 *
 * All seven SDKs' `encodeStateValue` / `decodeStateValue` enumerate the
 * fixed-size types as `PubKey, Addr, Ripemd160, Sha256, Point` and omit both
 * curve-point types, so they fall through to the push-data-framed default:
 *
 *   compiler writes/reads  <64 raw>            <96 raw>
 *   SDK deploys            40 || <64 raw>      4c 60 || <96 raw>
 *                          ^^ 65 bytes         ^^^^^ 98 bytes
 *
 * So the deploy succeeds and the FIRST spend fails — the script slices its
 * state at a compile-time offset that is one (or two) bytes short of where the
 * SDK actually put the value. Measured on the real `@bsv/sdk` Script VM:
 *
 *   P256Point  input 0: Script evaluation error: OP_NUMEQUALVERIFY requires
 *                       the top stack item to be truthy
 *   P384Point  (same)   state section = 98 bytes, `6a 4c60 cccc...`
 *
 * This is the same writer-vs-reader class as `Sig` / `SigHashPreimage`
 * (6dc1979b) with the sides reversed: there the SDK was right and six
 * compilers wrong; here all seven compilers are right and all seven SDKs are
 * wrong. The decider is the same one R-015 established — the fixed-width
 * enumeration — and `P256Point` / `P384Point` belong in it, because
 * `packages/runar-lang/src/types.ts` defines them as `ByteString` subtypes
 * whose cast constructors hard-assert 64 and 96 bytes.
 *
 * `Point` is the control: identical shape, already in every table, passes
 * today. `PubKey` (33) and `ByteString` (framed) bracket it on both sides.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner, findLastOpReturn } from 'runar-sdk';
import { PrivateKey } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

const PRIV = PrivateKey.fromString('b1'.repeat(32), 16);
const PKH = PRIV.toPublicKey().toHash('hex') as string;

function mutatingSource(propType: string): string {
  return `import { StatefulSmartContract } from 'runar-lang';
class CurvePointState extends StatefulSmartContract {
  tag: ${propType};
  constructor(tag: ${propType}) { super(tag); this.tag = tag; }
  public update(next: ${propType}) { this.tag = next; }
}`;
}

interface RoundTrip {
  /** Raw state-section bytes (after the last OP_RETURN) as DEPLOYED. */
  deployStateHex: string;
  /** Raw state-section bytes of the continuation the spend created. */
  postCallStateHex: string;
  /** Decoded state after a real Script VM spend. */
  postCallState: Record<string, unknown>;
}

/**
 * Deploy with `initial`, then spend calling `update(next)`, with
 * `MockProvider.enableBroadcastValidation()` so a misframed state section
 * fails the spend outright instead of an equality check.
 */
async function deployAndUpdate(
  propType: string,
  initial: string,
  next: string,
): Promise<RoundTrip> {
  const result = compile(mutatingSource(propType), { fileName: 'CurvePointState.runar.ts' });
  if (!result.success || !result.artifact) {
    throw new Error(`compile failed: ${result.diagnostics.map(d => d.message).join('; ')}`);
  }
  const signer = new LocalSigner(PRIV.toString());
  const provider = new MockProvider();
  provider.enableBroadcastValidation();
  provider.addUtxo(await signer.getAddress(), {
    txid: 'ee'.repeat(32),
    outputIndex: 0,
    satoshis: 1_000_000,
    script: '76a914' + PKH + '88ac',
  });

  const contract = new RunarContract(result.artifact as RunarArtifact, [initial]);
  contract.connect(provider, signer);
  await contract.deploy({ satoshis: 1000 });
  const deployed = contract.getUtxo()!.script;

  await contract.call('update', [next], { satoshis: 600 });
  const post = contract.getUtxo()!.script;

  return {
    deployStateHex: stateSectionHex(deployed),
    postCallStateHex: stateSectionHex(post),
    postCallState: contract.state as Record<string, unknown>,
  };
}

/** Slice the state section out of a locking script with the structural walker. */
function stateSectionHex(scriptHex: string): string {
  const pos = findLastOpReturn(scriptHex);
  if (pos === -1) throw new Error('stateSectionHex: no OP_RETURN in the script');
  return scriptHex.slice(pos + 2);
}

const CASES = [
  { type: 'Point', width: 64, a: 'aa'.repeat(64), b: 'bb'.repeat(64), control: true },
  { type: 'P256Point', width: 64, a: '11'.repeat(64), b: '22'.repeat(64), control: false },
  { type: 'P384Point', width: 96, a: 'cc'.repeat(96), b: 'dd'.repeat(96), control: false },
] as const;

describe('P256Point / P384Point state survives a real spend', () => {
  for (const c of CASES) {
    const tag = c.control ? `${c.type} (control)` : c.type;

    it(`${tag}: the SDK deploys ${c.width} RAW bytes, not a framed push`, async () => {
      const rt = await deployAndUpdate(c.type, c.a, c.b);
      // A framed push would be width+1 (direct) or width+2 (OP_PUSHDATA1).
      expect(rt.deployStateHex).toBe(c.a);
      expect(rt.deployStateHex.length / 2).toBe(c.width);
    });

    it(`${tag}: a spend round-trips the value through the continuation`, async () => {
      const rt = await deployAndUpdate(c.type, c.a, c.b);
      // The script's own writer emitted this — reading it back proves the
      // deploy-time WRITER and the on-chain READER agree on the width.
      expect(rt.postCallStateHex).toBe(c.b);
      expect(rt.postCallState.tag).toBe(c.b);
    });
  }

  it('negative control: a ByteString field IS framed', async () => {
    const value = '11'.repeat(64);
    const rt = await deployAndUpdate('ByteString', value, '22'.repeat(64));
    // 0x40 direct-push header, then the payload — NOT raw.
    expect(rt.deployStateHex).toBe('40' + value);
  });

  it('negative control: a PubKey field is raw at its own width (33)', async () => {
    const value = '02' + 'aa'.repeat(32);
    const rt = await deployAndUpdate('PubKey', value, '03' + 'bb'.repeat(32));
    expect(rt.deployStateHex).toBe(value);
    expect(rt.deployStateHex.length / 2).toBe(33);
  });
});
