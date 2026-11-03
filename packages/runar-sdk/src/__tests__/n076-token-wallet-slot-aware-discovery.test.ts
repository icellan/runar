/**
 * N-076: TokenWallet.getUtxos() must discover a deployed token contract with
 * the SLOT-AWARE matcher (`matchesArtifact`), not a raw byte prefix of the
 * template.
 *
 * The template carries three kinds of variable element: a constructor slot
 * (OP_0 replaced by the encoded argument), a codeSepIndex slot (OP_0 baked as
 * OP_1.. at deploy time) and a codePartLenSlots field (a 4-byte placeholder
 * replaced by the deployed code-part length). R-274 only matched up to the
 * first constructor slot, so a template with an earlier codeSepIndex slot
 * mismatched every honest deployment, and an unrelated script sharing the
 * leading bytes was accepted.
 *
 * Proves: a deployed instance (all three slot kinds substituted, plus a state
 * section) is found; scripts that share the pre-slot prefix but differ after
 * it, or carry a wrong code-part length, are not. Does NOT prove: on-chain
 * spendability of the matched UTXO, nor that a codeSepIndex-only artifact (no
 * constructor slots) is matched — `matchesArtifact` itself compares such a
 * template literally.
 */

import { describe, it, expect } from 'vitest';
import { TokenWallet } from '../tokens.js';
import { MockProvider } from '../providers/mock.js';
import type { RunarArtifact } from '../types.js';
import type { Signer } from '../signers/signer.js';

const signer = {
  async getPublicKey() { return '02' + '11'.repeat(32); },
  async getAddress() { return 'mocked-address'; },
  async sign() { return '00'.repeat(71); },
} as unknown as Signer;

// bytes: 76 a9 [00] 88 [00] 75 04 [00000000] ac
//   ctor slot @2, codeSepIndex slot @4, codePartLen field @7
const artifact = {
  version: 'runar-v0.1.0',
  compilerVersion: '0.1.0',
  contractName: 'FungibleToken',
  abi: {
    constructor: { params: [{ name: 'supply', type: 'bigint' }] },
    methods: [{ name: 'transfer', params: [], isPublic: true }],
  },
  script: '76a9' + '00' + '88' + '00' + '75' + '04' + '00000000' + 'ac',
  asm: '',
  stateFields: [{ name: 'balance', type: 'bigint', index: 1 }],
  constructorSlots: [{ paramIndex: 0, byteOffset: 2 }],
  // N-318: codeSepIndex 1, so the OP_1 baked below is what deploy writes there.
  codeSepIndexSlots: [{ byteOffset: 4, codeSepIndex: 1 }],
  codePartLenSlots: [{ byteOffset: 7 }],
  buildTimestamp: '2026-01-01T00:00:00Z',
} as unknown as RunarArtifact;

const STATE = '6a' + '0100';
// supply = 02aabb (3 bytes), codeSepIndex baked as OP_1, code part is 14 bytes.
const deployed = (tail = 'ac', len = '0e000000') =>
  '76a9' + '02aabb' + '88' + '51' + '75' + '04' + len + tail + STATE;

async function discover(...scripts: string[]): Promise<string[]> {
  const provider = new MockProvider();
  scripts.forEach((script, i) =>
    provider.addUtxo('mocked-address', {
      txid: String(i).repeat(64), outputIndex: 0, satoshis: 1000, script,
    }));
  const wallet = new TokenWallet(artifact, provider, signer);
  return (await wallet.getUtxos()).map((u) => u.txid);
}

describe('N-076: TokenWallet.getUtxos uses the slot-aware matcher', () => {
  it('finds a deployed instance with constructor, codeSepIndex and code-part-length slots', async () => {
    expect(await discover(deployed())).toEqual(['0'.repeat(64)]);
  });

  it('does not match scripts that share the pre-slot prefix but differ after it', async () => {
    expect(await discover(deployed('ad'))).toEqual([]);
  });

  it('does not match a script with a wrong code-part length field', async () => {
    expect(await discover(deployed('ac', '0f000000'))).toEqual([]);
  });

  it('does not match an unrelated script', async () => {
    expect(await discover('76a914' + '11'.repeat(20) + '88ac')).toEqual([]);
  });
});
