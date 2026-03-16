import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, ALICE, BOB, signTestMessage } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'NFTExample.runar.sol'), 'utf8');
const FILE_NAME = 'NFTExample.runar.sol';

const ALICE_PK = ALICE.pubKey;
const BOB_PK = BOB.pubKey;
const ALICE_SIG = signTestMessage(ALICE.privKey);
const TOKEN_ID = 'deadbeef01020304';
const METADATA = 'cafebabe';
const SATS = 1000n;

describe('SimpleNFT (Solidity)', () => {
  function makeNFT(owner = ALICE_PK) {
    return TestContract.fromSource(source, {
      owner,
      tokenId: TOKEN_ID,
      metadata: METADATA,
    }, FILE_NAME);
  }

  it('transfers ownership', () => {
    const nft = makeNFT();
    const result = nft.call('transfer', {
      sig: ALICE_SIG,
      newOwner: BOB_PK,
      outputSatoshis: SATS,
    });
    expect(result.success).toBe(true);
    expect(result.outputs).toHaveLength(1);
    expect(result.outputs[0]!.owner).toBe(BOB_PK);
  });

  it('burns the token with no outputs', () => {
    const nft = makeNFT();
    const result = nft.call('burn', { sig: ALICE_SIG });
    expect(result.success).toBe(true);
    expect(result.outputs).toHaveLength(0);
  });

  it('preserves immutable properties after transfer', () => {
    const nft = makeNFT();
    nft.call('transfer', { sig: ALICE_SIG, newOwner: BOB_PK, outputSatoshis: SATS });
    // tokenId and metadata are readonly — they don't change
    expect(nft.state.tokenId).toBe(TOKEN_ID);
    expect(nft.state.metadata).toBe(METADATA);
  });
});
