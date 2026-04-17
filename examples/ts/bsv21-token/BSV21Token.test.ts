import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, ALICE, signTestMessage } from 'runar-testing';
import { compile } from 'runar-compiler';
import type { RunarArtifact } from 'runar-ir-schema';
import { RunarContract } from '../../../packages/runar-sdk/src/contract.js';
import {
  parseInscriptionEnvelope,
} from '../../../packages/runar-sdk/src/ordinals/envelope.js';
import { BSV21 } from '../../../packages/runar-sdk/src/ordinals/bsv20.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'BSV21Token.runar.ts'), 'utf8');

const SIG = signTestMessage(ALICE.privKey);

/** Convert hex to UTF-8 string. */
function hexToUtf8(hex: string): string {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return new TextDecoder().decode(bytes);
}

function compileContract(): RunarArtifact {
  const result = compile(source, { fileName: 'BSV21Token.runar.ts' });
  if (!result.success || !result.artifact) {
    const errors = result.diagnostics
      .filter((d) => d.severity === 'error')
      .map((d) => d.message)
      .join('\n  ');
    throw new Error(`BSV21Token compile failed:\n  ${errors}`);
  }
  return result.artifact;
}

describe('BSV21Token', () => {
  describe('business logic', () => {
    it('accepts a valid unlock', () => {
      const contract = TestContract.fromSource(source, { pubKeyHash: ALICE.pubKeyHash });
      const result = contract.call('unlock', { sig: SIG, pubKey: ALICE.pubKey });
      expect(result.success).toBe(true);
    });
  });

  describe('compilation', () => {
    it('compiles to a valid artifact', () => {
      const artifact = compileContract();
      expect(artifact.contractName).toBe('BSV21Token');
    });
  });

  describe('BSV-21 deploy+mint inscription', () => {
    it('creates a deploy+mint inscription with all fields', () => {
      const artifact = compileContract();
      const inscription = BSV21.deployMint({
        amt: '1000000',
        dec: '18',
        sym: 'RNR',
        icon: 'b61b0172d95e266c18aea0c624db987e971a5d6d4ebc2aaed85da4642d635735_0',
      });
      const contract = new RunarContract(artifact, [ALICE.pubKeyHash]);
      contract.withInscription(inscription);

      const lockingScript = contract.getLockingScript();
      const parsed = parseInscriptionEnvelope(lockingScript);

      expect(parsed).not.toBeNull();
      expect(parsed!.contentType).toBe('application/bsv-20');

      const json = JSON.parse(hexToUtf8(parsed!.data));
      expect(json.p).toBe('bsv-20');
      expect(json.op).toBe('deploy+mint');
      expect(json.amt).toBe('1000000');
      expect(json.dec).toBe('18');
      expect(json.sym).toBe('RNR');
      expect(json.icon).toBe('b61b0172d95e266c18aea0c624db987e971a5d6d4ebc2aaed85da4642d635735_0');
    });

    it('creates a deploy+mint inscription with minimal fields', () => {
      const artifact = compileContract();
      const inscription = BSV21.deployMint({ amt: '500' });
      const contract = new RunarContract(artifact, [ALICE.pubKeyHash]);
      contract.withInscription(inscription);

      const lockingScript = contract.getLockingScript();
      const parsed = parseInscriptionEnvelope(lockingScript);

      const json = JSON.parse(hexToUtf8(parsed!.data));
      expect(json.p).toBe('bsv-20');
      expect(json.op).toBe('deploy+mint');
      expect(json.amt).toBe('500');
      expect(json.dec).toBeUndefined();
      expect(json.sym).toBeUndefined();
    });
  });

  describe('BSV-21 transfer inscription', () => {
    it('creates a transfer inscription with token ID', () => {
      const artifact = compileContract();
      const tokenId = '3b313338fa0555aebeaf91d8db1ffebd74773c67c8ad5181ff3d3f51e21e0000_1';
      const inscription = BSV21.transfer({ id: tokenId, amt: '100' });
      const contract = new RunarContract(artifact, [ALICE.pubKeyHash]);
      contract.withInscription(inscription);

      const lockingScript = contract.getLockingScript();
      const parsed = parseInscriptionEnvelope(lockingScript);

      expect(parsed).not.toBeNull();
      expect(parsed!.contentType).toBe('application/bsv-20');

      const json = JSON.parse(hexToUtf8(parsed!.data));
      expect(json.p).toBe('bsv-20');
      expect(json.op).toBe('transfer');
      expect(json.id).toBe(tokenId);
      expect(json.amt).toBe('100');
    });
  });

  describe('round-trip', () => {
    it('deploy+mint inscription survives fromUtxo round-trip', () => {
      const artifact = compileContract();
      const inscription = BSV21.deployMint({ amt: '1000000', sym: 'RNR' });
      const contract = new RunarContract(artifact, [ALICE.pubKeyHash]);
      contract.withInscription(inscription);

      const lockingScript = contract.getLockingScript();

      const reconnected = RunarContract.fromUtxo(artifact, {
        txid: '00'.repeat(32),
        outputIndex: 0,
        satoshis: 1,
        script: lockingScript,
      });

      expect(reconnected.inscription).not.toBeNull();
      expect(reconnected.inscription!.contentType).toBe('application/bsv-20');

      const json = JSON.parse(hexToUtf8(reconnected.inscription!.data));
      expect(json.p).toBe('bsv-20');
      expect(json.op).toBe('deploy+mint');
      expect(json.amt).toBe('1000000');
      expect(json.sym).toBe('RNR');
    });

    it('transfer inscription survives fromUtxo round-trip', () => {
      const artifact = compileContract();
      const tokenId = 'abc123_0';
      const inscription = BSV21.transfer({ id: tokenId, amt: '50' });
      const contract = new RunarContract(artifact, [ALICE.pubKeyHash]);
      contract.withInscription(inscription);

      const lockingScript = contract.getLockingScript();

      const reconnected = RunarContract.fromUtxo(artifact, {
        txid: '00'.repeat(32),
        outputIndex: 0,
        satoshis: 1,
        script: lockingScript,
      });

      const json = JSON.parse(hexToUtf8(reconnected.inscription!.data));
      expect(json.op).toBe('transfer');
      expect(json.id).toBe(tokenId);
      expect(json.amt).toBe('50');
    });
  });
});
