import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, ALICE, BOB, signTestMessage } from 'runar-testing';
import { compile } from 'runar-compiler';
import type { RunarArtifact } from 'runar-ir-schema';
import { RunarContract } from '../../../packages/runar-sdk/src/contract.js';
import {
  buildInscriptionEnvelope,
  parseInscriptionEnvelope,
} from '../../../packages/runar-sdk/src/ordinals/envelope.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'OrdinalNFT.runar.ts'), 'utf8');

const SIG = signTestMessage(ALICE.privKey);
const BOB_SIG = signTestMessage(BOB.privKey);

/** Convert a UTF-8 string to hex. */
function utf8ToHex(str: string): string {
  return Array.from(new TextEncoder().encode(str))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Convert hex to UTF-8 string. */
function hexToUtf8(hex: string): string {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return new TextDecoder().decode(bytes);
}

function compileContract(): RunarArtifact {
  const result = compile(source, { fileName: 'OrdinalNFT.runar.ts' });
  if (!result.success || !result.artifact) {
    const errors = result.diagnostics
      .filter((d) => d.severity === 'error')
      .map((d) => d.message)
      .join('\n  ');
    throw new Error(`OrdinalNFT compile failed:\n  ${errors}`);
  }
  return result.artifact;
}

describe('OrdinalNFT', () => {
  describe('business logic', () => {
    it('accepts a valid unlock with correct pubkey and signature', () => {
      const contract = TestContract.fromSource(source, { pubKeyHash: ALICE.pubKeyHash });
      const result = contract.call('unlock', { sig: SIG, pubKey: ALICE.pubKey });
      expect(result.success).toBe(true);
    });

    it('rejects unlock with wrong public key', () => {
      const contract = TestContract.fromSource(source, { pubKeyHash: ALICE.pubKeyHash });
      const result = contract.call('unlock', { sig: BOB_SIG, pubKey: BOB.pubKey });
      expect(result.success).toBe(false);
    });

    it('is a stateless contract', () => {
      const contract = TestContract.fromSource(source, { pubKeyHash: ALICE.pubKeyHash });
      expect(contract.state.pubKeyHash).toBeDefined();
    });
  });

  describe('compilation', () => {
    it('compiles to a valid artifact', () => {
      const artifact = compileContract();
      expect(artifact.contractName).toBe('OrdinalNFT');
      expect(artifact.abi.methods).toHaveLength(1);
      expect(artifact.abi.methods[0]!.name).toBe('unlock');
    });
  });

  describe('SDK inscription flow', () => {
    it('attaches an image inscription to the locking script', () => {
      const artifact = compileContract();
      const contract = new RunarContract(artifact, [ALICE.pubKeyHash]);

      // Simulate a small PNG header as inscription data
      const pngData = '89504e470d0a1a0a';
      contract.withInscription({ contentType: 'image/png', data: pngData });

      const lockingScript = contract.getLockingScript();

      // The locking script should contain the inscription envelope
      const expectedEnvelope = buildInscriptionEnvelope('image/png', pngData);
      expect(lockingScript).toContain(expectedEnvelope);

      // Should be parseable back
      const parsed = parseInscriptionEnvelope(lockingScript);
      expect(parsed).not.toBeNull();
      expect(parsed!.contentType).toBe('image/png');
      expect(parsed!.data).toBe(pngData);
    });

    it('attaches a text inscription to the locking script', () => {
      const artifact = compileContract();
      const contract = new RunarContract(artifact, [ALICE.pubKeyHash]);

      const textData = utf8ToHex('Hello, Ordinals!');
      contract.withInscription({ contentType: 'text/plain', data: textData });

      const lockingScript = contract.getLockingScript();

      const parsed = parseInscriptionEnvelope(lockingScript);
      expect(parsed).not.toBeNull();
      expect(parsed!.contentType).toBe('text/plain');
      expect(hexToUtf8(parsed!.data)).toBe('Hello, Ordinals!');
    });

    it('round-trips inscription through fromUtxo', () => {
      const artifact = compileContract();
      const contract = new RunarContract(artifact, [ALICE.pubKeyHash]);

      const pngData = '89504e470d0a1a0a';
      contract.withInscription({ contentType: 'image/png', data: pngData });

      const lockingScript = contract.getLockingScript();

      // Simulate loading the contract from a UTXO on-chain
      const reconnected = RunarContract.fromUtxo(artifact, {
        txid: '00'.repeat(32),
        outputIndex: 0,
        satoshis: 1,
        script: lockingScript,
      });

      // The inscription should survive the round-trip
      expect(reconnected.inscription).not.toBeNull();
      expect(reconnected.inscription!.contentType).toBe('image/png');
      expect(reconnected.inscription!.data).toBe(pngData);
    });

    it('locking script without inscription has no envelope', () => {
      const artifact = compileContract();
      const contract = new RunarContract(artifact, [ALICE.pubKeyHash]);

      const lockingScript = contract.getLockingScript();
      const parsed = parseInscriptionEnvelope(lockingScript);
      expect(parsed).toBeNull();
    });

    it('withInscription returns this for chaining', () => {
      const artifact = compileContract();
      const contract = new RunarContract(artifact, [ALICE.pubKeyHash]);
      const result = contract.withInscription({ contentType: 'text/plain', data: '' });
      expect(result).toBe(contract);
    });
  });
});
