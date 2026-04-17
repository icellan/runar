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
import { BSV20 } from '../../../packages/runar-sdk/src/ordinals/bsv20.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'BSV20Token.runar.ts'), 'utf8');

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
  const result = compile(source, { fileName: 'BSV20Token.runar.ts' });
  if (!result.success || !result.artifact) {
    const errors = result.diagnostics
      .filter((d) => d.severity === 'error')
      .map((d) => d.message)
      .join('\n  ');
    throw new Error(`BSV20Token compile failed:\n  ${errors}`);
  }
  return result.artifact;
}

describe('BSV20Token', () => {
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
      expect(artifact.contractName).toBe('BSV20Token');
    });
  });

  describe('BSV-20 deploy inscription', () => {
    it('creates a deploy inscription with correct JSON', () => {
      const artifact = compileContract();
      const inscription = BSV20.deploy({ tick: 'RUNAR', max: '21000000', lim: '1000' });
      const contract = new RunarContract(artifact, [ALICE.pubKeyHash]);
      contract.withInscription(inscription);

      const lockingScript = contract.getLockingScript();
      const parsed = parseInscriptionEnvelope(lockingScript);

      expect(parsed).not.toBeNull();
      expect(parsed!.contentType).toBe('application/bsv-20');

      const json = JSON.parse(hexToUtf8(parsed!.data));
      expect(json.p).toBe('bsv-20');
      expect(json.op).toBe('deploy');
      expect(json.tick).toBe('RUNAR');
      expect(json.max).toBe('21000000');
      expect(json.lim).toBe('1000');
    });

    it('creates a deploy inscription with decimals', () => {
      const artifact = compileContract();
      const inscription = BSV20.deploy({ tick: 'USDT', max: '100000000', dec: '8' });
      const contract = new RunarContract(artifact, [ALICE.pubKeyHash]);
      contract.withInscription(inscription);

      const lockingScript = contract.getLockingScript();
      const parsed = parseInscriptionEnvelope(lockingScript);

      const json = JSON.parse(hexToUtf8(parsed!.data));
      expect(json.dec).toBe('8');
    });
  });

  describe('BSV-20 mint inscription', () => {
    it('creates a mint inscription with correct JSON', () => {
      const artifact = compileContract();
      const inscription = BSV20.mint({ tick: 'RUNAR', amt: '1000' });
      const contract = new RunarContract(artifact, [ALICE.pubKeyHash]);
      contract.withInscription(inscription);

      const lockingScript = contract.getLockingScript();
      const parsed = parseInscriptionEnvelope(lockingScript);

      expect(parsed).not.toBeNull();
      expect(parsed!.contentType).toBe('application/bsv-20');

      const json = JSON.parse(hexToUtf8(parsed!.data));
      expect(json.p).toBe('bsv-20');
      expect(json.op).toBe('mint');
      expect(json.tick).toBe('RUNAR');
      expect(json.amt).toBe('1000');
    });
  });

  describe('BSV-20 transfer inscription', () => {
    it('creates a transfer inscription with correct JSON', () => {
      const artifact = compileContract();
      const inscription = BSV20.transfer({ tick: 'RUNAR', amt: '50' });
      const contract = new RunarContract(artifact, [ALICE.pubKeyHash]);
      contract.withInscription(inscription);

      const lockingScript = contract.getLockingScript();
      const parsed = parseInscriptionEnvelope(lockingScript);

      expect(parsed).not.toBeNull();
      expect(parsed!.contentType).toBe('application/bsv-20');

      const json = JSON.parse(hexToUtf8(parsed!.data));
      expect(json.p).toBe('bsv-20');
      expect(json.op).toBe('transfer');
      expect(json.tick).toBe('RUNAR');
      expect(json.amt).toBe('50');
    });
  });

  describe('round-trip', () => {
    it('inscription survives fromUtxo round-trip', () => {
      const artifact = compileContract();
      const inscription = BSV20.deploy({ tick: 'TEST', max: '1000' });
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
      expect(json.op).toBe('deploy');
      expect(json.tick).toBe('TEST');
      expect(json.max).toBe('1000');
    });
  });
});
