import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';
import { createHash } from 'node:crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'CrossCovenantRef.runar.sol'), 'utf8');
const FILE_NAME = 'CrossCovenantRef.runar.sol';

function hash256hex(hex: string): string {
  const first = createHash('sha256').update(Buffer.from(hex, 'hex')).digest();
  return createHash('sha256').update(first).digest('hex');
}

describe('CrossCovenantRef (Solidity)', () => {
  // Simulate a referenced output: some bytes with an embedded state root
  // Layout: 16 bytes prefix + 32 bytes state root + 8 bytes suffix
  const prefix = 'aabbccddee0011223344556677889900';
  const stateRoot = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
  const suffix = '0102030405060708';
  const referencedOutput = prefix + stateRoot + suffix;

  // Hash of the referenced output
  const outputHash = hash256hex(referencedOutput);

  describe('verifyAndExtract', () => {
    it('accepts valid output with correct state root', () => {
      const c = TestContract.fromSource(source, { sourceScriptHash: outputHash }, FILE_NAME);
      const r = c.call('verifyAndExtract', {
        referencedOutput,
        expectedStateRoot: stateRoot,
        stateRootOffset: 16n, // prefix is 16 bytes
      });
      expect(r.success).toBe(true);
    });

    it('rejects tampered output (wrong hash)', () => {
      const c = TestContract.fromSource(source, { sourceScriptHash: outputHash }, FILE_NAME);
      const tampered = 'ff' + referencedOutput.slice(2);
      const r = c.call('verifyAndExtract', {
        referencedOutput: tampered,
        expectedStateRoot: stateRoot,
        stateRootOffset: 16n,
      });
      expect(r.success).toBe(false);
    });

    it('rejects wrong state root expectation', () => {
      const c = TestContract.fromSource(source, { sourceScriptHash: outputHash }, FILE_NAME);
      const wrongRoot = '0000000000000000000000000000000000000000000000000000000000000000';
      const r = c.call('verifyAndExtract', {
        referencedOutput,
        expectedStateRoot: wrongRoot,
        stateRootOffset: 16n,
      });
      expect(r.success).toBe(false);
    });
  });
});
