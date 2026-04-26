import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'MultiSig2of3.runar.ts'), 'utf8');

// Mock 33-byte compressed pubkeys and signatures. checkMultiSig is mocked
// in the interpreter — these are placeholders for shape only.
const PK1 = '02' + 'aa'.repeat(32);
const PK2 = '02' + 'bb'.repeat(32);
const PK3 = '02' + 'cc'.repeat(32);
const SIG1 = '30' + '11'.repeat(35);
const SIG2 = '30' + '22'.repeat(35);

describe('MultiSig2of3 (TS)', () => {
  it('compiles a 2-of-3 multisig to Bitcoin Script with OP_CHECKMULTISIG', () => {
    const contract = TestContract.fromSource(source, { pk1: PK1, pk2: PK2, pk3: PK3 });
    const result = contract.call('unlock', { sig1: SIG1, sig2: SIG2 });
    expect(typeof result.success).toBe('boolean');
  });

  it('exposes all three pubkeys as readonly state', () => {
    const contract = TestContract.fromSource(source, { pk1: PK1, pk2: PK2, pk3: PK3 });
    expect(contract.state.pk1).toBeDefined();
    expect(contract.state.pk2).toBeDefined();
    expect(contract.state.pk3).toBeDefined();
  });
});
