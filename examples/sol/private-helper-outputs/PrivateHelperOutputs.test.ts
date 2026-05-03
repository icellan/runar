import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'PrivateHelperOutputs.runar.sol'), 'utf8');
const FILE_NAME = 'PrivateHelperOutputs.runar.sol';

describe('PrivateHelperOutputs (Solidity)', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { counter: 0n }, FILE_NAME);
    expect(c.state.counter).toBe(0n);
  });

  it('commit invokes private state mutation and persists the change', () => {
    const c = TestContract.fromSource(source, { counter: 5n }, FILE_NAME);
    const r = c.call('commit', {});
    expect(r.success).toBe(true);
    expect(c.state.counter).toBe(6n);
  });

  it('log routes a data output through a private helper', () => {
    const c = TestContract.fromSource(source, { counter: 0n }, FILE_NAME);
    const r = c.call('log', { payload: '6a0768656c6c6f21' });
    expect(r.success).toBe(true);
    expect(r.outputs!.some((o) => '_dataScript' in (o as object))).toBe(true);
  });

  it('partition routes a state output through a private helper', () => {
    const c = TestContract.fromSource(source, { counter: 100n }, FILE_NAME);
    const r = c.call('partition', { amount: 30n, leftover: 70n });
    expect(r.success).toBe(true);
    expect((r.outputs ?? []).length).toBeGreaterThanOrEqual(1);
  });
});
