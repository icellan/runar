// INTERPRETER-ONLY: spendability covered by conformance/witnesses/real-crypto/sighash-single-stateful.json
// (real deploy->call->@bsv/sdk Spend on THIS source with an uncommitted change output present, pinned
//  expectedState: bump 5->6 accepts, reset 5->0 accepts; a tampered continuation rejects under both
//  modes and a value-skimming SINGLE continuation rejects) and by conformance/sdk-call/ (the cross-SDK
//  SINGLE call vector).
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'SingleCounter.runar.ts'), 'utf8');

describe('SingleCounter', () => {
  it('bump (SINGLE|FORKID) takes no change params; reset (ALL|FORKID) still does', () => {
    // N-038: a SINGLE continuation commits only its own output, so the ABI
    // carries no _changePKH / _changeAmount for bump. This pins the ABI shape,
    // not the on-chain behaviour (that is the witness named above).
    const r = compile(source, { fileName: 'SingleCounter.runar.ts' });
    expect(r.success).toBe(true);
    const params = (name: string) =>
      r.artifact!.abi.methods.find((m) => m.name === name)!.params.map((p) => p.name);
    expect(params('bump')).not.toContain('_changePKH');
    expect(params('bump')).not.toContain('_changeAmount');
    expect(params('reset')).toContain('_changePKH');
    expect(params('reset')).toContain('_changeAmount');
  });

  it('bump emits one continuation carrying the incremented count', () => {
    const c = TestContract.fromSource(source, { count: 0n });
    const result = c.call('bump');
    expect(result.success).toBe(true);
    expect(result.outputs).toHaveLength(1);
    expect(result.outputs[0]!.count).toBe(1n);
  });

  it('reset clears a non-zero count', () => {
    const c = TestContract.fromSource(source, { count: 3n });
    expect(c.call('reset').success).toBe(true);
    expect(c.state.count).toBe(0n);
  });

  it('reset rejects a zero count', () => {
    const c = TestContract.fromSource(source, { count: 0n });
    expect(c.call('reset').success).toBe(false);
  });
});
