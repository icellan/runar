import { describe, it, expect } from 'vitest';
import { runDifferentialExecution } from '../oracle/index.js';

// A pure-arithmetic stateless contract: verify(a, b) asserts a + b === target.
const SRC = `
import { SmartContract, assert } from 'runar-lang';

export class Sum extends SmartContract {
  readonly target: bigint;
  constructor(target: bigint) { super(target); this.target = target; }
  public verify(a: bigint, b: bigint): void {
    assert(a + b === this.target);
  }
}
`;

describe('runDifferentialExecution', () => {
  it('agrees ACCEPT: interpreter and BSV engine both accept the valid witness', () => {
    const r = runDifferentialExecution({
      source: SRC,
      fileName: 'Sum.runar.ts',
      method: 'verify',
      args: [3n, 7n],
      constructorArgs: { target: 10n },
    });
    expect(r.interpreterAccepted).toBe(true);
    expect(r.vmAccepted).toBe(true);
    expect(r.agrees).toBe(true);
  });

  it('agrees REJECT: both reject a witness that violates the assert', () => {
    const r = runDifferentialExecution({
      source: SRC,
      fileName: 'Sum.runar.ts',
      method: 'verify',
      args: [3n, 8n],
      constructorArgs: { target: 10n },
    });
    expect(r.interpreterAccepted).toBe(false);
    expect(r.vmAccepted).toBe(false);
    expect(r.agrees).toBe(true);
  });
});
