/**
 * F-024 (R14) — TestContract evaluates `continuationAmount()`.
 *
 * What this proves: the AST interpreter behind TestContract answers
 * `continuationAmount()` with the value set by `setContinuationAmount`, and
 * defaults to the mock preimage's `amount` (the honest continuation), so an
 * author's stricter rule (`== input + bet`) can be unit-tested off-chain.
 * What this does NOT prove: anything on-chain. TestContract shares the
 * compiler's model; the drain / deposit verdicts come from @bsv/sdk Spend in
 * f024-stateful-value-drain.test.ts.
 */
import { describe, it, expect } from 'vitest';
import { TestContract } from '../test-contract.js';

const POT = `
class Pot extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public join(bet: bigint) {
    assert(continuationAmount() == extractAmount(this.txPreimage) + bet);
    this.count = this.count + 1n;
  }
  public bump() {
    assert(continuationAmount() == extractAmount(this.txPreimage));
    this.count = this.count + 1n;
  }
}
`;

describe('F-024 TestContract continuationAmount()', () => {
  it('defaults to the mock input amount (an honest continuation)', () => {
    const c = TestContract.fromSource(POT, { count: 0n });
    c.setMockPreimage({ amount: 1_000n });
    expect(c.call('bump').success).toBe(true);
    expect(c.state.count).toBe(1n);
  });

  it('reads the value set by setContinuationAmount, so a stricter author rule is testable', () => {
    const c = TestContract.fromSource(POT, { count: 0n });
    c.setMockPreimage({ amount: 1_000n });
    c.setContinuationAmount(1_500n);
    expect(c.call('join', { bet: 500n }).success).toBe(true);
    expect(c.call('join', { bet: 400n }).success).toBe(false);
    c.setContinuationAmount(undefined);
    expect(c.call('join', { bet: 0n }).success).toBe(true);
  });
});
