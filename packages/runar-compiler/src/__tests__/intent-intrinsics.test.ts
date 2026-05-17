// ---------------------------------------------------------------------------
// Intent sub-covenant intrinsics (BSVM Phase 13) — TS-tier port.
// Mirrors compilers/go/frontend/intent_intrinsics_test.go.
// Pure frontend sugar: typecheck signatures + ANF auto-injection. No new
// ANF kinds, no stack-IR codegen changes.
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { typecheck } from '../passes/03-typecheck.js';
import type { TypeCheckResult } from '../passes/03-typecheck.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import type { ContractNode } from '../ir/index.js';
import type { ANFMethod, ANFProgram } from '../ir/index.js';

function parseContract(source: string, fileName?: string): ContractNode {
  const result = parse(source, fileName);
  if (!result.contract) {
    throw new Error(`Parse failed: ${result.errors.map(e => e.message).join(', ')}`);
  }
  return result.contract;
}

function typecheckSource(source: string, fileName?: string): TypeCheckResult {
  return typecheck(parseContract(source, fileName));
}

function lowerSource(source: string, fileName?: string): ANFProgram {
  return lowerToANF(parseContract(source, fileName));
}

function findMethod(program: ANFProgram, name: string): ANFMethod {
  const m = program.methods.find(x => x.name === name);
  if (!m) throw new Error(`method ${name} not found in ${program.methods.map(x => x.name).join(', ')}`);
  return m;
}

function paramNamesOf(m: ANFMethod): string[] {
  return m.params.map(p => p.name);
}

function expectErrorContains(result: TypeCheckResult, substr: string): void {
  const matched = result.errors.find(e => e.message.includes(substr));
  if (!matched) {
    throw new Error(
      `expected typecheck error containing "${substr}", got: ${result.errors.map(e => e.message).join(' | ')}`,
    );
  }
}

// ---------------------------------------------------------------------------
// extractPrevOutputScript
// ---------------------------------------------------------------------------

describe('extractPrevOutputScript', () => {
  it('auto-injects _prevOutScript_<idx> witness param', () => {
    const source = `
      class IntentCov extends StatefulSmartContract {
        readonly stateCovScriptHash: ByteString;

        constructor(stateCovScriptHash: ByteString) {
          super(stateCovScriptHash);
          this.stateCovScriptHash = stateCovScriptHash;
        }

        public coSpend() {
          const s = extractPrevOutputScript(0n, this.stateCovScriptHash);
          assert(len(s) > 0n);
        }
      }
    `;
    const p = lowerSource(source);
    const m = findMethod(p, 'coSpend');
    const names = paramNamesOf(m);
    expect(names).toContain('_prevOutScript_0');
    expect(names).toContain('txPreimage');
  });

  it('produces two params for two distinct literal indices', () => {
    const source = `
      class IntentCov extends StatefulSmartContract {
        readonly h0: ByteString;
        readonly h1: ByteString;

        constructor(h0: ByteString, h1: ByteString) {
          super(h0, h1);
          this.h0 = h0;
          this.h1 = h1;
        }

        public coSpend() {
          const a = extractPrevOutputScript(0n, this.h0);
          const b = extractPrevOutputScript(1n, this.h1);
          assert(len(a) > 0n);
          assert(len(b) > 0n);
        }
      }
    `;
    const p = lowerSource(source);
    const names = paramNamesOf(findMethod(p, 'coSpend'));
    expect(names).toContain('_prevOutScript_0');
    expect(names).toContain('_prevOutScript_1');
  });

  it('is idempotent for repeated identical indices (single param)', () => {
    const source = `
      class IntentCov extends StatefulSmartContract {
        readonly h0: ByteString;

        constructor(h0: ByteString) {
          super(h0);
          this.h0 = h0;
        }

        public coSpend() {
          const a = extractPrevOutputScript(0n, this.h0);
          const b = extractPrevOutputScript(0n, this.h0);
          assert(len(a) > 0n);
          assert(len(b) > 0n);
        }
      }
    `;
    const m = findMethod(lowerSource(source), 'coSpend');
    const count = m.params.filter(p => p.name === '_prevOutScript_0').length;
    expect(count).toBe(1);
  });

  it('rejects a non-literal index at typecheck', () => {
    const source = `
      class IntentCov extends StatefulSmartContract {
        readonly h0: ByteString;

        constructor(h0: ByteString) {
          super(h0);
          this.h0 = h0;
        }

        public coSpend(idx: bigint) {
          const s = extractPrevOutputScript(idx, this.h0);
          assert(len(s) > 0n);
        }
      }
    `;
    expectErrorContains(typecheckSource(source), 'must be an integer literal');
  });
});

// ---------------------------------------------------------------------------
// requireOutputP2PKH
// ---------------------------------------------------------------------------

describe('requireOutputP2PKH', () => {
  it('auto-injects _serialisedOutputs param', () => {
    const source = `
      class Cov extends StatefulSmartContract {
        readonly bondPKH: ByteString;
        readonly bond: bigint;

        constructor(bondPKH: ByteString, bond: bigint) {
          super(bondPKH, bond);
          this.bondPKH = bondPKH;
          this.bond = bond;
        }

        public payBond() {
          requireOutputP2PKH(0n, this.bondPKH, this.bond);
        }
      }
    `;
    const names = paramNamesOf(findMethod(lowerSource(source), 'payBond'));
    expect(names).toContain('_serialisedOutputs');
  });

  it('emits exactly one _serialisedOutputs param across multiple calls', () => {
    const source = `
      class Cov extends StatefulSmartContract {
        readonly bondPKH: ByteString;
        readonly bond: bigint;

        constructor(bondPKH: ByteString, bond: bigint) {
          super(bondPKH, bond);
          this.bondPKH = bondPKH;
          this.bond = bond;
        }

        public payMulti() {
          requireOutputP2PKH(0n, this.bondPKH, this.bond);
          requireOutputP2PKH(1n, this.bondPKH, this.bond);
        }
      }
    `;
    const m = findMethod(lowerSource(source), 'payMulti');
    const count = m.params.filter(p => p.name === '_serialisedOutputs').length;
    expect(count).toBe(1);
  });

  it('emits the hashOutputs check exactly once per method body', () => {
    // Two calls should produce only one hash256 -> extractOutputHash ===
    // assert sequence (the idempotent intro check), plus two per-call
    // substring assertions. We count the bin_op '===' nodes whose left
    // operand traces back to a hash256(_serialisedOutputs) — one intro
    // plus two substring extracts = 3.
    const source = `
      class Cov extends StatefulSmartContract {
        readonly bondPKH: ByteString;
        readonly bond: bigint;

        constructor(bondPKH: ByteString, bond: bigint) {
          super(bondPKH, bond);
          this.bondPKH = bondPKH;
          this.bond = bond;
        }

        public payMulti() {
          requireOutputP2PKH(0n, this.bondPKH, this.bond);
          requireOutputP2PKH(1n, this.bondPKH, this.bond);
        }
      }
    `;
    const m = findMethod(lowerSource(source), 'payMulti');
    // Count extractOutputHash calls — should be exactly the one from the
    // idempotent hashOutputs intro plus one in the auto-injected state
    // continuation. Without idempotency we'd get 3+.
    const extractOutputHashCalls = m.body.filter(
      b => b.value.kind === 'call' && b.value.func === 'extractOutputHash',
    ).length;
    expect(extractOutputHashCalls).toBeLessThanOrEqual(2);
  });

  it('rejects a non-literal index at typecheck', () => {
    const source = `
      class Cov extends StatefulSmartContract {
        readonly bondPKH: ByteString;
        readonly bond: bigint;

        constructor(bondPKH: ByteString, bond: bigint) {
          super(bondPKH, bond);
          this.bondPKH = bondPKH;
          this.bond = bond;
        }

        public payBond(idx: bigint) {
          requireOutputP2PKH(idx, this.bondPKH, this.bond);
        }
      }
    `;
    expectErrorContains(typecheckSource(source), 'must be an integer literal');
  });

  it('rejects use in a stateless SmartContract', () => {
    const source = `
      class Sl extends SmartContract {
        readonly bondPKH: ByteString;
        readonly bond: bigint;

        constructor(bondPKH: ByteString, bond: bigint) {
          super(bondPKH, bond);
          this.bondPKH = bondPKH;
          this.bond = bond;
        }

        public payBond() {
          requireOutputP2PKH(0n, this.bondPKH, this.bond);
        }
      }
    `;
    expectErrorContains(typecheckSource(source), 'StatefulSmartContract');
  });
});

// ---------------------------------------------------------------------------
// currentBlockHeight
// ---------------------------------------------------------------------------

describe('currentBlockHeight', () => {
  it('desugars to extractLocktime(txPreimage)', () => {
    const source = `
      class Cov extends StatefulSmartContract {
        readonly deadline: bigint;

        constructor(deadline: bigint) {
          super(deadline);
          this.deadline = deadline;
        }

        public spend() {
          const h = currentBlockHeight();
          assert(h <= this.deadline);
        }
      }
    `;
    const m = findMethod(lowerSource(source), 'spend');
    const sawExtractLocktime = m.body.some(
      b => b.value.kind === 'call' && b.value.func === 'extractLocktime',
    );
    expect(sawExtractLocktime).toBe(true);
  });

  it('rejects use in a stateless SmartContract', () => {
    const source = `
      class Sl extends SmartContract {
        readonly deadline: bigint;

        constructor(deadline: bigint) {
          super(deadline);
          this.deadline = deadline;
        }

        public spend() {
          const h = currentBlockHeight();
          assert(h > this.deadline);
        }
      }
    `;
    expectErrorContains(typecheckSource(source), 'StatefulSmartContract');
  });
});

// ---------------------------------------------------------------------------
// Crit-2 — extractPrevOutputScript prefix-hash 3-arg form
// ---------------------------------------------------------------------------

describe('extractPrevOutputScript prefix-hash form (Crit-2)', () => {
  it('lowers the 3-arg form with substr(witness, 0, prefixLen)', () => {
    const source = `
      class IntentTemplate extends StatefulSmartContract {
        readonly expectedPolicyPrefixHash: ByteString;

        constructor(expectedPolicyPrefixHash: ByteString) {
          super(expectedPolicyPrefixHash);
          this.expectedPolicyPrefixHash = expectedPolicyPrefixHash;
        }

        public bind() {
          const s = extractPrevOutputScript(0n, this.expectedPolicyPrefixHash, 600n);
          assert(len(s) > 0n);
        }
      }
    `;
    const p = lowerSource(source);
    const m = findMethod(p, 'bind');

    // Locate a substr call whose first arg traces back to load_param(_prevOutScript_0).
    // That distinguishes the auto-injected prefix substr from any other
    // user-level substr emitted in the body.
    let sawPrefixSubstr = false;
    for (let i = 0; i < m.body.length; i++) {
      const b = m.body[i]!;
      if (b.value.kind === 'call' && b.value.func === 'substr' && b.value.args.length === 3) {
        const ref = b.value.args[0]!;
        for (let j = 0; j < i; j++) {
          const cand = m.body[j]!;
          if (
            cand.name === ref &&
            cand.value.kind === 'load_param' &&
            cand.value.name === '_prevOutScript_0'
          ) {
            sawPrefixSubstr = true;
            break;
          }
        }
        if (sawPrefixSubstr) break;
      }
    }
    expect(sawPrefixSubstr).toBe(true);
  });

  it('rejects a non-literal prefixLen at typecheck', () => {
    const source = `
      class Cov extends StatefulSmartContract {
        readonly h: ByteString;

        constructor(h: ByteString) {
          super(h);
          this.h = h;
        }

        public bind(n: bigint) {
          const s = extractPrevOutputScript(0n, this.h, n);
          assert(len(s) > 0n);
        }
      }
    `;
    expectErrorContains(
      typecheckSource(source),
      'prefixLen) must be an integer literal',
    );
  });

  it('rejects a 4-arg call (too many arguments)', () => {
    const source = `
      class Cov extends StatefulSmartContract {
        readonly h: ByteString;

        constructor(h: ByteString) {
          super(h);
          this.h = h;
        }

        public bind() {
          const s = extractPrevOutputScript(0n, this.h, 600n, 999n);
          assert(len(s) > 0n);
        }
      }
    `;
    expectErrorContains(typecheckSource(source), 'expects 2 or 3 arguments');
  });
});

// ---------------------------------------------------------------------------
// Crit-3 — reject requireOutputP2PKH + addDataOutput mix in same method
// ---------------------------------------------------------------------------

describe('requireOutputP2PKH + addDataOutput mix (Crit-3)', () => {
  it('rejects a method that mixes requireOutputP2PKH() with this.addDataOutput()', () => {
    const source = `
      class Cov extends StatefulSmartContract {
        readonly bondPKH: ByteString;
        readonly bond: bigint;
        readonly tag: ByteString;

        constructor(bondPKH: ByteString, bond: bigint, tag: ByteString) {
          super(bondPKH, bond, tag);
          this.bondPKH = bondPKH;
          this.bond = bond;
          this.tag = tag;
        }

        public payBondAndAnnounce() {
          this.addDataOutput(0n, this.tag);
          requireOutputP2PKH(0n, this.bondPKH, this.bond);
        }
      }
    `;
    expectErrorContains(
      typecheckSource(source),
      'mixes requireOutputP2PKH() with addDataOutput()',
    );
  });

  it('accepts requireOutputP2PKH() in a method that has no addDataOutput()', () => {
    const source = `
      class Cov extends StatefulSmartContract {
        readonly bondPKH: ByteString;
        readonly bond: bigint;

        constructor(bondPKH: ByteString, bond: bigint) {
          super(bondPKH, bond);
          this.bondPKH = bondPKH;
          this.bond = bond;
        }

        public payBond() {
          requireOutputP2PKH(0n, this.bondPKH, this.bond);
        }
      }
    `;
    const result = typecheckSource(source);
    const mixErr = result.errors.find(e =>
      e.message.includes('mixes requireOutputP2PKH() with addDataOutput()'),
    );
    expect(mixErr).toBeUndefined();
  });
});
