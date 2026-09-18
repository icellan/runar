// ---------------------------------------------------------------------------
// R-2 / R-4 — typecheck bounds for intent sub-covenant intrinsics.
// Mirrors compilers/go/frontend/intent_intrinsics_test.go:
//   TestRequireOutputP2PKH_OutputIndexBound_Rejects
//   TestRequireOutputP2PKH_NegativeIndex_Rejects
//   TestExtractPrevOutputScript_PrefixLenTooSmall_Rejects
//   TestExtractPrevOutputScript_PrefixLenTooLarge_Rejects
// ---------------------------------------------------------------------------

import { describe, it } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { typecheck } from '../passes/03-typecheck.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import type { TypeCheckResult } from '../passes/03-typecheck.js';
import type { ContractNode } from '../ir/index.js';

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

function expectErrorContains(result: TypeCheckResult, substr: string): void {
  const matched = result.errors.find(e => e.message.includes(substr));
  if (!matched) {
    throw new Error(
      `expected typecheck error containing "${substr}", got: ${result.errors.map(e => e.message).join(' | ')}`,
    );
  }
}

describe('R-2 / R-4 intent intrinsic bounds', () => {
  it('requireOutputP2PKH() rejects outputIndex > 1000', () => {
    const source = `
      class Cov extends StatefulSmartContract {
        readonly pkh: ByteString;
        readonly a: bigint;

        constructor(pkh: ByteString, a: bigint) {
          super(pkh, a);
          this.pkh = pkh;
          this.a = a;
        }

        public pay() {
          // W2: any literal index above 0 is rejected at typecheck. 2000 was
          // chosen when the bound was <= 1000 and still exercises it.
          requireOutputP2PKH(2000n, this.pkh, this.a);
        }
      }
    `;
    expectErrorContains(typecheckSource(source), 'must be 0 in v1');
  });

  it('requireOutputP2PKH() rejects negative index', () => {
    const source = `
      class Cov extends StatefulSmartContract {
        readonly pkh: ByteString;
        readonly a: bigint;

        constructor(pkh: ByteString, a: bigint) {
          super(pkh, a);
          this.pkh = pkh;
          this.a = a;
        }

        public pay() {
          requireOutputP2PKH(-1n, this.pkh, this.a);
        }
      }
    `;
    expectErrorContains(typecheckSource(source), 'must be >= 0');
  });

  it('extractPrevOutputScript() rejects prefixLen < 32', () => {
    const source = `
      class Cov extends StatefulSmartContract {
        readonly h: ByteString;

        constructor(h: ByteString) {
          super(h);
          this.h = h;
        }

        public bind() {
          // prefixLen=16 < 32 (hash size) — should be rejected.
          const s = extractPrevOutputScript(0n, this.h, 16n);
          assert(len(s) > 0n);
        }
      }
    `;
    expectErrorContains(typecheckSource(source), 'must be >= 32');
  });

  it('extractPrevOutputScript() rejects prefixLen > 4 MiB', () => {
    const source = `
      class Cov extends StatefulSmartContract {
        readonly h: ByteString;

        constructor(h: ByteString) {
          super(h);
          this.h = h;
        }

        public bind() {
          // prefixLen=10485760 > 4 MiB — should be rejected.
          const s = extractPrevOutputScript(0n, this.h, 10485760n);
          assert(len(s) > 0n);
        }
      }
    `;
    expectErrorContains(typecheckSource(source), 'MAX_SCRIPT_BYTES');
  });
});

// ---------------------------------------------------------------------------
// N-060 — a `-0n` index evades the literal gate and silently DELETES the
// covenant.
//
// The index gate above accepts `UnaryExpr{'-', BigIntLiteral}` only so that a
// negative index reports "must be >= 0" instead of the misleading "must be an
// integer literal". `-0n` negates to `0n`, so it passes that bound check — but
// ANF lowering matches on a bare `bigint_literal` and, finding a `unary_expr`,
// falls through to `load_const ''`: no witness param, no hash assertion, NO
// COVENANT, and no diagnostic. A contract whose whole purpose is the covenant
// compiles to a script that does not carry it.
//
// Mirrors compilers/rust/tests/intent_intrinsics_bounds.rs (R-068).
// ---------------------------------------------------------------------------

const EPS_NEG_ZERO_SRC = `
      class Cov extends StatefulSmartContract {
        readonly h: ByteString;
        count: bigint;

        constructor(h: ByteString, count: bigint) {
          super(h, count);
          this.h = h;
          this.count = count;
        }

        public bind() {
          const s = extractPrevOutputScript(-0n, this.h);
          assert(len(s) > 0n);
          this.count = this.count + 1n;
        }
      }
    `;

const ROP_NEG_ZERO_SRC = `
      class Cov extends StatefulSmartContract {
        readonly pkh: ByteString;
        readonly amt: bigint;
        count: bigint;

        constructor(pkh: ByteString, amt: bigint, count: bigint) {
          super(pkh, amt, count);
          this.pkh = pkh;
          this.amt = amt;
          this.count = count;
        }

        public pay() {
          requireOutputP2PKH(-0n, this.pkh, this.amt);
          this.count = this.count + 1n;
        }
      }
    `;

function anfJson(source: string): string {
  const contract = parseContract(source, 'Test.runar.ts');
  const program = lowerToANF(contract);
  return JSON.stringify(program, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
}

describe('N-060 negative-zero intent intrinsic index', () => {
  it('extractPrevOutputScript() rejects a -0n index', () => {
    expectErrorContains(typecheckSource(EPS_NEG_ZERO_SRC, 'Test.runar.ts'), 'must be an integer literal');
  });

  it('requireOutputP2PKH() rejects a -0n index', () => {
    expectErrorContains(typecheckSource(ROP_NEG_ZERO_SRC, 'Test.runar.ts'), 'must be an integer literal');
  });

  // The funds-safety half of the pair: a `-0n` index must never reach codegen,
  // because when it does the intrinsic lowers to a bare empty-string constant
  // and the covenant it was supposed to install is simply absent.
  it('a -0n index never silently drops the covenant', () => {
    for (const [label, src] of [
      ['extractPrevOutputScript', EPS_NEG_ZERO_SRC],
      ['requireOutputP2PKH', ROP_NEG_ZERO_SRC],
    ] as const) {
      const result = typecheckSource(src, 'Test.runar.ts');
      if (result.errors.length > 0) continue;
      const json = anfJson(src);
      throw new Error(
        `${label}(-0n, ...) compiled with NO diagnostic; covenant markers present: ` +
          `_prevOutScript_=${json.includes('_prevOutScript_')} ` +
          `_serialisedOutputs=${json.includes('_serialisedOutputs')}`,
      );
    }
  });

  // Controls — the valid forms must keep lowering exactly as before.

  it('CONTROL: a literal 0n index still installs the covenant', () => {
    const eps = EPS_NEG_ZERO_SRC.replace('extractPrevOutputScript(-0n,', 'extractPrevOutputScript(0n,');
    if (!anfJson(eps).includes('_prevOutScript_0')) {
      throw new Error('extractPrevOutputScript(0n, ...) must still auto-inject its witness param');
    }
    // W2: the only index this intrinsic accepts is 0, so the control uses it.
    const rop = ROP_NEG_ZERO_SRC.replace('requireOutputP2PKH(-0n,', 'requireOutputP2PKH(0n,');
    if (!anfJson(rop).includes('_serialisedOutputs')) {
      throw new Error('requireOutputP2PKH(0n, ...) must still auto-inject _serialisedOutputs');
    }
  });

  it('CONTROL: a plain negative index still reports the bound message', () => {
    const src = EPS_NEG_ZERO_SRC.replace('extractPrevOutputScript(-0n,', 'extractPrevOutputScript(-3n,');
    expectErrorContains(typecheckSource(src, 'Test.runar.ts'), 'must be >= 0');
  });
});
