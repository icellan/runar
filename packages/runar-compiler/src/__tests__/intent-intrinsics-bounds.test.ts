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
          // 2000 > 1000 bound — should be rejected at typecheck.
          requireOutputP2PKH(2000n, this.pkh, this.a);
        }
      }
    `;
    expectErrorContains(typecheckSource(source), 'bound to <= 1000');
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
