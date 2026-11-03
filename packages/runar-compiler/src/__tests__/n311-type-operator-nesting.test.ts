import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { InputLimits } from 'runar-ir-schema';

/**
 * N-311 — measure (A) of MAX_SOURCE_NESTING counts intersection / union type
 * nesting (user decision R117).
 *
 * Measure (A) used to count nested type ARGUMENTS but not type OPERATORS, so a
 * `.runar.ts` annotation nesting `&` / `|` to any depth passed the limit. The Go
 * tier's tree-sitter grammar builds even `&&&…&Int` as a valid right-nested
 * intersection_type chain, and its measure-(A) walk followed all of it (about
 * 208 MB of Go heap at 256k levels). The rule now adds +1 per operand of an
 * intersection or union type, so a type operator nested inside another counts
 * one level, and the operands of one flat `A & B & C` list share a level.
 *
 * Shape: `let q: (bigint & (bigint & … bigint)) = a;` with n parenthesised
 * levels. The declaration statement is level 1 and each operator level adds
 * one, so the innermost operand sits at level n + 1: n = 127 is within (A),
 * n = 128 is one past.
 *
 * Proves, for the TS reference: n = 127 is refused for the unsupported type but
 * NOT with the nesting diagnostic, n = 128 is refused with it (for `&`, `|`
 * and an alternation of both), a 20 000-level annotation is refused with it,
 * and a flat 500-operand intersection is not (its operands share one level).
 * Does not prove: anything about the other six tiers
 * (conformance/negatives/n311-type-operator-nesting-parity.test.ts drives all
 * seven CLIs), nor that no tier accepts such a type — none does; no Rúnar type
 * is an intersection or union, so "within (A)" never means "compiles".
 */

const L = InputLimits.MAX_SOURCE_NESTING;
const DIAG = `source nesting depth exceeds MAX_SOURCE_NESTING (limit=${L})`;

const HEAD = "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n public verify(a: bigint, b: bigint) {\n let q: {T} = a;\n assert(q == this.t);\n }\n}\n";

/** n parenthesised levels; `ops` cycles per level. */
function nested(n: number, ops: string[]): string {
  let open = '';
  for (let i = 0; i < n; i++) open += `(bigint ${ops[i % ops.length]} `;
  return HEAD.replace('{T}', open + 'bigint' + ')'.repeat(n));
}

function messages(src: string): string[] {
  const r = compile(src, { fileName: 'P.runar.ts' });
  expect(r.success).toBe(false);
  return r.diagnostics.map((d) => d.message);
}

describe('N-311: measure (A) counts intersection / union type nesting', () => {
  for (const [name, ops] of [['&', ['&']], ['|', ['|']], ['& |', ['&', '|']]] as const) {
    it(`${name}: n=${L - 1} is refused for the type, not for nesting`, () => {
      const msgs = messages(nested(L - 1, [...ops]));
      expect(msgs).not.toContain(DIAG);
    });

    it(`${name}: n=${L} (one past) is refused with the shared diagnostic`, () => {
      expect(messages(nested(L, [...ops]))).toContain(DIAG);
    });
  }

  it('a 20 000-level intersection is refused with the shared diagnostic, no RangeError', () => {
    const msgs = messages(nested(20000, ['&']));
    expect(msgs).toContain(DIAG);
    expect(msgs.join('\n')).not.toMatch(/call stack/i);
  });

  it('a flat 500-operand intersection is one level, not 500', () => {
    const msgs = messages(HEAD.replace('{T}', Array(500).fill('bigint').join(' & ')));
    expect(msgs).not.toContain(DIAG);
  });
});
