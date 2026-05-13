/**
 * Phase-3 follow-up tests for the generic expression-form
 * `asm<T>({...})` surface syntax.
 *
 * In the expression form the asm() return value flows into a let-binding:
 *
 *   const x: bigint = asm<bigint>({ body: '...', in_arity: 0, out_arity: 1 });
 *   assert(x === 0n);
 *
 * The compiler:
 *   1. Captures `T` at parse time and stashes it on the synthetic
 *      call_expr as `asmReturnType`.
 *   2. Typechecks the call as producing a value of type T (instead of
 *      `void`, which is what statement-form asm returns).
 *   3. Lowers it to a raw_script ANF binding whose result is consumed
 *      by the surrounding variable_decl.
 *   4. Rejects out_arity != 1 — only one stack value can flow into a
 *      single let-binding.
 *   5. Rejects non-primitive return types (only `bigint`, `boolean`,
 *      `ByteString` are allowed).
 *   6. Does NOT count expression-form asm as the method's terminator —
 *      the method must end with an explicit assert() or terminal
 *      statement-form asm.
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

function compileSource(source: string) {
  return compile(source, { fileName: 'Anyone.runar.ts' });
}

describe('asm<T>({...}) expression-form surface syntax', () => {
  it('binds an asm<bigint>() result into a const and uses it in a subsequent assert', () => {
    // `5152` = OP_1 OP_2. After running, top of stack = 2n. We bind that
    // to `x` and assert it equals 2n. The terminal assert provides the
    // method's truthy stack value.
    const source = `
      import { UnsafeSmartContract, asm, assert } from 'runar-lang';

      class ExprForm extends UnsafeSmartContract {
        constructor() { super(); }

        public unlock() {
          const x: bigint = asm<bigint>({ body: '5152', in_arity: 0, out_arity: 1 });
          assert(x === 2n);
        }
      }
    `;
    const result = compileSource(source);
    if (!result.success) {
      // eslint-disable-next-line no-console
      console.error('compile failed', result.diagnostics);
    }
    expect(result.success).toBe(true);
    // The artifact must carry exactly one rawScriptSpan covering the
    // asm body bytes 0x51 0x52 (2 bytes total).
    const spans = result.artifact?.rawScriptSpans ?? [];
    expect(spans.length).toBe(1);
    expect(spans[0]!.length).toBe(2);
    expect(spans[0]!.outArity).toBe(1);
  });

  it('rejects out_arity != 1 in expression form (out_arity 2 is invalid)', () => {
    const source = `
      import { UnsafeSmartContract, asm, assert } from 'runar-lang';

      class MultiOut extends UnsafeSmartContract {
        constructor() { super(); }

        public unlock() {
          const x: bigint = asm<bigint>({ body: '5152', in_arity: 0, out_arity: 2 });
          assert(x === 1n);
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(false);
    const messages = result.diagnostics.map(d => d.message).join('\n');
    expect(messages).toMatch(/out_arity\s+1/i);
    expect(messages).toMatch(/expression-form|bind|single/i);
  });

  it('rejects a non-primitive return type (FixedArray<bigint, 3>) in the generic argument', () => {
    const source = `
      import { UnsafeSmartContract, asm, assert, FixedArray } from 'runar-lang';

      class BadType extends UnsafeSmartContract {
        constructor() { super(); }

        public unlock() {
          const x: FixedArray<bigint, 3> = asm<FixedArray<bigint, 3>>({ body: '51', in_arity: 0, out_arity: 1 });
          assert(true);
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(false);
    const messages = result.diagnostics.map(d => d.message).join('\n');
    expect(messages).toMatch(/asm<T>.*bigint.*boolean.*ByteString/i);
  });

  it('does NOT trip the terminal-truthy rule for expression-form asm in mid-method position', () => {
    // The expression-form asm is mid-method; the terminal statement is
    // an explicit assert(). That should be accepted by the
    // UnsafeSmartContract terminator check.
    const source = `
      import { UnsafeSmartContract, asm, assert } from 'runar-lang';

      class MidMethod extends UnsafeSmartContract {
        constructor() { super(); }

        public unlock() {
          const a: bigint = asm<bigint>({ body: '51', in_arity: 0, out_arity: 1 });
          const b: bigint = asm<bigint>({ body: '52', in_arity: 0, out_arity: 1 });
          assert(a + b === 3n);
        }
      }
    `;
    const result = compileSource(source);
    if (!result.success) {
      // eslint-disable-next-line no-console
      console.error('compile failed', result.diagnostics);
    }
    expect(result.success).toBe(true);
  });

  it('still populates rawScriptSpans correctly when mixed expression-form and statement-form asm are present', () => {
    const source = `
      import { UnsafeSmartContract, asm, assert } from 'runar-lang';

      class Mixed extends UnsafeSmartContract {
        constructor() { super(); }

        public unlock() {
          const x: bigint = asm<bigint>({ body: '51', in_arity: 0, out_arity: 1 });
          assert(x === 1n);
          asm({ body: '52', in_arity: 0, out_arity: 1 });
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(true);
    const spans = result.artifact?.rawScriptSpans ?? [];
    // Two asm() calls -> two raw_script ANF nodes -> two emit spans.
    expect(spans.length).toBe(2);
    // First span (expression-form) is one byte ('51').
    expect(spans[0]!.length).toBe(1);
    // Second span (statement-form) is one byte ('52').
    expect(spans[1]!.length).toBe(1);
  });
});
