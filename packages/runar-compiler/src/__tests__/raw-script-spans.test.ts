/**
 * Phase 4 emit-side tests for `rawScriptSpans` artifact metadata.
 *
 * Whenever the emitter writes a `raw_bytes` StackOp (produced by lowering a
 * `raw_script` ANF node, which in turn comes from a source-level
 * `asm({...})` call), it records the span's byte offset, length, and
 * declared stack-effect arities into the artifact's `rawScriptSpans` field.
 *
 * The analyzer reads this field to skip the contents of each span — the
 * bytes are opaque and not guaranteed to form a well-formed opcode stream.
 * These tests pin down the contract between the compiler and the analyzer
 * so silent emit-side regressions (forgetting to record a span, mis-tracking
 * the offset, dropping `inArity` / `outArity`) surface immediately.
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

function compileSource(source: string) {
  return compile(source, { fileName: 'WithAsm.runar.ts' });
}

describe('rawScriptSpans — emit-side artifact metadata', () => {
  it('records a single span for a one-call asm() contract', () => {
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class WithAsm extends UnsafeSmartContract {
        constructor() {
          super();
        }

        public unlock() {
          asm({ body: '51', in_arity: 0, out_arity: 1 });
        }
      }
    `;
    const r = compileSource(source);
    expect(r.success).toBe(true);
    expect(r.artifact?.rawScriptSpans).toEqual([
      { offset: 0, length: 1, inArity: 0, outArity: 1 },
    ]);
  });

  it('records consecutive spans with monotonically increasing offsets', () => {
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class WithAsm extends UnsafeSmartContract {
        constructor() {
          super();
        }

        public unlock() {
          asm({ body: '51', in_arity: 0, out_arity: 1 });
          asm({ body: '6151', in_arity: 1, out_arity: 1 });
        }
      }
    `;
    const r = compileSource(source);
    expect(r.success).toBe(true);
    expect(r.artifact?.rawScriptSpans).toEqual([
      { offset: 0, length: 1, inArity: 0, outArity: 1 },
      { offset: 1, length: 2, inArity: 1, outArity: 1 },
    ]);
    // Sanity: the recorded offsets cover the emitted hex exactly.
    expect(r.scriptHex).toBe('516151');
  });

  it('carries non-default arities through to the artifact', () => {
    // in_arity = 2 is the part this test pins. Two method params supply the
    // two stack items the stack-lowering pass expects (the validator checks
    // declared arity against static stack depth at the asm call site). The
    // body is OP_EQUAL (0x87) which pops 2 and pushes 1, satisfying
    // out_arity 1. The byte itself isn't important — only that the declared
    // arities round-trip through the artifact unchanged.
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class WithAsm extends UnsafeSmartContract {
        constructor() {
          super();
        }

        public unlock(a: bigint, b: bigint) {
          asm({ body: '87', in_arity: 2, out_arity: 1 });
        }
      }
    `;
    const r = compileSource(source);
    expect(r.success).toBe(true);
    expect(r.artifact?.rawScriptSpans).toEqual([
      { offset: 0, length: 1, inArity: 2, outArity: 1 },
    ]);
  });

  it('omits `rawScriptSpans` entirely for contracts that use no asm()', () => {
    // Regression guard: an ordinary SmartContract must not gain an empty
    // `rawScriptSpans` array — the field is optional and absent by default
    // so the artifact JSON stays minimal across the 7-tier conformance suite.
    const source = `
      import { SmartContract, assert } from 'runar-lang';

      class Always extends SmartContract {
        constructor() { super(); }
        public unlock(): void {
          assert(1n === 1n);
        }
      }
    `;
    const r = compile(source, { fileName: 'Always.runar.ts' });
    expect(r.success).toBe(true);
    expect(r.artifact?.rawScriptSpans).toBeUndefined();
  });

  it('records a span at the correct offset inside a multi-byte body', () => {
    // body of 4 bytes — the recorded length must match exactly. This
    // catches off-by-one mistakes in the offset bookkeeping. The validator
    // requires out_arity 1 on the terminal call, so we wrap the
    // 4-byte body that way.
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class WithAsm extends UnsafeSmartContract {
        constructor() {
          super();
        }

        public unlock() {
          asm({ body: '76a90051', in_arity: 0, out_arity: 1 });
        }
      }
    `;
    const r = compileSource(source);
    expect(r.success).toBe(true);
    expect(r.artifact?.rawScriptSpans).toEqual([
      { offset: 0, length: 4, inArity: 0, outArity: 1 },
    ]);
    expect(r.scriptHex).toBe('76a90051');
  });
});
