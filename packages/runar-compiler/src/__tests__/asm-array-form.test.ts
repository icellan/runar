/**
 * Phase-3 follow-up tests for the array-form `asm({ body: [...] })`
 * surface syntax. Each test compiles a contract whose `asm()` call uses
 * an array body and verifies that the emitted hex is byte-identical
 * to the equivalent hex-string body.
 *
 * The array body is encoded at parse time using the same push-data /
 * script-number encoders the emit pass uses, so the resulting IR
 * shape (raw_script ANF node + raw_bytes StackOp) is identical to
 * the hex-string form. Downstream passes (validate, typecheck, ANF
 * lower, stack lower, peephole, emit) never see the array form.
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

function compileSource(source: string) {
  return compile(source, { fileName: 'Anyone.runar.ts' });
}

describe('asm({...}) array-form body', () => {
  it('encodes [OP_TRUE] byte-identical to the hex-string form "51"', () => {
    const arraySource = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class ArrayForm extends UnsafeSmartContract {
        constructor() { super(); }

        public unlock() {
          asm({ body: [OP_TRUE], in_arity: 0, out_arity: 1 });
        }
      }
    `;
    const stringSource = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class StringForm extends UnsafeSmartContract {
        constructor() { super(); }

        public unlock() {
          asm({ body: '51', in_arity: 0, out_arity: 1 });
        }
      }
    `;
    const arr = compileSource(arraySource);
    const str = compileSource(stringSource);
    expect(arr.success).toBe(true);
    expect(str.success).toBe(true);
    expect(arr.scriptHex).toBe(str.scriptHex);
    expect(arr.scriptHex).toBe('51');
  });

  it('encodes [OP_DUP, OP_HASH160, push("1234abcd"), OP_EQUALVERIFY] with correct 4-byte push prefix', () => {
    // OP_DUP=0x76, OP_HASH160=0xa9, push 4 bytes => length-prefix 0x04 + payload,
    // OP_EQUALVERIFY=0x88. Expected body hex: 76a9 04 1234abcd 88.
    // We push a dummy bytestring onto the stack first so the asm() body
    // has its required in_arity=1 input, and end with a terminal asm
    // leaving OP_1 so the script returns truthy.
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class P2PKHLike extends UnsafeSmartContract {
        constructor() { super(); }

        public unlock() {
          asm({ body: [push('1234abcd')], in_arity: 0, out_arity: 1 });
          asm({ body: [OP_DUP, OP_HASH160, push('1234abcd'), OP_EQUALVERIFY], in_arity: 1, out_arity: 0 });
          asm({ body: '51', in_arity: 0, out_arity: 1 });
        }
      }
    `;
    const result = compileSource(source);
    if (!result.success) {
      // eslint-disable-next-line no-console
      console.error('compile failed', result.diagnostics);
    }
    expect(result.success).toBe(true);
    // The full emitted script is: push-prelude + p2pkh-template + terminal-OP_1
    // Prelude push: 04 1234abcd (5 bytes)
    // P2PKH-like template: 76 a9 04 1234abcd 88 (8 bytes)
    // Terminal: 51 (1 byte)
    // Total: 041234abcd76a9041234abcd8851
    expect(result.scriptHex).toBe('041234abcd76a9041234abcd8851');
  });

  it('encodes push(42n) as a length-prefixed script-number push (not a small-int opcode)', () => {
    // 42 doesn't fit OP_1..OP_16, so emit `0x01 0x2a` (push 1 byte 0x2a).
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class Push42 extends UnsafeSmartContract {
        constructor() { super(); }

        public unlock() {
          asm({ body: [push(42n)], in_arity: 0, out_arity: 1 });
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(true);
    expect(result.scriptHex).toBe('012a');
  });

  it('encodes push(3n) using the small-int opcode OP_3 (0x53)', () => {
    // 1..16 must use OP_1..OP_16 — MINIMALDATA rule.
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class Push3 extends UnsafeSmartContract {
        constructor() { super(); }

        public unlock() {
          asm({ body: [push(3n)], in_arity: 0, out_arity: 1 });
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(true);
    expect(result.scriptHex).toBe('53');
  });

  it('rejects an unknown opcode identifier with a clear diagnostic', () => {
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class BadOp extends UnsafeSmartContract {
        constructor() { super(); }

        public unlock() {
          asm({ body: [OP_FAKE], in_arity: 0, out_arity: 1 });
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(false);
    const messages = result.diagnostics.map(d => d.message).join('\n');
    expect(messages).toMatch(/unknown opcode.*OP_FAKE/i);
  });

  it('rejects push() with no arguments with a clear diagnostic', () => {
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class BadPush extends UnsafeSmartContract {
        constructor() { super(); }

        public unlock() {
          asm({ body: [push()], in_arity: 0, out_arity: 1 });
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(false);
    const messages = result.diagnostics.map(d => d.message).join('\n');
    expect(messages).toMatch(/push\(\).*one literal argument/i);
  });

  it('emits both string-form and array-form asm in the same method as raw_script ANF nodes', () => {
    // Sanity: two asm calls (one string, one array) in one method emit
    // their bytes in source order and both end up as raw_script nodes
    // (we check that via rawScriptSpans length on the artifact).
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class Mixed extends UnsafeSmartContract {
        constructor() { super(); }

        public unlock() {
          asm({ body: '61', in_arity: 0, out_arity: 0 });
          asm({ body: [OP_TRUE], in_arity: 0, out_arity: 1 });
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(true);
    // OP_NOP (0x61) then OP_TRUE (0x51).
    expect(result.scriptHex).toBe('6151');
    // Each asm() call produces one raw_script ANF binding, which maps
    // to one entry in rawScriptSpans on the assembled artifact.
    const spans = result.artifact?.rawScriptSpans ?? [];
    expect(spans.length).toBe(2);
    expect(spans[0]!.length).toBe(1); // '61'
    expect(spans[1]!.length).toBe(1); // '51'
  });
});
