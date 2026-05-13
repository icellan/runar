/**
 * Phase 3 surface-syntax tests for the `asm({...})` compiler intrinsic.
 *
 * Covers:
 *   1. `extends UnsafeSmartContract` + `asm({ body: '51', ... })` compiles
 *      through the regular `compile()` entry point and re-emits exactly
 *      the body bytes (Phase 1 round-trip is the floor for what `asm`
 *      produces — Phase 3 just makes the syntax reachable from user code).
 *   2. `extends SmartContract` + asm() is rejected by the validator with
 *      the gating diagnostic, even when the call is otherwise well-formed.
 *   3. Body field is required and must be a string-literal hex value.
 *   4. Malformed hex (odd length, non-hex chars) is rejected at validate
 *      time even though the parser already validates ByteString literals.
 *   5. Two `asm({...})` calls compose to the byte-concatenation of their
 *      bodies — proves the `raw_script` ANF nodes compose without
 *      inter-binding fixup.
 *
 * Out of scope for v0 (Phase-3 follow-ups, NOT exercised here):
 *   - `const x: bigint = asm<bigint>({...})` expression form
 *   - `body: [OP_DUP, push(...)]` array-form bodies
 *   - multi-output (out_arity > 1) asm
 *   - automatic stack-effect inference
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

function compileSource(source: string) {
  return compile(source, { fileName: 'Anyone.runar.ts' });
}

describe('asm({...}) surface syntax — UnsafeSmartContract happy path', () => {
  it('compiles a minimal OP_1 contract through the regular pipeline', () => {
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class Anyone extends UnsafeSmartContract {
        constructor() {
          super();
        }

        public unlock() {
          asm({ body: '51', in_arity: 0, out_arity: 1 });
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(true);
    // The body of unlock is exactly the single OP_1 byte (no PUSH wrappers,
    // no constructor splices), so the emitted script is byte-identical.
    expect(result.scriptHex).toBe('51');
  });

  it('uses out_arity default of 1 when omitted', () => {
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class Anyone extends UnsafeSmartContract {
        constructor() {
          super();
        }

        public unlock() {
          asm({ body: '51' });
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(true);
    expect(result.scriptHex).toBe('51');
  });

  it('concatenates two asm calls into a single byte stream', () => {
    // Two terminal-truthy asms in sequence — emit byte-by-byte concat.
    // First asm leaves OP_1 (0x51) on the stack, second leaves OP_NOP+OP_1
    // (0x61, 0x51). We only care that the bytes concatenate; the script
    // semantics are the contract author's problem (that's the whole point
    // of UnsafeSmartContract).
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class TwoAsms extends UnsafeSmartContract {
        constructor() {
          super();
        }

        public unlock() {
          asm({ body: '61', in_arity: 0, out_arity: 0 });
          asm({ body: '51', in_arity: 0, out_arity: 1 });
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(true);
    expect(result.scriptHex).toBe('6151');
  });
});

describe('asm({...}) surface syntax — UnsafeSmartContract gating', () => {
  it('rejects asm() in a SmartContract', () => {
    const source = `
      import { SmartContract, asm, assert } from 'runar-lang';

      class Bad extends SmartContract {
        constructor() {
          super();
        }

        public unlock() {
          asm({ body: '51', in_arity: 0, out_arity: 1 });
          assert(true);
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(false);
    const messages = result.diagnostics.map(d => d.message).join('\n');
    expect(messages).toMatch(/asm.*only available in.*UnsafeSmartContract/i);
    // SmartContract is named explicitly so the user knows what to change.
    expect(messages).toMatch(/SmartContract/);
  });

  it('rejects asm() in a StatefulSmartContract', () => {
    const source = `
      import { StatefulSmartContract, asm } from 'runar-lang';

      class BadStateful extends StatefulSmartContract {
        count: bigint;

        constructor(count: bigint) {
          super(count);
          this.count = count;
        }

        public bump() {
          asm({ body: '51', in_arity: 0, out_arity: 1 });
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(false);
    const messages = result.diagnostics.map(d => d.message).join('\n');
    expect(messages).toMatch(/asm.*only available in.*UnsafeSmartContract/i);
    expect(messages).toMatch(/StatefulSmartContract/);
  });
});

describe('asm({...}) surface syntax — argument shape rejection', () => {
  it('rejects asm() with no body field', () => {
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class Missing extends UnsafeSmartContract {
        constructor() {
          super();
        }

        public unlock() {
          asm({ in_arity: 0, out_arity: 1 });
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(false);
    const messages = result.diagnostics.map(d => d.message).join('\n');
    expect(messages).toMatch(/asm.*body/i);
  });

  it('rejects asm() with odd-length hex body', () => {
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class OddLen extends UnsafeSmartContract {
        constructor() {
          super();
        }

        public unlock() {
          asm({ body: '5', in_arity: 0, out_arity: 1 });
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(false);
    const messages = result.diagnostics.map(d => d.message).join('\n');
    expect(messages).toMatch(/odd/i);
  });

  it('rejects asm() with non-hex characters in body', () => {
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class NonHex extends UnsafeSmartContract {
        constructor() {
          super();
        }

        public unlock() {
          asm({ body: 'zz', in_arity: 0, out_arity: 1 });
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(false);
    const messages = result.diagnostics.map(d => d.message).join('\n');
    expect(messages).toMatch(/non-hex/i);
  });

  it('rejects asm() with negative in_arity', () => {
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class NegArity extends UnsafeSmartContract {
        constructor() {
          super();
        }

        public unlock() {
          asm({ body: '51', in_arity: -1, out_arity: 1 });
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(false);
    const messages = result.diagnostics.map(d => d.message).join('\n');
    expect(messages).toMatch(/in_arity.*non-negative/i);
  });

  it('rejects asm() called with positional args instead of an object literal', () => {
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class Positional extends UnsafeSmartContract {
        constructor() {
          super();
        }

        public unlock() {
          // @ts-expect-error — Phase-3 v0 only supports the object-literal form.
          asm('51', 0, 1);
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(false);
    const messages = result.diagnostics.map(d => d.message).join('\n');
    // Parser pushes "expects exactly one object-literal argument", catches
    // the wrong-arity shape before the validator gets a chance to see it.
    expect(messages).toMatch(/asm/i);
    expect(messages).toMatch(/object[- ]literal/i);
  });

  it('rejects asm() called with a non-object-literal argument', () => {
    const source = `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class NonObject extends UnsafeSmartContract {
        constructor() {
          super();
        }

        public unlock() {
          // @ts-expect-error — Phase-3 v0 only supports the object-literal form.
          asm('51');
        }
      }
    `;
    const result = compileSource(source);
    expect(result.success).toBe(false);
    const messages = result.diagnostics.map(d => d.message).join('\n');
    expect(messages).toMatch(/asm/i);
    expect(messages).toMatch(/object[- ]literal/i);
  });
});
