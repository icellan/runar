/**
 * Regression test for: if-without-else silently skips body in compiled script.
 *
 * Root cause: stack lowering PICKs (copies) outer-protected locals inside the
 * then-branch, leaving a stale copy on the stack.  After OP_ENDIF, subsequent
 * code references the stale copy instead of the if-expression result.
 *
 * The fix adds stale-entry removal (OP_NIP / ROLL+DROP) after OP_ENDIF when
 * the then-branch reassigns a local variable without an else branch.
 */
import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

// ---------------------------------------------------------------------------
// Contract sources
// ---------------------------------------------------------------------------

/** Minimal reproduction: if-without-else that reassigns a local. */
const IF_WITHOUT_ELSE_SOURCE = `
class IfWithoutElse extends SmartContract {
  constructor() { super(); }

  public test(input: bigint) {
    let result = 0n;
    if (input != 0n) { result = result + 1n; }
    assert(result == input);
  }
}
`;

/** Control: same logic with explicit else — this always worked. */
const IF_WITH_ELSE_SOURCE = `
class IfWithElse extends SmartContract {
  constructor() { super(); }

  public test(input: bigint) {
    let result = 0n;
    if (input == 0n) { result = 0n; } else { result = result + 1n; }
    assert(result == input);
  }
}
`;

/** Multiple if-without-else in sequence (countOccupied pattern). */
const MULTI_IF_WITHOUT_ELSE_SOURCE = `
class MultiIfWithoutElse extends SmartContract {
  constructor() { super(); }

  public test(a: bigint, b: bigint, c: bigint) {
    let count = 0n;
    if (a != 0n) { count = count + 1n; }
    if (b != 0n) { count = count + 1n; }
    if (c != 0n) { count = count + 1n; }
    assert(count == 3n);
  }
}
`;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('if-without-else regression', () => {
  it('ANF references result after if-without-else correctly', () => {
    const result = compile(IF_WITHOUT_ELSE_SOURCE);
    expect(result.success).toBe(true);

    const method = result.anf!.methods.find(m => m.name === 'test');
    expect(method).toBeDefined();
    const bindings = method!.body;

    // The if binding should exist
    const ifBinding = bindings.find(b => b.value.kind === 'if');
    expect(ifBinding).toBeDefined();

    // The comparison feeding the assert must reference 'result', which after
    // the stack lowering fix resolves to the correct stack slot (the new value,
    // not the stale pre-if copy).
    const cmpBinding = bindings.find(
      b => b.value.kind === 'bin_op' && b.value.op === '==='
    );
    expect(cmpBinding).toBeDefined();
    if (cmpBinding && cmpBinding.value.kind === 'bin_op') {
      // One of left/right must be 'result' (the reassigned local)
      const refs = [cmpBinding.value.left, cmpBinding.value.right];
      expect(refs.some(r => r === 'result')).toBe(true);
    }
  });

  it('generated script removes stale copy after if-without-else', () => {
    const result = compile(IF_WITHOUT_ELSE_SOURCE);
    expect(result.success).toBe(true);
    expect(result.artifact).toBeDefined();

    // The script should contain OP_NIP (0x77) after OP_ENDIF (0x68) to
    // remove the stale old-value copy left by the PICKed outer ref.
    const script = result.artifact!.script;
    const endifIdx = script.indexOf('68');
    expect(endifIdx).toBeGreaterThan(-1);
    // OP_NIP should follow OP_ENDIF
    expect(script.substring(endifIdx, endifIdx + 4)).toBe('6877');
  });

  it('multiple sequential if-without-else compiles and removes stale copies', () => {
    const result = compile(MULTI_IF_WITHOUT_ELSE_SOURCE);
    expect(result.success).toBe(true);
    expect(result.artifact).toBeDefined();

    const method = result.anf!.methods.find(m => m.name === 'test');
    expect(method).toBeDefined();
    const ifBindings = method!.body.filter(b => b.value.kind === 'if');
    expect(ifBindings.length).toBe(3);

    // Each OP_ENDIF should be followed by OP_NIP (stale removal)
    const script = result.artifact!.script;
    let idx = 0;
    let nipCount = 0;
    while ((idx = script.indexOf('6877', idx)) !== -1) {
      nipCount++;
      idx += 4;
    }
    expect(nipCount).toBe(3);
  });

  it('if-with-else still compiles correctly (no regression)', () => {
    const result = compile(IF_WITH_ELSE_SOURCE);
    expect(result.success).toBe(true);
    expect(result.artifact).toBeDefined();

    // The if-with-else case should NOT have OP_NIP after OP_ENDIF since
    // both branches properly produce the result without stale copies.
    const script = result.artifact!.script;
    // OP_ENDIF (68) should NOT be immediately followed by OP_NIP (77)
    expect(script.indexOf('6877')).toBe(-1);
  });
});
