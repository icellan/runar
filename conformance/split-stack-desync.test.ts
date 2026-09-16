import { describe, expect, it } from 'vitest';
import { compile } from 'runar-compiler';

// ---------------------------------------------------------------------------
// `split` keeps the stack model in sync with the runtime stack.
//
// This file used to PIN THE DEFECT. In `05-stack-lower.ts#lowerBuiltinCall`,
// `split` pushed TWO stack-map slots for ONE binding:
//
//     if (func === 'split') {
//       this.stackMap.push(null);        // left part  <- orphan, never dropped
//       this.stackMap.push(bindingName); // right part (top)
//     }
//
// The left half is unnameable — no parser accepts array destructuring, and the
// typechecker's own signature returns a single ByteString — so nothing ever
// consumed that slot. Every later `bringToTop` had to step over it, a branch's
// residue drain could not tell it from its own residue, and the read resolved
// to the wrong slot or aborted with `Value 't11' not found on stack`. That made
// `split` unusable in any contract that does anything after the split, which is
// nearly all of them: the only shape anyone had ever written was the one that
// happens to compile, which is exactly why it had no fixture and no fuzzer
// reach.
//
// The lowering now emits `OP_SPLIT OP_NIP` and pushes one slot — the shape
// `substr`, `right` and `__array_access` already used for the halves they do
// not bind. The rows below are the same programs, now required to COMPILE.
//
// COMPILING IS NOT THE PROPERTY. A stack-model change that type-checks while
// leaving the runtime stack one item off is the bug class this whole branch
// exists to catch, and no amount of successful compiling would catch it. The
// runtime half of this fix lives in
// `conformance/split_residue_execution_test.go`, which spends these shapes on
// the go-sdk consensus interpreter, reads back a value bound BEFORE the split
// alongside the split's own result, and requires wrong values to be rejected.
// This file is the cheap, fast, precise half: it names the defect if it comes
// back, instead of reporting "a spend failed".
// ---------------------------------------------------------------------------

function compileSource(body: string): { ok: boolean; errors: string[]; hex?: string } {
  const src = `import { SmartContract, assert, len, split, substr, left } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class T extends SmartContract {
  constructor() { super(); }
  public run(data: ByteString): void {
${body}
  }
}
`;
  const r = compile(src, { fileName: 'T.runar.ts' });
  return {
    ok: r.success === true,
    errors: (r.diagnostics ?? [])
      .filter((d) => d.severity === 'error')
      .map((d) => d.message),
    hex: r.scriptHex,
  };
}

describe('split keeps the stack model in sync', () => {
  it('compiles when nothing is read after the split', () => {
    const r = compileSource(
      `    const b0: ByteString = split(data, 1n);
    assert(len(b0) >= 0n);`,
    );
    expect(r.errors).toEqual([]);
    expect(r.ok).toBe(true);
  });

  it('CONTROL: substr in the same shape compiles', () => {
    // substr NIPs its left half, and always did. This row is what told the
    // original investigation that the failure was about `split` specifically
    // and not about reading a ByteString param twice. Keeping it means a
    // regression that breaks BOTH still reports as "not a split problem".
    const r = compileSource(
      `    const b0: ByteString = substr(data, 0n, 1n);
    assert(len(b0) >= 0n && len(data) >= 0n);`,
    );
    expect(r.errors).toEqual([]);
    expect(r.ok).toBe(true);
  });

  it('compiles when the split operand is read again', () => {
    // Was: `Value 't11' not found on stack (stack has 3 items: [...])`.
    const r = compileSource(
      `    const b0: ByteString = split(data, 1n);
    assert(len(b0) >= 0n && len(data) >= 0n);`,
    );
    expect(r.errors).toEqual([]);
    expect(r.ok).toBe(true);
  });

  it('compiles when any later local is read', () => {
    // Not specific to re-reading the operand: ANY read whose value had to be
    // brought to the top past the orphaned slot resolved wrongly.
    const r = compileSource(
      `    const b0: ByteString = split(data, 1n);
    const n: bigint = len(b0);
    assert(n >= 0n && n < 100n);`,
    );
    expect(r.errors).toEqual([]);
    expect(r.ok).toBe(true);
  });

  it('compiles when a binding made BEFORE the split is read after it', () => {
    // The shape a real contract writes: measure something, cut, then use both.
    const r = compileSource(
      `    const n: bigint = len(data);
    const b0: ByteString = split(data, 1n);
    assert(len(b0) === n - 1n);`,
    );
    expect(r.errors).toEqual([]);
    expect(r.ok).toBe(true);
  });

  it('emits OP_SPLIT followed immediately by OP_NIP', () => {
    // The mechanism, read directly off the bytes. Without this the rows above
    // would also pass on a lowering that dropped the RIGHT half, or that
    // deferred the cleanup to the method epilogue and left the model desynced
    // in between — both of which compile.
    //
    // `left(data, n)` is the other side of the same cut and lowers to
    // OP_SPLIT OP_DROP, so requiring 7f77 and not 7f75 also pins WHICH half
    // `split` binds.
    const r = compileSource(
      `    const b0: ByteString = split(data, 1n);
    assert(len(b0) >= 0n);`,
    );
    expect(r.ok).toBe(true);
    expect(r.hex, 'split must drop the left half at the split site').toContain('7f77');
    expect(r.hex, 'split must not drop the RIGHT half — that is `left`').not.toContain('7f75');

    const l = compileSource(
      `    const b0: ByteString = left(data, 1n);
    assert(len(b0) >= 0n);`,
    );
    expect(l.ok).toBe(true);
    expect(l.hex, 'left must drop the right half').toContain('7f75');
  });
});
