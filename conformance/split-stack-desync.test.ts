import { describe, expect, it } from 'vitest';
import { compile } from 'runar-compiler';

// ---------------------------------------------------------------------------
// `split` desyncs the stack model whenever anything is READ after it.
//
// Found by switching on the `split` arm of the fuzzer's `arbBytesExpr`
// (packages/runar-testing/src/fuzzer/generator.ts) — the arm's first seeded
// run produced a program the compiler could not lower. `split` had no fixture
// and no fuzzer reach before that, which is exactly why this survived: the
// only shape anyone had ever written is the one that happens to compile.
//
// CAUSE, in 05-stack-lower.ts#lowerBuiltinCall — `split` pushes TWO stack-map
// slots for ONE binding:
//
//     if (func === 'split') {
//       this.stackMap.push(null);        // left part  <- orphan, never dropped
//       this.stackMap.push(bindingName); // right part (top)
//     }
//
// The left half is unnameable (no parser accepts array destructuring, and the
// typechecker's own signature returns a single ByteString), so nothing ever
// consumes that slot. The model's depth diverges from the runtime stack and
// the next `bringToTop` resolves to the wrong slot. `substr` does not have the
// bug because it NIPs its left half away.
//
// This is a compile-time ABORT, not a silent miscompile, so it costs nobody
// money — but it makes `split` unusable in any contract that does anything
// after the split, which is nearly all of them.
//
// THIS TEST PINS CURRENT BEHAVIOUR. It is not an endorsement. When the
// lowering is fixed, the second case starts compiling and this file goes RED —
// that is the signal to delete the `expect(...).toBe(false)` here and flip
// SPLIT_ARM_ENABLED to true in the fuzzer generator.
// ---------------------------------------------------------------------------

function compileSource(body: string): { ok: boolean; errors: string[] } {
  const src = `import { SmartContract, assert, len, split, substr } from 'runar-lang';
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
  };
}

describe('split desyncs the stack model when a read follows it', () => {
  it('compiles when nothing is read after the split', () => {
    const r = compileSource(
      `    const b0: ByteString = split(data, 1n);
    assert(len(b0) >= 0n);`,
    );
    expect(r.errors).toEqual([]);
    expect(r.ok).toBe(true);
  });

  it('CONTROL: substr in the same shape compiles', () => {
    // substr NIPs its left half, so its stack model stays in sync. This is the
    // row that proves the failure below is about `split` specifically and not
    // about reading a ByteString param twice.
    const r = compileSource(
      `    const b0: ByteString = substr(data, 0n, 1n);
    assert(len(b0) >= 0n && len(data) >= 0n);`,
    );
    expect(r.errors).toEqual([]);
    expect(r.ok).toBe(true);
  });

  it('FAILS TO COMPILE when the split operand is read again', () => {
    const r = compileSource(
      `    const b0: ByteString = split(data, 1n);
    assert(len(b0) >= 0n && len(data) >= 0n);`,
    );
    expect(r.ok).toBe(false);
    expect(r.errors.join(' ')).toMatch(/not found on stack/);
  });

  it('FAILS TO COMPILE when any later local is read', () => {
    // Not specific to re-reading the operand: ANY read whose value must be
    // brought to the top past the orphaned slot resolves wrongly.
    const r = compileSource(
      `    const b0: ByteString = split(data, 1n);
    const n: bigint = len(b0);
    assert(n >= 0n && n < 100n);`,
    );
    expect(r.ok).toBe(false);
    expect(r.errors.join(' ')).toMatch(/not found on stack/);
  });
});
