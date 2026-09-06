/**
 * Two containment gaps the multi-result branch node left open, both found by
 * an independent adversarial review of 4b0f688f.
 *
 * P1-2 — STALE ANF WIRE FORMAT IS SILENTLY ACCEPTED.
 *
 * `--ir` is a documented user surface: `runar compile --ir program.anf.json`
 * feeds a checked-in ANF JSON straight to stack lowering, and the conformance
 * suite's `--ir-parity` mode replays the TypeScript tier's `expected-ir.json`
 * through all six other tiers. ANF carries no version field, so an ANF JSON
 * produced BEFORE the multi-result node — where the trailing `__merge$` block
 * was a CONVENTION that stack lowering recognised by name, not a declared
 * contract — deserialises perfectly today. `results` is simply absent, so
 * `nDeclared === 0`, and the lowerer falls back to inferring the result count
 * from `thenDepth - parentDepth`. That count includes the arm's untrimmed
 * `__merge$` residue, so N result slots are registered for a different N.
 *
 * The convention no longer exists in any tier, so the correct response is a
 * loud refusal rather than a wrong script. Detection is exact and costs no
 * opcodes: a `__merge$`-prefixed binding in an arm is emitted by exactly one
 * thing — `appendBranchResults` — and that function only ever runs for an `if`
 * that declares `results`. So the block present with `results` absent is, by
 * construction, an ANF the current compiler could not have produced.
 *
 * P1-3 — `results` COULD CONTAIN DUPLICATES, AND THE LAYOUT ASSERT COMPARED
 * NAMES ONLY.
 *
 * `results` is built as `mergedLocals ++ armWrittenProperties`, and
 * `appendBranchResults` decides local-vs-property per entry by `props.has(name)`
 * — keyed on the NAME, not the position. A method with a local named `count`
 * beside a property named `count` therefore yields `results = ['count',
 * 'count']`, and BOTH entries take the property path: two `load_prop`/
 * `update_prop` pairs, silently replacing the merged local's value with the
 * property's. The layout assertion in 05-stack-lower compares the arm's top-N
 * slot NAMES against `results`, and both slots are named `count`, so it is
 * satisfied by coincidentally-equal names and the substitution goes unnoticed.
 *
 * These are asserted at the compiler boundary rather than through a spend,
 * because both are REFUSALS: the correct behaviour is a diagnostic, and there
 * is no script to execute.
 */

import { describe, it, expect } from 'vitest';
import { compile, compileFromANF } from 'runar-compiler';
import { MERGED_LOCAL_TEMP_PREFIX } from 'runar-ir-schema';

/**
 * A contract whose `if` DOES declare results, so the compiler emits a real
 * `__merge$` block. Stripping `results` from the emitted ANF then reproduces
 * exactly the pre-4b0f688f wire format, byte for byte, without hand-writing
 * an ANF blob that might not match what the old compiler actually produced.
 */
const MERGE_SOURCE = `import { StatefulSmartContract } from 'runar-lang';

export class Merge extends StatefulSmartContract {
  a: bigint = 0n;
  b: bigint = 0n;
  constructor(a: bigint, b: bigint) { super(a, b); this.a = a; this.b = b; }

  public go(x: bigint, flag: bigint) {
    let na: bigint = 1n;
    let nb: bigint = 2n;
    if (flag > 0n) { na = x + 1n; nb = x + 2n; } else { nb = x + 3n; }
    this.a = na;
    this.b = nb;
  }
}
`;

interface AnyIf {
  kind: string;
  then?: { name: string; value: AnyIf }[];
  else?: { name: string; value: AnyIf }[];
  results?: string[];
}

/** Walk every `if` node in an ANF program body. */
function forEachIf(bindings: { name: string; value: AnyIf }[], fn: (v: AnyIf) => void): void {
  for (const b of bindings) {
    if (b.value.kind === 'if') {
      fn(b.value);
      forEachIf(b.value.then ?? [], fn);
      forEachIf(b.value.else ?? [], fn);
    } else if (b.value.kind === 'loop') {
      forEachIf((b.value as unknown as { body: { name: string; value: AnyIf }[] }).body ?? [], fn);
    }
  }
}

describe('P1-2: ANF from a pre-multi-result compiler', () => {
  it('the fixture really does carry a declared __merge$ block', () => {
    const r = compile(MERGE_SOURCE, {
      fileName: 'Merge.runar.ts',
      disableConstantFolding: true,
    });
    expect(r.success).toBe(true);
    const anf = (r.artifact as unknown as { anf: { methods: { body: never[] }[] } }).anf;
    let declaring = 0;
    let blocks = 0;
    for (const m of anf.methods) {
      forEachIf(m.body, (v) => {
        if ((v.results?.length ?? 0) > 0) declaring++;
        if ((v.then ?? []).some((b) => b.name.startsWith(MERGED_LOCAL_TEMP_PREFIX))) blocks++;
      });
    }
    expect(declaring).toBeGreaterThan(0);
    expect(blocks).toBeGreaterThan(0);
  });

  it('is REFUSED, not silently lowered against an inferred result count', () => {
    const r = compile(MERGE_SOURCE, {
      fileName: 'Merge.runar.ts',
      disableConstantFolding: true,
    });
    // The emitted ANF with `results` deleted IS the pre-4b0f688f wire format:
    // the `__merge$` block was there before the node existed, as a convention
    // the lowerer recognised by name. Deriving it from the current compiler's
    // own output is safer than hand-writing a blob that might not match what
    // the old compiler really produced.
    const anf = (r.artifact as unknown as {
      anf: { methods: { body: { name: string; value: AnyIf }[] }[] };
    }).anf;
    let stripped = 0;
    for (const m of anf.methods) {
      forEachIf(m.body, (v) => {
        if (v.results !== undefined) { delete v.results; stripped++; }
      });
    }
    expect(stripped).toBeGreaterThan(0);

    // Refused either as a diagnostic or as a thrown compiler error — both are
    // a refusal; what matters is that no script comes out and that the reason
    // names the wire format rather than surfacing as a depth mismatch three
    // passes later.
    let message = '';
    try {
      // `compileFromANF` refuses by THROWING today, so the diagnostic branch
      // below is unreachable — it is kept so this test still passes unchanged
      // if the refusal is ever converted into a returned diagnostic list.
      // `CompileFromANFResult` carries neither field, hence the cast.
      const out = compileFromANF(anf as never, { disableConstantFolding: true }) as unknown as {
        success: boolean;
        diagnostics: { message: string }[];
      };
      expect(out.success).toBe(false);
      message = out.diagnostics.map((d) => d.message).join(' ');
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/pre-multi-result compiler/i);
  });
});

describe('P1-3: a local shadowing a property name', () => {
  /**
   * `let count` beside `this.count`, both live across an `if` with a non-empty
   * else — the shape that made `results` contain the same name twice.
   */
  const SHADOW = `import { StatefulSmartContract } from 'runar-lang';

export class Shadow extends StatefulSmartContract {
  count: bigint = 0n;
  constructor(seed: bigint) { super(seed); this.count = seed; }

  public go(x: bigint, flag: bigint) {
    let count: bigint = 1n;
    if (flag > 0n) { count = x + 1n; this.count = x + 2n; }
    else { count = x + 3n; }
    assert(count > 0n);
  }
}
`;

  it('never reaches stack lowering with a duplicated result name', () => {
    const r = compile(SHADOW, { fileName: 'Shadow.runar.ts', disableConstantFolding: true });
    if (r.success) {
      // Accepted end to end — then `results` must not contain duplicates,
      // because the layout assert cannot tell two same-named slots apart.
      const anf = (r.artifact as unknown as { anf: { methods: { body: never[] }[] } }).anf;
      for (const m of anf.methods) {
        forEachIf(m.body, (v) => {
          const res = v.results ?? [];
          expect(new Set(res).size, `duplicate results: [${res.join(', ')}]`).toBe(res.length);
        });
      }
    } else {
      // Or refused with a diagnostic that names the shadowing, not an
      // internal-codegen-error surfaced from three passes later.
      expect(r.diagnostics.map((d) => d.message).join(' '))
        .toMatch(/shadow/i);
    }
  });
});
