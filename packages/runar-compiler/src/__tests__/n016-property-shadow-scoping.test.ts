import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

/**
 * N-016 — a local that shares a contract property's name must never capture
 * a later `this.<prop>` read or write (user decision R8: correct scoping).
 *
 *     readonly target: bigint;
 *     public unlock(n: bigint) {
 *       const target = n + 1n;
 *       assert(target == this.target);   // must compare against the PROPERTY
 *     }
 *
 * compiled to `8b769c` (OP_1ADD OP_DUP OP_NUMEQUAL): stack lowering resolved
 * `load_prop target` by name, found the local's slot, and compared the local
 * with itself — an always-true guard. Every tier did the same.
 *
 * The oracle here is alpha-equivalence, derived from the source language and
 * not from any compiler output: renaming a local (or a private helper's
 * parameter, or a public parameter) to a fresh name cannot change what the
 * program means, so the shadowing spelling must compile to exactly the bytes
 * of the renamed spelling. Each shape is one template instantiated twice —
 * `$L` replaced by the property's own name (shadowing) and by `lcl` (control).
 * Checked in both constant-folding modes.
 *
 * What this proves: in the TS reference, a property-named local declared at
 * method top level, inside an if-arm, inside a nested block, as a loop
 * variable, mutated with ++, byte-typed, inside a private helper, a private
 * helper's parameter, and a public parameter all leave `this.<prop>` reads
 * resolving to the property; in stateful contracts property reads, writes
 * and the state continuation are unaffected by a same-named local, including
 * an if whose arms rebind the local AND write the property (previously
 * refused). The on-chain execution proof (real @bsv/sdk Spend, all seven
 * tiers) is packages/runar-testing/src/__tests__/n016-property-shadow-spend.test.ts.
 * What it does NOT prove: the other six tiers (their own suites and the
 * `property-shadow` conformance fixture cover them), or local-vs-compiler-temp
 * name collisions (a local literally named `t3`), which are a different
 * namespace and not part of this item.
 */

const STATELESS = (body: string, propType = 'bigint') => `
import { SmartContract, assert, cat, ByteString } from 'runar-lang';

class Shadow extends SmartContract {
  readonly target: ${propType};
  constructor(target: ${propType}) {
    super(target);
    this.target = target;
  }

${body}
}
`;

const STATEFUL = (body: string) => `
import { StatefulSmartContract, assert } from 'runar-lang';

class Shadow extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

${body}
}
`;

const SHAPES: Record<string, { template: string; prop: string }> = {
  'local at method top level, then this.target': {
    prop: 'target',
    template: STATELESS(`  public unlock(n: bigint) {
    const $L = n + 1n;
    assert($L == this.target);
  }`),
  },
  'local inside an if-arm': {
    prop: 'target',
    template: STATELESS(`  public unlock(n: bigint) {
    if (n > 0n) {
      const $L = n + 1n;
      assert($L == this.target);
    } else {
      assert(n == this.target);
    }
  }`),
  },
  'local inside a nested block': {
    prop: 'target',
    template: STATELESS(`  public unlock(n: bigint) {
    if (n > 0n) {
      if (n > 1n) {
        const $L = n + 1n;
        assert($L == this.target);
      } else {
        assert(n + 2n == this.target);
      }
    } else {
      assert(false);
    }
  }`),
  },
  'loop variable': {
    prop: 'target',
    template: STATELESS(`  public unlock(n: bigint) {
    let acc = 0n;
    for (let $L = 0n; $L < 2n; $L++) {
      acc = acc + this.target - $L;
    }
    assert(acc == n);
  }`),
  },
  'local mutated with ++': {
    prop: 'target',
    template: STATELESS(`  public unlock(n: bigint) {
    let $L = n;
    $L++;
    assert($L == this.target);
  }`),
  },
  'byte-typed local': {
    prop: 'target',
    template: STATELESS(`  public unlock(a: ByteString) {
    const $L = cat(a, a);
    assert($L == this.target);
  }`, 'ByteString'),
  },
  'local inside a private helper': {
    prop: 'target',
    template: STATELESS(`  private chk(n: bigint): boolean {
    const $L = n + 1n;
    return $L == this.target;
  }

  public unlock(n: bigint) {
    assert(this.chk(n));
  }`),
  },
  'private helper parameter': {
    prop: 'target',
    template: STATELESS(`  private chk($L: bigint): boolean {
    return this.target == $L + 1n;
  }

  public unlock(n: bigint) {
    assert(this.chk(n));
  }`),
  },
  'public parameter, property read first': {
    prop: 'target',
    template: STATELESS(`  public unlock($L: bigint) {
    assert(this.target == $L + 1n);
  }`),
  },
  'stateful: local, then property read + write': {
    prop: 'count',
    template: STATEFUL(`  public bump(n: bigint) {
    const $L = n * 2n;
    this.count = this.count + $L;
    assert($L > 0n);
  }`),
  },
  'stateful: local live across a property write': {
    prop: 'count',
    template: STATEFUL(`  public bump(n: bigint) {
    let $L = n;
    this.count = this.count + 1n;
    assert(this.count > $L);
  }`),
  },
  'stateful: if-arms rebind the local and write the property': {
    prop: 'count',
    template: STATEFUL(`  public bump(n: bigint) {
    let $L = n;
    if (n > 3n) {
      $L = $L + 1n;
      this.count = this.count + $L;
    } else {
      this.count = this.count + 1n;
    }
  }`),
  },
  'stateful: an if-arm writes the property, then rebinds the local read after the if': {
    prop: 'count',
    template: STATEFUL(`  public bump(n: bigint) {
    let $L = n;
    if (n > 3n) {
      this.count = this.count + $L;
      $L = $L + 1n;
    } else {
      this.count = this.count + 1n;
    }
    assert($L > 0n);
  }`),
  },
};

function hexOf(source: string, disableConstantFolding: boolean): string {
  const r = compile(source, { fileName: 'Shadow.runar.ts', disableConstantFolding });
  const errors = r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
  expect(errors, 'compile errors').toEqual([]);
  expect(r.success).toBe(true);
  return r.artifact!.script;
}

describe('N-016 — a same-named local never captures this.<prop>', () => {
  it('the probe no longer compiles to the always-true self-comparison 8b769c', () => {
    const src = SHAPES['local at method top level, then this.target']!.template.replaceAll('$L', 'target');
    const hex = hexOf(src, true);
    expect(hex).not.toBe('8b769c');
    // OP_1ADD <placeholder for target> OP_NUMEQUAL — the comparison reads the
    // constructor slot, not a copy of the local.
    expect(hex).toBe('8b009c');
  });

  for (const [name, { template, prop }] of Object.entries(SHAPES)) {
    for (const disableConstantFolding of [true, false]) {
      it(`${name} (fold ${disableConstantFolding ? 'off' : 'on'}) compiles like the renamed spelling`, () => {
        const shadow = hexOf(template.replaceAll('$L', prop), disableConstantFolding);
        const control = hexOf(template.replaceAll('$L', 'lcl'), disableConstantFolding);
        expect(shadow).toBe(control);
      });
    }
  }
});
