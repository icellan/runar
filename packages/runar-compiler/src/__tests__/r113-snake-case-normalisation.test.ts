import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

/**
 * R-113 / CL-BUG-052 — snake_case → camelCase normalisation used two different
 * algorithms, and the TypeScript tier was the outlier.
 *
 * The TS parsers convert with `replace(/_([a-z0-9])/g, …)`: it only uppercases
 * when the character after the underscore is lower-case or a digit, and it
 * consumes one underscore at a time. The other six tiers split on `_` and
 * capitalise each following part. Measured on a `.runar.py` contract with two
 * properties, through every shipping compiler:
 *
 *     foo__bar     TS foo_Bar     go/rust/python/zig/ruby/java  fooBar
 *     baz_Qux      TS baz_Qux     go/rust/python/zig/ruby/java  bazQux
 *
 * An identifier with adjacent underscores, or an underscore before an
 * upper-case letter, therefore produced a DIFFERENT AST name — and so a
 * different canonical ANF — in the reference tier than in the other six. That
 * is invariant 2 (byte-identical ANF) failing on a name, silently, for any
 * fixture that happened to use one.
 *
 * The six-tier algorithm wins: it is the majority, and it is the one that does
 * something sensible with both shapes. Same direction as N-104 and R-092 —
 * converge on the many, never on the one.
 */

const pySource = `from runar import (
    SmartContract, Bigint, public, assert_,
)


class SnakeNames(SmartContract):
    foo__bar: Bigint
    baz_Qux: Bigint

    def __init__(self, foo__bar: Bigint, baz_Qux: Bigint):
        super().__init__(foo__bar, baz_Qux)
        self.foo__bar = foo__bar
        self.baz_Qux = baz_Qux

    @public
    def go(self, x: Bigint):
        assert_(x > self.foo__bar + self.baz_Qux)
`;

const rustSource = `use runar::prelude::*;

#[runar::contract]
struct SnakeNames {
    #[readonly]
    foo__bar: Int,
    #[readonly]
    baz_Qux: Int,
}

impl SnakeNames {
    pub fn go(&self, x: Int) {
        assert!(x > self.foo__bar + self.baz_Qux);
    }
}
`;

function propertyNames(source: string, fileName: string): string[] {
  const r = compile(source, { fileName });
  if (!r.success) {
    throw new Error(`compile failed: ${r.diagnostics.map((d) => d.message).join(' | ')}`);
  }
  return ((r.anf as unknown as { properties: Array<{ name: string }> }).properties ?? []).map(
    (p) => p.name,
  );
}

describe('R-113 snake_case normalisation matches the other six tiers', () => {
  it('.runar.py: adjacent underscores and _Upper collapse the same way', () => {
    expect(propertyNames(pySource, 'SnakeNames.runar.py')).toEqual(['fooBar', 'bazQux']);
  });

  it('.runar.rs: same shapes, same answer', () => {
    expect(propertyNames(rustSource, 'SnakeNames.runar.rs')).toEqual(['fooBar', 'bazQux']);
  });

  it('ordinary snake_case is unchanged — this is not a rename of everything', () => {
    const ordinary = pySource
      .replace(/foo__bar/g, 'pub_key_hash')
      .replace(/baz_Qux/g, 'owner_addr');
    expect(propertyNames(ordinary, 'SnakeNames.runar.py')).toEqual(['pubKeyHash', 'ownerAddr']);
  });

  it('a name with no underscore at all is untouched', () => {
    const plain = pySource.replace(/foo__bar/g, 'count').replace(/baz_Qux/g, 'total');
    expect(propertyNames(plain, 'SnakeNames.runar.py')).toEqual(['count', 'total']);
  });

  it('Python dunders still survive the parser (the __init__ above is one)', () => {
    // If dunder handling regressed, the constructor would not be found and the
    // compile in every case above would already have failed — but assert it
    // directly so the reason is legible.
    const r = compile(pySource, { fileName: 'SnakeNames.runar.py' });
    expect(r.success).toBe(true);
    expect(r.artifact?.abi.constructor.params.map((p) => p.name)).toEqual(['fooBar', 'bazQux']);
  });
});
