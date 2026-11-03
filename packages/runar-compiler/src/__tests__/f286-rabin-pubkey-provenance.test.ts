/**
 * F-286 — verifyRabinSig's public key must come from the contract, not the spender.
 *
 * `verifyRabinSig(msg, sig, padding, pubKey)` checks `(sig² + padding) mod n
 * == SHA256(msg) mod n`. If `n` is a spending-method argument the spender picks
 * it, and a spender who picks `n` forges any message without factoring
 * anything: `n = 1`, `sig = 0`, empty padding passes on real `Spend` (the
 * runar-testing F-286 test reproduces exactly that). Nothing in the frontend
 * stopped `public settle(..., pk: RabinPubKey)` from compiling.
 *
 * Rule (user decision R78): the 4th argument must be a contract property
 * (`this.x`, or a bare field name on the Java surface) or a literal, followed
 * through local aliases and through private helpers whose parameter is bound to
 * such a value at EVERY call site. Anything else is refused with one shared
 * diagnostic.
 *
 * What this proves: the TS reference frontend refuses the spender-chosen
 * modulus shapes below (public param, alias of a param, helper fed a param,
 * alias reassigned from a param, ternary) and still accepts the property,
 * literal, alias and helper shapes, on the TS surface and on every one of the
 * nine surfaces for the core accept/refuse pair.
 * What it does NOT prove: that the six peer tiers agree (that is
 * conformance/negatives N220–N228 + each tier's own test), that a hostile
 * `--ir` JSON cannot name a parameter as the modulus (`--ir` bypasses the
 * frontend), or anything about the strength of the key the deployer bakes.
 */
import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
// The one diagnostic every tier emits (conformance/negatives pins the refusal,
// this pins the wording on the reference tier).
const MSG =
  'verifyRabinSig public key (4th argument) must be a contract property or a literal; ' +
  'a spender-supplied Rabin modulus lets anyone forge a signature';

function errorsOf(source: string, fileName = 'C.runar.ts'): string[] {
  const r = compile(source, { fileName });
  return r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
}

function wrap(body: string, extraParams = '', extraMethods = ''): string {
  return `
import { SmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

class C extends SmartContract {
  readonly pk: RabinPubKey;
  readonly pk2: RabinPubKey;

  constructor(pk: RabinPubKey, pk2: RabinPubKey) {
    super(pk, pk2);
    this.pk = pk;
    this.pk2 = pk2;
  }

  public settle(msg: ByteString, sig: RabinSig, padding: ByteString${extraParams}) {
${body}
  }
${extraMethods}
}
`;
}

describe('F-286: verifyRabinSig public key provenance (TS reference frontend)', () => {
  describe('refused: a spender can choose the modulus', () => {
    const cases: [string, string][] = [
      ['public method parameter', wrap('    assert(verifyRabinSig(msg, sig, padding, n));', ', n: RabinPubKey')],
      ['const alias of a parameter', wrap('    const k = n;\n    assert(verifyRabinSig(msg, sig, padding, k));', ', n: RabinPubKey')],
      [
        'let alias initialised from a property, then reassigned from a parameter',
        wrap('    let k = this.pk;\n    k = n;\n    assert(verifyRabinSig(msg, sig, padding, k));', ', n: RabinPubKey'),
      ],
      [
        'private helper whose parameter is bound to a public parameter',
        wrap(
          '    assert(this.check(msg, sig, padding, n));',
          ', n: RabinPubKey',
          `
  private check(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    return verifyRabinSig(m, s, p, k);
  }`,
        ),
      ],
      [
        'private helper bound to a property at one call site and to a parameter at another',
        wrap(
          '    assert(this.check(msg, sig, padding, this.pk));\n    assert(this.check(msg, sig, padding, n));',
          ', n: RabinPubKey',
          `
  private check(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    return verifyRabinSig(m, s, p, k);
  }`,
        ),
      ],
      [
        'ternary between a property and a parameter',
        wrap('    assert(verifyRabinSig(msg, sig, padding, sig > 0n ? this.pk : n));', ', n: RabinPubKey'),
      ],
      ['computed from a property', wrap('    assert(verifyRabinSig(msg, sig, padding, this.pk + 1n));')],
      [
        'parameter, inside a for loop nested in an if',
        wrap(
          '    if (sig > 0n) {\n      for (let i = 0n; i < 2n; i++) {\n        assert(verifyRabinSig(msg, sig, padding, n));\n      }\n    }\n    assert(true);',
          ', n: RabinPubKey',
        ),
      ],
    ];
    for (const [label, src] of cases) {
      it(label, () => {
        expect(errorsOf(src)).toContain(MSG);
      });
    }
  });

  describe('accepted: the modulus is fixed by the deployer', () => {
    const cases: [string, string][] = [
      ['this.<prop>', wrap('    assert(verifyRabinSig(msg, sig, padding, this.pk));')],
      ['bigint literal', wrap('    assert(verifyRabinSig(msg, sig, padding, 1000003n));')],
      ['const alias of a property', wrap('    const k = this.pk;\n    assert(verifyRabinSig(msg, sig, padding, k));')],
      [
        'let alias reassigned only from properties',
        wrap('    let k = this.pk;\n    if (sig > 0n) { k = this.pk2; }\n    assert(verifyRabinSig(msg, sig, padding, k));'),
      ],
      [
        'private helper bound to a property at every call site',
        wrap(
          '    assert(this.check(msg, sig, padding, this.pk));\n    assert(this.check(msg, sig, padding, this.pk2));',
          '',
          `
  private check(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    return verifyRabinSig(m, s, p, k);
  }`,
        ),
      ],
      [
        'two-level private helper chain rooted in a property',
        wrap(
          '    assert(this.outer(msg, sig, padding, this.pk));',
          '',
          `
  private outer(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    const kk = k;
    return this.inner(m, s, p, kk);
  }
  private inner(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    return verifyRabinSig(m, s, p, k);
  }`,
        ),
      ],
    ];
    for (const [label, src] of cases) {
      it(label, () => {
        expect(errorsOf(src)).toEqual([]);
      });
    }
  });

  // The rule runs on the shared AST, so every surface reaches it. One accept /
  // refuse pair per surface pins that each parser hands it a shape it can read
  // (Java's bare field and Move's `contract.x` included).
  describe('every surface: property accepted, method parameter refused', () => {
    const surfaces: [string, string, string][] = [
      [
        '.runar.sol',
        `pragma runar ^0.1.0;
contract C is SmartContract {
    RabinPubKey immutable pk;
    constructor(RabinPubKey _pk) { pk = _pk; }
    function settle(bytes msg, RabinSig sig, bytes padding${'$P'}) public {
        require(verifyRabinSig(msg, sig, padding, ${'$K'}));
    }
}`,
        'this.pk',
      ],
      [
        '.runar.move',
        `module C {
    use runar::types::{ByteString, RabinSig, RabinPubKey};
    use runar::crypto::{verify_rabin_sig};
    resource struct C { pk: RabinPubKey, }
    public fun settle(contract: &C, msg: ByteString, sig: RabinSig, padding: ByteString${'$P'}) {
        assert!(verify_rabin_sig(msg, sig, padding, ${'$K'}), 0);
    }
}`,
        'contract.pk',
      ],
      [
        '.runar.go',
        `package c

import runar "github.com/icellan/runar/packages/runar-go"

type C struct {
	runar.SmartContract
	Pk runar.RabinPubKey \`runar:"readonly"\`
}

func (c *C) Settle(msg runar.ByteString, sig runar.RabinSig, padding runar.ByteString${'$P'}) {
	runar.Assert(runar.VerifyRabinSig(msg, sig, padding, ${'$K'}))
}
`,
        'c.Pk',
      ],
      [
        '.runar.rs',
        `use runar::prelude::*;

#[runar::contract]
pub struct C {
    #[readonly]
    pub pk: RabinPubKey,
}

impl C {
    pub fn settle(&self, msg: ByteString, sig: RabinSig, padding: ByteString${'$P'}) {
        assert!(verify_rabin_sig(&msg, sig, padding, &${'$K'}));
    }
}
`,
        'self.pk',
      ],
      [
        '.runar.py',
        `from runar import SmartContract, ByteString, RabinSig, RabinPubKey, public, assert_, verify_rabin_sig

class C(SmartContract):
    pk: RabinPubKey

    def __init__(self, pk: RabinPubKey):
        super().__init__(pk)
        self.pk = pk

    @public
    def settle(self, msg: ByteString, sig: RabinSig, padding: ByteString${'$P'}):
        assert_(verify_rabin_sig(msg, sig, padding, ${'$K'}))
`,
        'self.pk',
      ],
      [
        '.runar.zig',
        `const runar = @import("runar");

pub const C = struct {
    pub const Contract = runar.SmartContract;

    pk: runar.RabinPubKey,

    pub fn init(pk: runar.RabinPubKey) C {
        return .{ .pk = pk };
    }

    pub fn settle(self: *const C, msg: runar.ByteString, sig: runar.RabinSig, padding: runar.ByteString${'$P'}) void {
        runar.assert(runar.verifyRabinSig(msg, sig, padding, ${'$K'}));
    }
};
`,
        'self.pk',
      ],
      [
        '.runar.rb',
        `require 'runar'

class C < Runar::SmartContract
  prop :pk, RabinPubKey

  def initialize(pk)
    super(pk)
    @pk = pk
  end

  runar_public msg: ByteString, sig: RabinSig, padding: ByteString${'$P'}
  def settle(msg, sig, padding${'$Q'})
    assert verify_rabin_sig(msg, sig, padding, ${'$K'})
  end
end
`,
        '@pk',
      ],
      [
        '.runar.java',
        `package runar.examples;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.ByteString;
import runar.lang.types.RabinPubKey;
import runar.lang.types.RabinSig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.verifyRabinSig;

class C extends SmartContract {
    @Readonly RabinPubKey pk;

    C(RabinPubKey pk) {
        super(pk);
        this.pk = pk;
    }

    @Public
    void settle(ByteString msg, RabinSig sig, ByteString padding${'$P'}) {
        assertThat(verifyRabinSig(msg, sig, padding, ${'$K'}));
    }
}
`,
        'pk',
      ],
    ];
    const paramDecl: Record<string, [string, string]> = {
      '.runar.sol': [', RabinPubKey n', ''],
      '.runar.move': [', n: RabinPubKey', ''],
      '.runar.go': [', n runar.RabinPubKey', ''],
      '.runar.rs': [', n: RabinPubKey', ''],
      '.runar.py': [', n: RabinPubKey', ''],
      '.runar.zig': [', n: runar.RabinPubKey', ''],
      '.runar.rb': [', n: RabinPubKey', ', n'],
      '.runar.java': [', RabinPubKey n', ''],
    };
    for (const [ext, template, propSpelling] of surfaces) {
      const [p, q] = paramDecl[ext]!;
      const render = (withParam: boolean, k: string) =>
        template
          .replaceAll('$P', withParam ? p : '')
          .replaceAll('$Q', withParam ? q : '')
          .replaceAll('$K', k);
      it(`${ext}: ${propSpelling} compiles`, () => {
        expect(errorsOf(render(false, propSpelling), `C${ext}`)).toEqual([]);
      });
      it(`${ext}: a method parameter is refused`, () => {
        expect(errorsOf(render(true, 'n'), `C${ext}`)).toContain(MSG);
      });
    }
  });
});
