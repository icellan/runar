/**
 * N-205 (a) — a stateful method must not write a spender-supplied value into a
 * MUTABLE property that verifyRabinSig uses as its public key.
 *
 * F-286 made `verifyRabinSig`'s 4th argument a contract property or a literal.
 * A mutable property is still state the previous spend chose: if
 * `rotate(newKey)` assigns `this.key = newKey` (or passes `newKey` in the
 * key's `addOutput` slot), a spender sets the next UTXO's modulus to 1 and
 * then forges any message against it (n = 1, sig = 0, the F-286 attack) one
 * spend later.
 *
 * Rule (user decision R80): every property whose value reaches a
 * verifyRabinSig 4th argument (directly, through local aliases, or through a
 * private helper's parameter) is a KEY property, and so is every property
 * whose value is written into a key property. Outside the constructor a
 * mutable key property may only be written — by assignment, compound
 * assignment, ++/--, or its positional `addOutput` slot — with a value F-286
 * trusts (a property read or a literal, followed through aliases and private
 * helpers). Anything else is refused with one shared diagnostic naming the
 * property.
 *
 * What this proves: the TS reference frontend refuses the write shapes below
 * (parameter, alias of a parameter, compound assignment, ++, addOutput slot,
 * private setter fed a parameter, key reached through a helper, a property
 * that feeds the key being written from a parameter) and still accepts
 * literal / property / own-value writes, writes to non-key state, and the
 * key in its addOutput slot; plus one accept / refuse pair on every other
 * surface.
 * What it does NOT prove: that the six peer tiers agree (each tier's own N-205
 * test + conformance/negatives N240–N242), the `--ir` path (that is
 * conformance/negatives/ir-rabin-key-provenance.test.ts), or anything about an
 * `addRawOutput` whose script bytes the spender supplies — that recreates the
 * contract with ANY state and is not specific to the Rabin key.
 */
import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

const msg = (prop: string) =>
  `verifyRabinSig public key property '${prop}' may only be assigned a contract property or a literal ` +
  'outside the constructor; a spender-supplied Rabin modulus lets anyone forge a signature';

function errorsOf(source: string, fileName = 'C.runar.ts'): string[] {
  const r = compile(source, { fileName });
  return r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
}

function wrap(
  rotateBody: string,
  extraMethods = '',
  settleCheck = 'verifyRabinSig(msg, sig, padding, this.key)',
): string {
  return `
import { StatefulSmartContract, assert, ByteString, RabinSig, RabinPubKey, verifyRabinSig } from 'runar-lang';

class C extends StatefulSmartContract {
  key: RabinPubKey;
  other: RabinPubKey;
  count: bigint;
  readonly backup: RabinPubKey;

  constructor(key: RabinPubKey, other: RabinPubKey, count: bigint, backup: RabinPubKey) {
    super(key, other, count, backup);
    this.key = key;
    this.other = other;
    this.count = count;
    this.backup = backup;
  }

  public settle(msg: ByteString, sig: RabinSig, padding: ByteString) {
    assert(${settleCheck});
  }

  public rotate(newKey: RabinPubKey, n: bigint) {
${rotateBody}
    assert(true);
  }
${extraMethods}
}
`;
}

describe('N-205 (a): writes to a verifyRabinSig key property (TS reference frontend)', () => {
  describe('refused: a spender chooses the next modulus', () => {
    const cases: [string, string, string][] = [
      ['assigned a public parameter', wrap('    this.key = newKey;'), 'key'],
      ['assigned a const alias of a parameter', wrap('    const k = newKey;\n    this.key = k;'), 'key'],
      ['compound assignment from a parameter', wrap('    this.key += n;'), 'key'],
      ['incremented', wrap('    this.key++;'), 'key'],
      ['assigned inside an if', wrap('    if (n > 0n) {\n      this.key = newKey;\n    }'), 'key'],
      [
        'passed a parameter in its addOutput slot',
        wrap('    this.addOutput(1000n, newKey, this.other, this.count);'),
        'key',
      ],
      [
        'passed a parameter in its slot of an array-literal addOutput value list',
        wrap('    this.addOutput(1000n, [newKey, this.other, this.count]);'),
        'key',
      ],
      [
        'passed a parameter in a later slot of an array-literal value list (key is `other`)',
        wrap('    this.addOutput(1000n, [this.key, newKey, this.count]);', '', 'verifyRabinSig(msg, sig, padding, this.other)'),
        'other',
      ],
      [
        'written by a private setter fed a parameter',
        wrap('    this.setKey(newKey);', `
  private setKey(v: RabinPubKey): void {
    this.key = v;
  }`),
        'key',
      ],
      [
        'key reached through a private helper, then written from a parameter',
        wrap('    this.key = newKey;', `
  private check(m: ByteString, s: RabinSig, p: ByteString, k: RabinPubKey): boolean {
    return verifyRabinSig(m, s, p, k);
  }`, 'this.check(msg, sig, padding, this.key)'),
        'key',
      ],
      [
        'a property that feeds the key is itself written from a parameter',
        wrap('    this.key = this.other;\n    this.other = newKey;'),
        'other',
      ],
    ];
    for (const [label, src, prop] of cases) {
      it(label, () => {
        expect(errorsOf(src)).toContain(msg(prop));
      });
    }
  });

  describe('accepted: the next modulus is fixed by the deployer', () => {
    const cases: [string, string][] = [
      ['assigned a bigint literal', wrap('    this.key = 1000003n;')],
      ['assigned a readonly property', wrap('    this.key = this.backup;')],
      ['assigned another property that is only written from literals', wrap('    this.key = this.other;\n    this.other = 7n;')],
      ['non-key state written from a parameter', wrap('    this.count = this.count + n;')],
      ['non-Rabin mutable property written from a parameter', wrap('    this.other = newKey;')],
      ['the key in its own addOutput slot', wrap('    this.addOutput(1000n, this.key, this.other, n);')],
      ['the key in its own slot of an array-literal value list', wrap('    this.addOutput(1000n, [this.key, this.other, n]);')],
      [
        'written by a private setter fed a property at every call site',
        wrap('    this.setKey(this.backup);', `
  private setKey(v: RabinPubKey): void {
    this.key = v;
  }`),
      ],
    ];
    for (const [label, src] of cases) {
      it(label, () => {
        expect(errorsOf(src)).toEqual([]);
      });
    }
  });

  // The rule runs on the shared AST, so every surface reaches it. One accept /
  // refuse pair per surface pins that each parser hands it a property write it
  // can read (`self.x =`, `@x =`, `c.X =`, `contract.x =`).
  describe('every surface: literal write accepted, parameter write refused', () => {
    const surfaces: [string, string][] = [
      [
        '.runar.sol',
        `pragma runar ^0.1.0;
contract C is StatefulSmartContract {
    RabinPubKey key;
    constructor(RabinPubKey _key) { key = _key; }
    function settle(bytes msg, RabinSig sig, bytes padding) public {
        require(verifyRabinSig(msg, sig, padding, this.key));
    }
    function rotate(RabinPubKey newKey) public {
        this.key = $V;
        require(true);
    }
}`,
      ],
      [
        '.runar.move',
        `module C {
    use runar::types::{ByteString, RabinSig, RabinPubKey};
    use runar::crypto::{verify_rabin_sig};
    resource struct C { key: &mut RabinPubKey, }
    public fun settle(contract: &C, msg: ByteString, sig: RabinSig, padding: ByteString) {
        assert!(verify_rabin_sig(msg, sig, padding, contract.key), 0);
    }
    public fun rotate(contract: &mut C, new_key: RabinPubKey) {
        contract.key = $V;
        assert!(true, 0);
    }
}`,
      ],
      [
        '.runar.go',
        `package c

import runar "github.com/icellan/runar/packages/runar-go"

type C struct {
	runar.StatefulSmartContract
	Key runar.RabinPubKey
}

func (c *C) Settle(msg runar.ByteString, sig runar.RabinSig, padding runar.ByteString) {
	runar.Assert(runar.VerifyRabinSig(msg, sig, padding, c.Key))
}

func (c *C) Rotate(newKey runar.RabinPubKey) {
	c.Key = $V
	runar.Assert(true)
}
`,
      ],
      [
        '.runar.rs',
        `use runar::prelude::*;

#[runar::stateful_contract]
pub struct C {
    pub key: RabinPubKey,
}

impl C {
    pub fn settle(&self, msg: ByteString, sig: RabinSig, padding: ByteString) {
        assert!(verify_rabin_sig(&msg, sig, padding, &self.key));
    }
    pub fn rotate(&mut self, new_key: RabinPubKey) {
        self.key = $V;
        assert!(true);
    }
}
`,
      ],
      [
        '.runar.py',
        `from runar import StatefulSmartContract, ByteString, RabinSig, RabinPubKey, public, assert_, verify_rabin_sig

class C(StatefulSmartContract):
    key: RabinPubKey

    def __init__(self, key: RabinPubKey):
        super().__init__(key)
        self.key = key

    @public
    def settle(self, msg: ByteString, sig: RabinSig, padding: ByteString):
        assert_(verify_rabin_sig(msg, sig, padding, self.key))

    @public
    def rotate(self, new_key: RabinPubKey):
        self.key = $V
        assert_(True)
`,
      ],
      [
        '.runar.zig',
        `const runar = @import("runar");

pub const C = struct {
    pub const Contract = runar.StatefulSmartContract;

    key: runar.RabinPubKey = 0,

    pub fn init(key: runar.RabinPubKey) C {
        return .{ .key = key };
    }

    pub fn settle(self: *const C, msg: runar.ByteString, sig: runar.RabinSig, padding: runar.ByteString) void {
        runar.assert(runar.verifyRabinSig(msg, sig, padding, self.key));
    }

    pub fn rotate(self: *C, newKey: runar.RabinPubKey) void {
        self.key = $V;
        runar.assert(true);
    }
};
`,
      ],
      [
        '.runar.rb',
        `require 'runar'

class C < Runar::StatefulSmartContract
  prop :key, RabinPubKey

  def initialize(key)
    super(key)
    @key = key
  end

  runar_public msg: ByteString, sig: RabinSig, padding: ByteString
  def settle(msg, sig, padding)
    assert verify_rabin_sig(msg, sig, padding, @key)
  end

  runar_public new_key: RabinPubKey
  def rotate(new_key)
    @key = $V
    assert true
  end
end
`,
      ],
      [
        '.runar.java',
        `package runar.examples;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.ByteString;
import runar.lang.types.RabinPubKey;
import runar.lang.types.RabinSig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.verifyRabinSig;

class C extends StatefulSmartContract {
    RabinPubKey key;

    C(RabinPubKey key) {
        super(key);
        this.key = key;
    }

    @Public
    void settle(ByteString msg, RabinSig sig, ByteString padding) {
        assertThat(verifyRabinSig(msg, sig, padding, this.key));
    }

    @Public
    void rotate(RabinPubKey newKey) {
        this.key = $V;
        assertThat(true);
    }
}
`,
      ],
    ];
    const param: Record<string, string> = {
      '.runar.sol': 'newKey',
      '.runar.move': 'new_key',
      '.runar.go': 'newKey',
      '.runar.rs': 'new_key',
      '.runar.py': 'new_key',
      '.runar.zig': 'newKey',
      '.runar.rb': 'new_key',
      '.runar.java': 'newKey',
    };
    // Solidity also accepts a bare property name on the left (`key = x`): an
    // identifier target, which must not be mistaken for a local.
    surfaces.push(['.runar.sol', surfaces[0]![1].replace('this.key = $V;', 'key = $V;')]);
    for (const [ext, template] of surfaces) {
      it(`${ext}: a literal write compiles`, () => {
        expect(errorsOf(template.replaceAll('$V', '1000003'), `C${ext}`)).toEqual([]);
      });
      it(`${ext}: a method-parameter write is refused`, () => {
        expect(errorsOf(template.replaceAll('$V', param[ext]!), `C${ext}`)).toContain(msg('key'));
      });
    }
  });
});
