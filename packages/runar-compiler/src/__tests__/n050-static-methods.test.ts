import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { parse } from '../passes/01-parse.js';
import { staticMethodMessage } from '../errors.js';

/**
 * N-050 (external StaticSiphon) — a static / class-level method is not a
 * contract method, so it must never become a spending entry point.
 *
 * `parseMethod` checked `public` but never `static`, so
 *
 *     public static requirePositive(amount: bigint) { assert(amount > 0n); }
 *
 * got a dispatch selector. The script was byte-identical to the non-static
 * spelling and `requirePositive(1)` spent the Vault with no signature under
 * `@bsv/sdk` Spend (remediation-logs/EXT-2/probes/staticsiphon.out; the
 * execution proof is packages/runar-testing/src/__tests__/n050-static-method-spend.test.ts).
 *
 * The rule (R9/F-010 precedent, fail-closed), identical in all seven tiers:
 * every surface that can SPELL a static or class-level method refuses it,
 * public or private, with one diagnostic:
 *
 *     static methods are not allowed in Rúnar contracts; method '<m>' is declared static
 *
 * where <m> is the name as written in the source. The spellings are
 * `.ts` / `.java` `static`, `.py` `@staticmethod` / `@classmethod`, `.rb`
 * `def self.<m>`, and on the receiver-parameter surfaces (`.rs`, `.zig`) a
 * `pub fn` without a self receiver. A PRIVATE receiver-less `fn` on those two
 * surfaces stays a private helper, like a Go free function (R9): the
 * `multi-method` golden's `fn computeThreshold(a: i64, b: i64)` is one.
 * `.go`, `.sol` and `.move` cannot spell a static entry point (a Go free
 * function is a private helper; `static` is not a Solidity-surface token; a
 * Move `fun` has no receiver form to omit).
 *
 * What this proves: the reference tier refuses every spelling above with the
 * shared diagnostic and a source location, and the non-static spellings of the
 * same contracts (and the private receiver-less helpers) still compile.
 * What it does NOT prove: the other six tiers (their own suites, the
 * runar-testing spend test and conformance/negatives/N104-N111 cover that), or
 * anything on chain.
 */

const MSG = (m: string) => staticMethodMessage(m);

function errorsOf(source: string, fileName: string): string[] {
  const r = compile(source, { fileName });
  return (r.diagnostics ?? []).filter((d) => d.severity === 'error').map((d) => d.message);
}

function publicMethods(source: string, fileName: string): string[] {
  const r = compile(source, { fileName });
  const errs = (r.diagnostics ?? []).filter((d) => d.severity === 'error').map((d) => d.message);
  expect(errs, `${fileName} should compile`).toEqual([]);
  return r.artifact!.abi.methods.filter((m) => m.isPublic !== false).map((m) => m.name);
}

function expectRefused(source: string, fileName: string, name: string): void {
  const r = compile(source, { fileName });
  expect(r.success, `${fileName} compiled a static method`).toBe(false);
  expect(r.artifact).toBeFalsy();
  expect(errorsOf(source, fileName)).toContain(MSG(name));
  const hit = parse(source, fileName).errors.find((e) => e.message === MSG(name));
  expect(hit, `${fileName}: the parser did not emit the shared diagnostic`).toBeTruthy();
  expect(hit!.loc?.line ?? 0, `${fileName}: diagnostic carries no location`).toBeGreaterThan(0);
}

// ---------------------------------------------------------------------------
// .runar.ts
// ---------------------------------------------------------------------------

const tsVault = (decl: string) => `import { SmartContract, Sig, PubKey, assert, checkSig } from 'runar-lang';
export class Vault extends SmartContract {
  readonly owner: PubKey;
  constructor(owner: PubKey) { super(owner); this.owner = owner; }
  ${decl} requirePositive(amount: bigint) { assert(amount > 0n); }
  public withdraw(sig: Sig) { assert(checkSig(sig, this.owner)); }
}
`;

describe('N-050 .runar.ts', () => {
  it('the diagnostic text is the shared one', () => {
    expect(MSG('requirePositive')).toBe(
      "static methods are not allowed in Rúnar contracts; method 'requirePositive' is declared static",
    );
  });

  it.each(['public static', 'private static', 'static'])(
    'refuses `%s requirePositive`', (decl) => {
      expectRefused(tsVault(decl), 'Vault.runar.ts', 'requirePositive');
    },
  );

  it('the non-static spelling still compiles, with both entry points', () => {
    expect(publicMethods(tsVault('public'), 'Vault.runar.ts')).toEqual(['requirePositive', 'withdraw']);
    expect(publicMethods(tsVault('private'), 'Vault.runar.ts')).toEqual(['withdraw']);
  });
});

// ---------------------------------------------------------------------------
// .runar.java
// ---------------------------------------------------------------------------

const javaVault = (decl: string) => `package x;
import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;
import java.math.BigInteger;
import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
class Vault extends SmartContract {
    @Readonly PubKey owner;
    Vault(PubKey owner) { super(owner); this.owner = owner; }
    ${decl} void requirePositive(BigInteger amount) { assertThat(amount.compareTo(BigInteger.ZERO) > 0); }
    @Public
    void withdraw(Sig sig) { assertThat(checkSig(sig, owner)); }
}
`;

describe('N-050 .runar.java', () => {
  it.each(['@Public static', '@Public public static', 'static', 'private static', '@Public static final'])(
    'refuses `%s void requirePositive`', (decl) => {
      expectRefused(javaVault(decl), 'Vault.runar.java', 'requirePositive');
    },
  );

  it('the non-static spelling still compiles', () => {
    expect(publicMethods(javaVault('@Public'), 'Vault.runar.java')).toEqual(['requirePositive', 'withdraw']);
    expect(publicMethods(javaVault('private'), 'Vault.runar.java')).toEqual(['withdraw']);
  });
});

// ---------------------------------------------------------------------------
// .runar.py
// ---------------------------------------------------------------------------

const pyVault = (decorators: string, params = 'amount: int') => `from runar import SmartContract, Sig, PubKey, public, assert_, check_sig

class Vault(SmartContract):
    owner: PubKey

    def __init__(self, owner: PubKey):
        super().__init__(owner)
        self.owner = owner

${decorators}
    def require_positive(${params}):
        assert_(amount > 0)

    @public
    def withdraw(self, sig: Sig):
        assert_(check_sig(sig, self.owner))
`;

describe('N-050 .runar.py', () => {
  it.each([
    ['@public @staticmethod', '    @public\n    @staticmethod', 'amount: int'],
    ['@staticmethod @public', '    @staticmethod\n    @public', 'amount: int'],
    ['@staticmethod', '    @staticmethod', 'amount: int'],
    ['@public @classmethod', '    @public\n    @classmethod', 'cls, amount: int'],
    ['@classmethod', '    @classmethod', 'cls, amount: int'],
  ])('refuses %s', (_label, decorators, params) => {
    expectRefused(pyVault(decorators, params), 'Vault.runar.py', 'require_positive');
  });

  it('the instance-method spelling still compiles', () => {
    expect(publicMethods(pyVault('    @public', 'self, amount: int'), 'Vault.runar.py'))
      .toEqual(['requirePositive', 'withdraw']);
  });
});

// ---------------------------------------------------------------------------
// .runar.rb
// ---------------------------------------------------------------------------

const rbVault = (marker: string, def: string) => `require 'runar'

class Vault < Runar::SmartContract
  prop :owner, PubKey

  def initialize(owner)
    super(owner)
    @owner = owner
  end
${marker}
  def ${def}(amount)
    assert amount > 0
  end

  runar_public sig: Sig
  def withdraw(sig)
    assert check_sig(sig, @owner)
  end
end
`;

describe('N-050 .runar.rb', () => {
  it.each([
    ['runar_public def self.x', '  runar_public amount: Bigint', 'self.require_positive'],
    ['private def self.x', '  params amount: Bigint', 'self.require_positive'],
    ['def Vault.x', '  runar_public amount: Bigint', 'Vault.require_positive'],
  ])('refuses %s', (_label, marker, def) => {
    expectRefused(rbVault(marker, def), 'Vault.runar.rb', 'require_positive');
  });

  it('the instance-method spelling still compiles', () => {
    expect(publicMethods(rbVault('  runar_public amount: Bigint', 'require_positive'), 'Vault.runar.rb'))
      .toEqual(['requirePositive', 'withdraw']);
  });
});

// ---------------------------------------------------------------------------
// .runar.rs — an associated function without a self receiver
// ---------------------------------------------------------------------------

const rsVault = (fn: string) => `use runar::prelude::*;

#[runar::contract]
struct Vault {
    #[readonly]
    owner: PubKey,
}

impl Vault {
    ${fn}

    pub fn withdraw(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.owner));
    }
}
`;

describe('N-050 .runar.rs', () => {
  it('refuses `pub fn` without a self receiver', () => {
    expectRefused(rsVault('pub fn require_positive(amount: Int) {\n        assert!(amount > 0);\n    }'),
      'Vault.runar.rs', 'require_positive');
  });

  it('keeps `pub fn` with &self, and a private receiver-less helper', () => {
    expect(publicMethods(rsVault('pub fn require_positive(&self, amount: Int) {\n        assert!(amount > 0);\n    }'),
      'Vault.runar.rs')).toEqual(['requirePositive', 'withdraw']);
    expect(publicMethods(rsVault('fn require_positive(amount: Int) {\n        assert!(amount > 0);\n    }'),
      'Vault.runar.rs')).toEqual(['withdraw']);
  });
});

// ---------------------------------------------------------------------------
// .runar.zig — a `pub fn` without a receiver of the contract type
// ---------------------------------------------------------------------------

const zigVault = (fn: string) => `const runar = @import("runar");

pub const Vault = struct {
    pub const Contract = runar.SmartContract;

    owner: runar.PubKey,

    pub fn init(owner: runar.PubKey) Vault {
        return .{ .owner = owner };
    }

    ${fn}

    pub fn withdraw(self: *const Vault, sig: runar.Sig) void {
        runar.assert(runar.checkSig(sig, self.owner));
    }
};
`;

describe('N-050 .runar.zig', () => {
  it('refuses `pub fn` without a receiver', () => {
    expectRefused(zigVault('pub fn requirePositive(amount: i64) void {\n        runar.assert(amount > 0);\n    }'),
      'Vault.runar.zig', 'requirePositive');
  });

  it('keeps `pub fn` with a receiver, and a private receiver-less helper', () => {
    expect(publicMethods(zigVault('pub fn requirePositive(self: *const Vault, amount: i64) void {\n        _ = self;\n        runar.assert(amount > 0);\n    }'),
      'Vault.runar.zig')).toEqual(['requirePositive', 'withdraw']);
    expect(publicMethods(zigVault('fn requirePositive(amount: i64) void {\n        runar.assert(amount > 0);\n    }'),
      'Vault.runar.zig')).toEqual(['withdraw']);
  });
});
