import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-436: the ByteString-literal hex diagnostic must read the same in every
 * tier. TS measures `val.length` in UTF-16 code units, checks odd length
 * BEFORE the hex alphabet, and prints the literal as UTF-8. Go/Rust counted
 * bytes, Python/Ruby counted code points, and Go decoded .runar.rb/.runar.zig
 * sources as Latin-1 (mojibake in the printed literal).
 *
 * What this proves: for "\u00e9", "\u00e9\u00e9", U+1F600, "a", "zz" on
 * .runar.{ts,py,rb,zig,java}, every tier's full compile AND every native
 * tier's --parse-only print TS's exact message (kind, length unit, literal).
 * What it does NOT prove: the .sol/.move surfaces (no quoted literal syntax),
 * the .go/.rs surfaces (string-to-bytes conversion, separate semantics), TS's
 * own --parse-only (stops before validation), or locations (line:col).
 */

type Surface = 'ts' | 'py' | 'rb' | 'zig' | 'java';

const body = (surface: Surface, name: string, lit: string): string => {
  switch (surface) {
    case 'ts':
      return `import { SmartContract, assert, PubKey, Sig, checkSig } from 'runar-lang';

class ${name} extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  public unlock(sig: Sig) {
    const s = "${lit}";
    assert(checkSig(sig, this.pk));
  }
}
`;
    case 'py':
      return `from runar import SmartContract, Sig, PubKey, public, assert_, check_sig, ByteString

class ${name}(SmartContract):
    pk: PubKey

    def __init__(self, pk: PubKey):
        super().__init__(pk)
        self.pk = pk

    @public
    def unlock(self, sig: Sig):
        s: ByteString = "${lit}"
        assert_(check_sig(sig, self.pk))
`;
    case 'rb':
      return `require 'runar'

class ${name} < Runar::SmartContract
  prop :pk, PubKey

  def initialize(pk)
    super(pk)
    @pk = pk
  end

  runar_public sig: Sig
  def unlock(sig)
    s = "${lit}"
    assert check_sig(sig, @pk)
  end
end
`;
    case 'zig':
      return `const runar = @import("runar");

pub const ${name} = struct {
    pub const Contract = runar.SmartContract;

    pk: runar.PubKey,

    pub fn init(pk: runar.PubKey) ${name} {
        return .{ .pk = pk };
    }

    pub fn unlock(self: *const ${name}, sig: runar.Sig) void {
        const s = "${lit}";
        _ = s;
        runar.assert(runar.checkSig(sig, self.pk));
    }
};
`;
    case 'java':
      return `package runar.examples.t;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;

class ${name} extends SmartContract {
    @Readonly PubKey pk;

    ${name}(PubKey pk) {
        super(pk);
        this.pk = pk;
    }

    @Public
    void unlock(Sig sig) {
        ByteString s = ByteString.fromHex("${lit}");
        assertThat(checkSig(sig, pk));
    }
}
`;
  }
};

const tsMessage = (lit: string): string =>
  lit.length % 2 !== 0
    ? `ByteString literal '${lit}' has odd length (${lit.length}) \u2014 hex strings must have an even number of characters`
    : `ByteString literal '${lit}' contains non-hex characters \u2014 only 0-9, a-f, A-F are allowed`;

const BAD: Array<{ id: string; lit: string }> = [
  { id: 'A', lit: '\u00e9' }, // 1 UTF-16 unit (odd), 2 UTF-8 bytes
  { id: 'B', lit: '\u00e9\u00e9' }, // even, non-hex
  { id: 'D', lit: '\u{1F600}' }, // astral: 2 UTF-16 units, 1 code point, 4 bytes
  { id: 'E', lit: 'a' }, // ASCII odd
  { id: 'F', lit: 'zz' }, // ASCII even non-hex
];
const SURFACES: Surface[] = ['ts', 'py', 'rb', 'zig', 'java'];

const DIR = mkdtempSync(join(tmpdir(), 'n436-literal-diag-'));
const tiers = buildSourceTiers().filter((t) => t.cmd !== null);
const parseOnly = (t: Tier): Tier => ({
  ...t,
  argsFor: (s) => (t.id === 'ts' ? [s, '--parse-only'] : ['--source', s, '--parse-only']),
});
const nonTs = tiers.filter((t) => t.id !== 'ts');

describe('N-436: ByteString-literal hex diagnostic text is identical in every tier', () => {
  it('all seven tiers are present (else the comparison is vacuous)', () => {
    expect(tiers.map((t) => t.id).sort()).toEqual(['go', 'java', 'python', 'ruby', 'rust', 'ts', 'zig']);
  });

  for (const { id, lit } of BAD) {
    for (const surface of SURFACES) {
      const file = join(DIR, `T${id}.runar.${surface}`);
      writeFileSync(file, body(surface, `T${id}`, lit));
      const want = tsMessage(lit);
      for (const tier of tiers) {
        it(`${tier.id} full compile prints the TS message for ${JSON.stringify(lit)} on .runar.${surface}`, () => {
          const r = judge(tier, file);
          expect(r.verdict).toBe('rejected');
          expect(r.diag).toContain(want);
        }, tier.timeoutMs);
      }
      for (const tier of nonTs) {
        it(`${tier.id} --parse-only prints the TS message for ${JSON.stringify(lit)} on .runar.${surface}`, () => {
          const r = judge(parseOnly(tier), file);
          expect(r.verdict).toBe('rejected');
          expect(r.diag).toContain(want);
        }, tier.timeoutMs);
      }
    }
  }
});
