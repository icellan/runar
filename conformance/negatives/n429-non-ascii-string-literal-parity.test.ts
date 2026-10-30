import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-429: a non-ASCII (or otherwise non-hex) string literal in a method body is
 * a ByteString literal with a malformed hex body, and every tier must refuse
 * it at the ByteString-literal validation step.
 *
 * Zig's validator only checked the hex format of PROPERTY INITIALIZER literals
 * (N-414). A literal in a method body (`const s = "é";`) sailed through Zig's
 * `--parse-only` and only died in a full compile as the opaque
 * `stack lowering error: UnsupportedOperation` / `StackLowerFailed`, while the
 * other five native tiers refused it at validation.
 *
 * What this proves: for each surface Zig shares with its peers (.runar.ts,
 * .py, .rb, .zig, .java), every native tier's `--parse-only` refuses the
 * literal, every tier's full compile refuses it with a ByteString-literal
 * diagnostic, the Zig tier prints the TS tier's exact message (UTF-16 length
 * for the odd/even split, odd-length checked before non-hex), and a plain ASCII
 * hex literal is still accepted by all of them.
 * What it does NOT prove: the Go/Rust/Python/Ruby tiers' wording for
 * non-ASCII input (they count bytes or code points where TS counts UTF-16
 * units, so e.g. Go prints "non-hex" where TS prints "odd length (1)" for
 * 'é' -- same verdict, different prose; only the verdict is graded for them),
 * the TS tier's own `--parse-only` (it stops before the validate pass, which
 * compile-warnings.test.ts pins as a known separate divergence), the .sol /
 * .move surfaces (their tokenizers cannot spell a quoted literal) and the .go
 * / .rs surfaces (a Go `runar.ByteString("é")` is a string-to-bytes
 * conversion with different, accepted semantics).
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
        const s = runar.hexToBytes("${lit}");
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

// The TS validator's two messages. TS measures `val.length` in UTF-16 code
// units and checks odd length BEFORE the hex alphabet.
const tsMessage = (lit: string): string =>
  lit.length % 2 !== 0
    ? `ByteString literal '${lit}' has odd length (${lit.length}) — hex strings must have an even number of characters`
    : `ByteString literal '${lit}' contains non-hex characters — only 0-9, a-f, A-F are allowed`;

const BAD: Array<{ id: string; lit: string }> = [
  { id: 'A', lit: 'é' }, // "é": 1 UTF-16 unit (odd), 2 UTF-8 bytes (even)
  { id: 'B', lit: 'éé' }, // "éé": even, non-hex
  { id: 'D', lit: '\u{1F600}' }, // astral: 2 UTF-16 units (even), 1 code point
];
const SURFACES: Surface[] = ['ts', 'py', 'rb', 'zig', 'java'];

const DIR = mkdtempSync(join(tmpdir(), 'n429-non-ascii-literal-'));
const tiers = buildSourceTiers().filter((t) => t.cmd !== null);
const parseOnly = (t: Tier): Tier => ({
  ...t,
  argsFor: (s) => (t.id === 'ts' ? [s, '--parse-only'] : ['--source', s, '--parse-only']),
});
// The harness drives Zig as `compile <file> --hex`; that is the same one-shot
// compile the other tiers run with `--source <file> --hex`.
const nonTs = tiers.filter((t) => t.id !== 'ts');

describe('N-429: non-hex / non-ASCII ByteString literal in a method body', () => {
  it('all seven tiers are present (else the comparison is vacuous)', () => {
    expect(tiers.map((t) => t.id).sort()).toEqual(['go', 'java', 'python', 'ruby', 'rust', 'ts', 'zig']);
  });

  for (const { id, lit } of BAD) {
    for (const surface of SURFACES) {
      const file = join(DIR, `T${id}.runar.${surface}`);
      writeFileSync(file, body(surface, `T${id}`, lit));

      for (const tier of tiers) {
        it(`${tier.id} full compile refuses ${JSON.stringify(lit)} on .runar.${surface} at ByteString validation`, () => {
          const r = judge(tier, file);
          expect(r.verdict).toBe('rejected');
          expect(r.diag).toMatch(/ByteString literal/);
          expect(r.diag).not.toMatch(/StackLowerFailed|stack lowering/i);
        }, tier.timeoutMs);
      }

      for (const tier of nonTs) {
        it(`${tier.id} --parse-only refuses ${JSON.stringify(lit)} on .runar.${surface}`, () => {
          const r = judge(parseOnly(tier), file);
          expect(r.verdict).toBe('rejected');
          expect(r.diag).toMatch(/ByteString literal/);
        }, tier.timeoutMs);
      }

      const zig = tiers.find((t) => t.id === 'zig');
      if (zig) {
        it(`zig prints the TS message for ${JSON.stringify(lit)} on .runar.${surface}`, () => {
          const want = tsMessage(lit);
          expect(judge(zig, file).diag).toContain(want);
          expect(judge(parseOnly(zig), file).diag).toContain(want);
        }, zig.timeoutMs);
      }
    }
  }

  // Control: a plain ASCII hex literal in the same position is still legal.
  for (const surface of SURFACES) {
    const file = join(DIR, `TOK.runar.${surface}`);
    writeFileSync(file, body(surface, 'TOK', 'ab'));
    for (const tier of tiers) {
      it(`${tier.id} full compile still accepts "ab" on .runar.${surface}`, () => {
        expect(judge(tier, file).verdict).toBe('accepted');
      }, tier.timeoutMs);
    }
  }
});
