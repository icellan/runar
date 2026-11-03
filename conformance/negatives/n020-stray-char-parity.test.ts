import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-020 — a stray character that the surface's tokenizer does not recognise,
 * inside a method body on `.runar.java` and `.runar.rs`, is refused with the
 * TS reference's diagnostic `Unexpected character '<c>'` at the character's
 * line and column by the tokenizers N-020 fixed: Go on `.java`, and Go and
 * Rust on `.rs` (plus TS itself, the reference).
 *
 * SCOPE: only those cells are generated. The remaining tiers on these two
 * surfaces (rust/python/zig/ruby/java on `.java`; python/zig/ruby/java on
 * `.rs`) are covered by N-214, which extends this test, including the
 * decision on how the java tier's javac messages map to this diagnostic.
 *
 * Before the fix the TS reference refused, while the Go `.runar.java`
 * tokenizer and the Go and Rust `.runar.rs` tokenizers dropped the character
 * without a word: `a + § b` compiled exactly as `a + b`.
 *
 * The characters are ones the TS tokenizer for that surface does not know:
 * on `.rs` `@`, `§` and a backtick; on `.java` `#`, `§` and a backtick. `@` is
 * a real Java token (annotations), and TS refuses it in an expression with a
 * PARSER diagnostic, not this one, so it is not a stray character there.
 *
 * What this proves:
 *   - for each of those characters on each of .java and .rs, every in-scope
 *     tier rejects the source and its diagnostic carries
 *     `:<line>:<col>: Unexpected character '<c>'` at the stray character;
 *   - the unmodified template compiles to the same hex on every tier, so the
 *     rejection is about the character and not about the template.
 * What it does NOT prove:
 *   - the position prefix beyond `:line:col:` (file naming differs per tier),
 *     or the diagnostics that follow the first one;
 *   - characters other than these, characters outside a method body, or
 *     non-ASCII LETTERS (the Go tokenizers take `é` into an identifier where
 *     TS refuses it);
 *   - any other surface: the wider matrix (.ts/.sol/.move/.go/.zig/.rb) is
 *     measured in remediation-logs/N-020/matrix-before.txt and is N-214's.
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TMP = mkdtempSync(join(tmpdir(), 'n020-'));

const java = (c: string) => `package runar.examples.arithmetic;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

class Arithmetic extends SmartContract {

    @Readonly Bigint target;

    Arithmetic(Bigint target) {
        super(target);
        this.target = target;
    }

    @Public
    void verify(Bigint a, Bigint b) {
        Bigint sum = a.plus(${c}b);
        assertThat(sum.eq(this.target));
    }
}
`;
// The stray character is on line 21, column 28 (0-based) of the .java template.
const JAVA_AT = ':21:28: ';

const rs = (c: string) => `use runar::prelude::*;

#[runar::contract]
struct Arithmetic {
    #[readonly]
    target: Int,
}

impl Arithmetic {
    pub fn verify(&self, a: Int, b: Int) {
        let sum = a + ${c}b;
        assert!(sum == self.target);
    }
}
`;
// The stray character is on line 11, column 22 (0-based) of the .rs template.
const RS_AT = ':11:22: ';

let n = 0;
function write(file: string, text: string): string {
  const dir = join(TMP, String(n++));
  mkdirSync(dir, { recursive: true });
  const p = join(dir, file);
  writeFileSync(p, text);
  return p;
}

// [surface, file, template, position, stray characters, in-scope tier ids]
const SURFACES: Array<[string, string, (c: string) => string, string, string[], string[]]> = [
  ['.java', 'Arithmetic.runar.java', java, JAVA_AT, ['#', '§', '`'], ['ts', 'go']],
  ['.rs', 'Arithmetic.runar.rs', rs, RS_AT, ['@', '§', '`'], ['ts', 'go', 'rust']],
];

describe('N-020 stray unrecognised character — Go .java, Go/Rust .rs vs the TS reference', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [surface, file, mk, at, chars, inScope] of SURFACES) {
    for (const c of chars) {
      const path = write(file, mk(`${c} `));
      for (const tier of TIERS.filter((t) => inScope.includes(t.id))) {
        it(`${tier.id} refuses a stray ${JSON.stringify(c)} on ${surface} with the shared diagnostic`, () => {
          const j = judge(tier, path);
          expect(j.verdict).toBe('rejected');
          expect(j.diag).toContain(`${at}Unexpected character '${c}'`);
        });
      }
    }

    const controlPath = write(file, mk(''));
    it(`every tier compiles the unmodified ${surface} template to the same hex`, () => {
      const hexes = TIERS.map((t) => compileHex(t, controlPath));
      for (const h of hexes) expect(h).toBe(hexes[0]);
    });
  }
});
