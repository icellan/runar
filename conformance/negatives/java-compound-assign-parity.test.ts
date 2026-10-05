import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers, compileHex } from './tier-harness.js';

/**
 * N-134 — seven-tier parity for `.runar.java` compound assignment.
 *
 * TS (finishExpressionStatement) and, since N-130, the Java tier lower an
 * expression statement `t op= e` to `t = t op e` for exactly ten operators:
 * + - * / % & | ^ << >>. The Go, Rust, Python, Zig and Ruby .runar.java
 * parsers knew only the first five, so `<<= >>= &= |= ^=` died with a parse
 * error ("unsupported expression token Eq", "unexpected token '='", ...) in
 * those five tiers while TS and Java compiled the contract.
 *
 * Why here and not packages/runar-compiler/src/__tests__/cross-compiler.test.ts:
 * those suites feed TS-produced ANF to the other tiers' `--ir` mode and never
 * run their .runar.java parsers, where the gap lived. Why not a conformance
 * fixture: the item forbids one (it would also need a provenance-gated golden).
 *
 * What this proves:
 *   - every available tier compiles N-130's Compound.runar.java probe (all ten
 *     operators, on a local, a bigint property and a ByteString property) to
 *     the same bytes in both fold modes, and those bytes are pinned;
 *   - the pin is not self-referential: the same contract with every compound
 *     spelled out as `t = t op e` (which all seven tiers already compiled
 *     identically before N-134) produces the identical sha256;
 *   - for each of the ten operators, a bare `count op= 2` is refused with
 *     the N-023 diagnostic and a for-header update `i op= 2` /
 *     `this.count op= 1` is refused by the loop-update rule (N-128/N-133), not
 *     by an incidental parse error. (Before N-134, Rust, Python and Ruby also
 *     refused `*= /= %=` in a for header with a parse error.)
 * What it does NOT prove: on-chain spend behaviour of the bytes; compound
 * forms in expression position (refused everywhere, as in TS); `>>>=` (not
 * in TS's set, refused everywhere); or the .runar.ts surface, whose own
 * parser refuses `<<= >>= &= |= ^=` independently of this item.
 */

const COMPOUND_SHA256 = 'a66871ae82eb652992f39ef9f8ef7f6474cf92bc424776d344127ec843643fce';

const ALL_OPS = ['+=', '-=', '*=', '/=', '%=', '<<=', '>>=', '&=', '|=', '^='] as const;

const BARE_MSG = "bare assignment to property 'count' is not allowed; write `this.count = ...`";
const LOOP_MSG = 'For loop update must advance the loop variable by one';

/** remediation-logs/N-130/probe/Compound.runar.java, the N-130 probe. */
const COMPOUND_JAVA = `package p;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;

class Compound extends StatefulSmartContract {
    Bigint count;
    ByteString tag;

    Compound(Bigint count, ByteString tag) {
        super(count, tag);
        this.count = count;
        this.tag = tag;
    }

    @Public
    void step(Bigint d, ByteString m) {
        Bigint t = d;
        t += 3;
        this.count += t;
        this.count -= 1;
        this.count *= 2;
        this.count /= 3;
        this.count %= 1000;
        this.count <<= 2;
        this.count >>= 1;
        this.count &= 255;
        this.count |= 16;
        this.count ^= 5;
        this.tag &= m;
        this.tag |= m;
        this.tag ^= m;
        assertThat(this.count > 0);
    }
}
`;

/** COMPOUND_JAVA with every `t op= e` written out as `t = t op e`. */
const SPELLED_JAVA = COMPOUND_JAVA.replace(
  /^( +)(t|this\.count|this\.tag) (\+|-|\*|\/|%|<<|>>|&|\||\^)= (.*);$/gm,
  '$1$2 = $2 $3 $4;',
);

function counter(body: string): string {
  return `package p;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

class Counter extends StatefulSmartContract {
    Bigint count;

    Counter(Bigint count) {
        super(count);
        this.count = count;
    }

    @Public
    void increment() {
        ${body}
    }
}
`;
}

/** Run a tier and return its refusal diagnostic; fail if it compiled. */
function refusal(tier: Tier, file: string): string {
  const r = spawnSync(tier.cmd!, [...tier.prefix, ...tier.argsFor(file)], {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.error) throw new Error(`${tier.id} could not run: ${r.error.message}`);
  if (r.status === 0) throw new Error(`${tier.id} ${file}: compiled, expected a refusal`);
  return `${r.stderr ?? ''}\n${r.stdout ?? ''}`;
}

const sha256 = (s: string): string => createHash('sha256').update(s).digest('hex');

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF_TIERS: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n134-java-compound-'));
});

function write(name: string, src: string): string {
  const p = join(dir, name);
  writeFileSync(p, src);
  return p;
}

const opName = (op: string): string =>
  ({
    '+=': 'add', '-=': 'sub', '*=': 'mul', '/=': 'div', '%=': 'mod',
    '<<=': 'shl', '>>=': 'shr', '&=': 'and', '|=': 'or', '^=': 'xor',
  })[op]!;

describe('N-134 .runar.java compound assignment — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (process.env.CI === 'true') expect(TIERS.length).toBe(7);
  });

  it('the spelled-out oracle really spells out all fourteen compound statements', () => {
    expect(SPELLED_JAVA).not.toMatch(/ (\+|-|\*|\/|%|<<|>>|&|\||\^)= /);
    expect(SPELLED_JAVA).toContain('this.count = this.count << 2;');
    expect(SPELLED_JAVA).toContain('this.tag = this.tag ^ m;');
  });

  for (const [mode, tiers] of [
    ['fold-on', TIERS],
    ['fold-off', FOLD_OFF_TIERS],
  ] as const) {
    for (const tier of tiers) {
      it(`${tier.id} (${mode}) compiles Compound.runar.java to the pinned bytes`, () => {
        expect(sha256(compileHex(tier, write('Compound.runar.java', COMPOUND_JAVA)))).toBe(
          COMPOUND_SHA256,
        );
      });
      it(`${tier.id} (${mode}) compiles the spelled-out form to the same bytes`, () => {
        expect(sha256(compileHex(tier, write('Compound.runar.java', SPELLED_JAVA)))).toBe(
          COMPOUND_SHA256,
        );
      });
    }
  }

  for (const op of ALL_OPS) {
    for (const tier of TIERS) {
      it(`${tier.id} refuses bare \`count ${op} 2\` with the N-023 diagnostic`, () => {
        const f = write(`Bare_${opName(op)}.runar.java`, counter(`count ${op} 2;`));
        expect(refusal(tier, f)).toContain(BARE_MSG);
      });
      it(`${tier.id} refuses \`i ${op} 2\` as a for update with the loop-update rule`, () => {
        const f = write(
          `ForVar_${opName(op)}.runar.java`,
          counter(`for (Bigint i = Bigint.ZERO; i < 2; i ${op} 2) { this.count = this.count + 1; }`),
        );
        expect(refusal(tier, f)).toContain(LOOP_MSG);
      });
      it(`${tier.id} refuses \`this.count ${op} 1\` as a for update with the loop-update rule`, () => {
        const f = write(
          `ForState_${opName(op)}.runar.java`,
          counter(`for (Bigint i = Bigint.ZERO; i < 2; this.count ${op} 1) { assertThat(true); }`),
        );
        expect(refusal(tier, f)).toContain(LOOP_MSG);
      });
    }
  }
});
