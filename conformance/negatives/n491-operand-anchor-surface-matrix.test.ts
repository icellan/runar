import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { REPO, buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-491 (user decision R194) — every TS surface parser records operand
 * locations exactly as the `.runar.ts` parser does.
 *
 * N-489 pinned eight operand shapes on `.runar.ts` in all seven tiers
 * (n233-diagnostic-anchor-parity.test.ts, N489-ts-* rows) and measured that
 * TS's OWN parsers disagree for the same shape on the other eight surfaces:
 * `.runar.sol`, `.move`, `.py`, `.rb` and `.java` located only identifier
 * operands of `&&` / `||` and printed no location for a unary operator or any
 * composite; `.runar.go` and `.zig` located composites but not a unary; only
 * `.runar.rs` located every shape. `.runar.ts` is the reference. Its rule, for
 * the eight shapes here (fixtures N491-<surface>-<shape>):
 *
 *   - a unary `!` / `-` (Python `not`) anchors at the OPERATOR;
 *   - an identifier operand anchors at the identifier;
 *   - a parenthesis wrapping the WHOLE operand is unwrapped: the anchor is the
 *     first token inside it;
 *   - a composite (binary) operand anchors at its own first token: the
 *     literal of a literal-led composite, the outer `(` of a composite led by
 *     a parenthesised call or ternary.
 *
 * (a) TS prints each message at `<file>:<line>:<column of the anchor text>`,
 *     where the column is computed from the fixture text, never copied from a
 *     compiler's output.
 * (b) For each of the other six tiers, either it prints the same anchor or the
 *     (tier, fixture) pair is in DIVERGENT. The allowlist is strict both ways:
 *     a listed pair that matches fails ("converged — remove it"), an unlisted
 *     pair that diverges fails. The per-tier items N-492..N-497 empty it.
 *
 * Excluded, deliberately and not silently: the paren-ternary shape on the four
 * surfaces without a `?:` ternary (NO_TERNARY). `.runar.move`, `.runar.go` and
 * `.runar.zig` have no conditional expression in any tier's TS parser at all;
 * `.runar.rs` would spell it `if c { a } else { b }`, which TS's `.runar.rs`
 * parser (and five of the other six tiers) does not accept as an expression —
 * a parse-acceptance question, not an anchor one, and not this item.
 *
 * What this proves: for these 60 (surface, shape) fixtures TS anchors every
 * refusal by the `.runar.ts` rule, every tier refuses, and the set of tiers
 * that anchor differently is exactly DIVERGENT.
 * What it does NOT prove: anchor parity for any other operand shape (a bare
 * literal operand, member / index / call operands, nested unaries), for any
 * other diagnostic, or on `.runar.ts` itself (that is n233's N489-ts-* rows).
 * The N-491 fix locates binary and unary nodes parsed from OPERATOR syntax on
 * every surface parser; nodes those parsers synthesize (compound-assignment
 * desugars, Java's BigInteger method spellings such as `.add()` / `.negate()`)
 * and the call / member / index / ternary nodes of the `.sol`, `.move`,
 * `.py`, `.rb` and `.java` parsers still carry no location, which none of
 * these shapes reaches.
 */

const TIERS = buildSourceTiers();
const NEG = join(REPO, 'conformance/negatives');

const SURFACES = ['sol', 'move', 'go', 'rs', 'py', 'zig', 'rb', 'java'] as const;
type Surface = (typeof SURFACES)[number];

/** Surfaces with no ternary expression TS can parse (see header). */
const NO_TERNARY: Partial<Record<Surface, string>> = {
  move: 'Move has no conditional expression',
  go: 'Go has no conditional expression',
  zig: "Zig's `if (c) a else b` expression is not parsed by TS's .runar.zig parser",
  rs: "TS's .runar.rs parser does not accept `if c { a } else { b }` as an expression",
};

const NOT = "perand of '!' must be boolean";
const NEG_MSG = "perand of unary '-' must be bigint";
const AND_RIGHT = "ight operand of '&&' must be boolean";
const OR_LEFT = "eft operand of '||' must be boolean";
const AND_LEFT = "eft operand of '&&' must be boolean";

/**
 * shape -> [message fragment, anchor text by surface ('*' = default)]. The
 * anchor's first character is the expected position; it must occur exactly
 * once in the fixture.
 */
const SHAPES: Record<string, [string, Partial<Record<Surface | '*', string>>]> = {
  'not-bigint': [NOT, { '*': '!x', py: 'not x' }],
  'neg-bool': [NEG_MSG, { '*': '-flag' }],
  'and-right': [AND_RIGHT, { '*': 'x)', move: 'x, 0' }],
  'or-left': [OR_LEFT, { '*': 'x ||', py: 'x or', zig: 'x or' }],
  'paren-left': [AND_LEFT, { '*': 'x + 1)' }],
  'lit-led': [AND_LEFT, { '*': '5 + 1' }],
  'paren-call': [AND_LEFT, { '*': '(abs(x)) + 1', go: '(runar.Abs(x)) + 1', zig: '(runar.abs(x)) + 1' }],
  'paren-ternary': [AND_LEFT, { '*': '(flag ? x : x) + 1', py: '(x if flag else x) + 1' }],
};

/**
 * (tier, fixture) pairs whose anchor still differs from TS's, measured at the
 * N-491 tip. Each tier's follow-up item empties its list.
 */
const DIVERGENT: Record<string, string[]> = {
  // N-492 (Zig): converged — every Zig surface parser records operand locations.
  zig: [],
  // N-493 (Go): converged — every Go-side surface parser records operand locations.
  go: [],
  // N-494 (Rust): converged — every Rust-side surface parser records operand locations.
  rust: [],
  // N-495 (Python): converged — every Python-side surface parser records operand locations.
  python: [],
  // N-496 (Ruby): converged — every Ruby-side surface parser records operand locations.
  ruby: [],
  // N-497 (Java): converged — every Java-side surface parser records operand locations.
  java: [],
};

interface Row {
  fixture: string;
  message: string;
  line: number;
  column: number;
}

function rows(): Row[] {
  const out: Row[] = [];
  for (const s of SURFACES) {
    for (const [shape, [message, anchors]] of Object.entries(SHAPES)) {
      if (shape === 'paren-ternary' && NO_TERNARY[s] !== undefined) continue;
      const fixture = `N491-${s}-${shape}.runar.${s}`;
      const anchor = anchors[s] ?? anchors['*']!;
      const lines = readFileSync(join(NEG, fixture), 'utf8').split('\n');
      const hits = lines.flatMap((text, i) => {
        const col = text.indexOf(anchor);
        if (col < 0) return [];
        if (text.indexOf(anchor, col + 1) >= 0) throw new Error(`${fixture}: anchor ${JSON.stringify(anchor)} twice on one line`);
        return [{ line: i + 1, column: col }];
      });
      if (hits.length !== 1) throw new Error(`${fixture}: anchor ${JSON.stringify(anchor)} must occur on exactly one line`);
      out.push({ fixture, message, ...hits[0]! });
    }
  }
  return out;
}

const ROWS = rows();

/** The `L:C` printed on the first diagnostic line carrying `message`, or null. */
function locationOf(diag: string, fixture: string, message: string): string | null {
  const esc = fixture.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const line = diag.split('\n').find((l) => l.includes(message));
  if (line === undefined) return null;
  const m = line.match(new RegExp(`${esc}:(\\d+):(\\d+):`));
  return m ? `${m[1]}:${m[2]}` : null;
}

describe('N-491: TS surface parsers anchor operands as .runar.ts does', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  it('the fixture set is exactly the matrix (no silent omission, no stray fixture)', () => {
    const onDisk = readdirSync(NEG).filter((f) => f.startsWith('N491-')).sort();
    expect(onDisk).toEqual(ROWS.map((r) => r.fixture).sort());
    expect(ROWS.length).toBe(SURFACES.length * Object.keys(SHAPES).length - Object.keys(NO_TERNARY).length);
  });

  it('DIVERGENT names only matrix fixtures and known tiers', () => {
    const fixtures = new Set(ROWS.map((r) => r.fixture));
    expect(Object.keys(DIVERGENT).sort()).toEqual(TIERS.map((t) => t.id).filter((id) => id !== 'ts').sort());
    for (const [tier, list] of Object.entries(DIVERGENT)) {
      for (const f of list) expect(fixtures.has(f), `${tier}: ${f}`).toBe(true);
      expect(new Set(list).size, `${tier}: duplicate entry`).toBe(list.length);
    }
  });

  const ts = TIERS.find((t) => t.id === 'ts')!;
  for (const r of ROWS) {
    it(`(a) ts: ${r.fixture} -> :${r.line}:${r.column}`, () => {
      const res = judge(ts, join(NEG, r.fixture));
      expect(res.verdict, `ts must refuse ${r.fixture}`).toBe('rejected');
      expect(res.diag, `ts must print ${JSON.stringify(r.message)}`).toContain(r.message);
      expect(locationOf(res.diag, r.fixture, r.message)).toBe(`${r.line}:${r.column}`);
    }, 900_000);
  }

  for (const r of ROWS) {
    it(`(b) other tiers: ${r.fixture}`, () => {
      const want = `${r.line}:${r.column}`;
      const problems: string[] = [];
      for (const tier of TIERS) {
        if (tier.id === 'ts') continue;
        const res = judge(tier, join(NEG, r.fixture));
        expect(res.verdict, `${tier.id} must refuse ${r.fixture}`).toBe('rejected');
        // A refusal for some other reason (a parse error) is not an anchor
        // divergence and must not be absorbed into DIVERGENT.
        expect(res.diag, `${tier.id} must print ${JSON.stringify(r.message)}`).toContain(r.message);
        const got = locationOf(res.diag, r.fixture, r.message);
        const listed = DIVERGENT[tier.id]!.includes(r.fixture);
        if (got === want && listed) problems.push(`${tier.id}: converged on ${want} — remove from DIVERGENT`);
        if (got !== want && !listed) problems.push(`${tier.id}: got ${got}, want ${want} — unlisted divergence`);
      }
      expect(problems).toEqual([]);
    }, 900_000);
  }
});
