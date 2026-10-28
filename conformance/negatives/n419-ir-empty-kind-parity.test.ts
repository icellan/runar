import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadANFFromJSON } from '../../packages/runar-compiler/src/index.js';
import { IR_TIER_IDS, Tier, buildIrTiers, judge } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-419 — every tier's `--ir` loader refuses a binding whose `value.kind` is
 * the EMPTY STRING with ONE shared diagnostic:
 *   IR validation: <path>.value.kind must be a non-empty string
 * at every nesting level (a method body, an `if` arm, a `loop` body), the
 * same path style as N-408's empty binding name.
 *
 * The defect: N-069's required-field check tests that `kind` is a string and
 * `""` is a string. Go, Python and Ruby refused it later with per-tier wording
 * (`method <m> binding <n> has empty kind`); the other tiers' behaviour is
 * what this test measures.
 *
 * Diagnostics are graded exactly. The control is N-069's P2PK control; the
 * nested control (named arms, real kinds) must be ACCEPTED by every tier so
 * each refusal is discriminating.
 *
 * What this does NOT prove: that an unknown non-empty kind is refused with a
 * shared message (a separate, existing check), or whitespace-only kinds.
 */

const REQUIRED = JSON.parse(
  readFileSync(join(__dirname, 'ir-required-fields-cases.json'), 'utf8'),
) as { control: Ir };

type Ir = {
  contractName: string;
  properties: unknown[];
  methods: Array<{
    name: string;
    isPublic: boolean;
    params: Array<{ name: string; type: string }>;
    body: Array<{ name: string; value: Record<string, unknown> }>;
  }>;
};

/** `m(flag) { if (flag) <then> else <else>; loop 2x <body>; assert(flag) }` with kinds as given. */
const nestedIr = (thenKind: string, elseKind: string, loopKind: string): Ir => ({
  contractName: 'X',
  properties: [],
  methods: [
    {
      name: 'm',
      isPublic: true,
      params: [{ name: 'flag', type: 'boolean' }],
      body: [
        { name: 't0', value: { kind: 'load_param', name: 'flag' } },
        {
          name: 't1',
          value: {
            kind: 'if',
            cond: 't0',
            then: [{ name: 'a0', value: { kind: thenKind, value: true } }],
            else: [{ name: 'e0', value: { kind: elseKind, value: true } }],
          },
        },
        {
          name: 't2',
          value: {
            kind: 'loop',
            count: 2,
            start: 0,
            step: 1,
            iterVar: 'i',
            body: [{ name: 'l0', value: { kind: loopKind, value: 1 } }],
          },
        },
        { name: 't3', value: { kind: 'assert', value: 't0' } },
      ],
    },
  ],
});

const EMPTY = (path: string): string => `IR validation: ${path} must be a non-empty string`;

interface Case {
  name: string;
  ir: Ir;
  error: string;
}

const topLevel = JSON.parse(JSON.stringify(REQUIRED.control)) as Ir;
topLevel.methods[0].body[1].value.kind = '';

const CASES: Case[] = [
  {
    name: 'binding-kind-empty',
    ir: topLevel,
    error: EMPTY('methods[0].body[1].value.kind'),
  },
  {
    name: 'binding-kind-empty-in-then-arm',
    ir: nestedIr('', 'load_const', 'load_const'),
    error: EMPTY('methods[0].body[1].value.then[0].value.kind'),
  },
  {
    name: 'binding-kind-empty-in-else-arm',
    ir: nestedIr('load_const', '', 'load_const'),
    error: EMPTY('methods[0].body[1].value.else[0].value.kind'),
  },
  {
    name: 'binding-kind-empty-in-loop-body',
    ir: nestedIr('load_const', 'load_const', ''),
    error: EMPTY('methods[0].body[2].value.body[0].value.kind'),
  },
];

const DIR = mkdtempSync(join(tmpdir(), 'n419-ir-empty-kind-'));
const write = (name: string, ir: unknown): string => {
  const p = join(DIR, `${name}.json`);
  writeFileSync(p, JSON.stringify(ir));
  return p;
};
const CONTROL = write('control', REQUIRED.control);
const NESTED_NAMED = write('nested-named', nestedIr('load_const', 'load_const', 'load_const'));

const TIERS: Tier[] = buildIrTiers();
const available = TIERS.filter((t) => t.cmd !== null);

describe('N-419: --ir loaders refuse an empty binding kind with one message (all 7 tiers)', () => {
  it('every case differs from the control and carries an "IR validation:" diagnostic', () => {
    const control = JSON.stringify(REQUIRED.control);
    expect(CASES.length).toBeGreaterThanOrEqual(4);
    for (const c of CASES) {
      expect(JSON.stringify(c.ir), c.name).not.toBe(control);
      expect(c.error, c.name).toMatch(/^IR validation: /);
    }
  });

  it('the matrix names all seven IR-capable CLI tiers', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...IR_TIER_IDS].sort());
  });

  it('every IR-capable tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (isCiEnv(process.env)) expect(missing).toEqual([]);
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  it('ts loads the control and the named nested IR', () => {
    expect(() => loadANFFromJSON(JSON.stringify(REQUIRED.control))).not.toThrow();
    expect(() =>
      loadANFFromJSON(JSON.stringify(nestedIr('load_const', 'load_const', 'load_const'))),
    ).not.toThrow();
  });

  for (const c of CASES) {
    it(`ts loader refuses ${c.name} with "${c.error}"`, () => {
      let message = '<accepted>';
      try {
        loadANFFromJSON(JSON.stringify(c.ir));
      } catch (e) {
        message = (e as Error).message;
      }
      expect(message).toBe(c.error);
    });
  }

  for (const tier of available) {
    it(`${tier.id} ACCEPTS the control and the named nested IR`, () => {
      expect(judge(tier, CONTROL).verdict).toBe('accepted');
      expect(judge(tier, NESTED_NAMED).verdict).toBe('accepted');
    });

    for (const c of CASES) {
      it(`${tier.id} refuses ${c.name} with the shared diagnostic`, () => {
        const { verdict, diag } = judge(tier, write(`${tier.id}-${c.name}`, c.ir));
        expect(verdict, `${tier.id} accepted ${c.name}`).toBe('rejected');
        expect(diag).toContain(c.error);
      });
    }
  }
});
