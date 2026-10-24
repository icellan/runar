import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import {
  CONSENSUS_SPEND_CONTEXT,
  newConsensusSpend,
} from '../../packages/runar-testing/src/consensus-spend.js';
import { loadANFFromJSON } from '../../packages/runar-compiler/src/index.js';
import { IR_TIER_IDS, Tier, buildIrTiers, judge } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-207 — every tier's `--ir` loader refuses an EMPTY identifier
 * (contractName, a method name, a param name or type, a property name or
 * type) and DUPLICATE parameter names within one method, with ONE shared
 * diagnostic per case:
 *   IR validation: <path> must be a non-empty string
 *   IR validation: <path>.name '<name>' duplicates <earlier path>.name
 *
 * The defect: N-069's required-field check tests presence and JSON type, and
 * `""` is a string, so all of these loaded. Duplicate param names alias ONE
 * stack slot (measured with the TS reference + `@bsv/sdk` consensus Spend,
 * see the oracle test below): every `load_param` of the name resolves to the
 * LAST declared slot, the earlier param is never read although the ABI still
 * advertises it, and an author-written `assert(p0 === p1)` over two params
 * both named `''` compiles to `767c9c77` (DUP SWAP NUMEQUAL NIP) — a value
 * compared with itself, so the guard is always true and unequal arguments
 * spend.
 *
 * The control is N-069's P2PK control (`ir-required-fields-cases.json`),
 * which every tier must ACCEPT, so each refusal below is discriminating. Each
 * case changes ONE identifier of it. Diagnostics are graded exactly: the item
 * is "one shared message", so a refusal for an unrelated downstream reason
 * (e.g. an undeclared `load_prop` once the property name is blanked) does not
 * count.
 *
 * What this does NOT prove: that identifiers are otherwise well-formed
 * (whitespace-only, reserved words, non-ASCII), that property names are
 * unique, or that a param may not shadow a property — none of that is in
 * N-207's scope. It also says nothing about the source path, whose parsers
 * cannot produce an empty identifier.
 */

const REQUIRED = JSON.parse(
  readFileSync(join(__dirname, 'ir-required-fields-cases.json'), 'utf8'),
) as { control: Ir };

type Ir = {
  contractName: string;
  properties: Array<{ name: string; type: string; readonly: boolean }>;
  methods: Array<{
    name: string;
    isPublic: boolean;
    params: Array<{ name: string; type: string }>;
    body: Array<{ name: string; value: Record<string, unknown> }>;
  }>;
};

const clone = (): Ir => JSON.parse(JSON.stringify(REQUIRED.control)) as Ir;
const mutate = (f: (ir: Ir) => void): Ir => {
  const ir = clone();
  f(ir);
  return ir;
};

/** `check(p0, p1) { assert(p0 === p1) }` with the two params named as given. */
const equalityIr = (p0: string, p1: string): Ir => ({
  contractName: 'X',
  properties: [],
  methods: [
    {
      name: 'check',
      isPublic: true,
      params: [
        { name: p0, type: 'bigint' },
        { name: p1, type: 'bigint' },
      ],
      body: [
        { name: 't0', value: { kind: 'load_param', name: p0 } },
        { name: 't1', value: { kind: 'load_param', name: p1 } },
        { name: 't2', value: { kind: 'bin_op', op: '===', left: 't0', right: 't1' } },
        { name: 't3', value: { kind: 'assert', value: 't2' } },
      ],
    },
  ],
});

interface Case {
  name: string;
  ir: Ir;
  error: string;
}

const EMPTY = (path: string): string => `IR validation: ${path} must be a non-empty string`;

const CASES: Case[] = [
  {
    name: 'contract-name-empty',
    ir: mutate((ir) => (ir.contractName = '')),
    error: EMPTY('contractName'),
  },
  {
    name: 'property-name-empty',
    ir: mutate((ir) => (ir.properties[0].name = '')),
    error: EMPTY('properties[0].name'),
  },
  {
    name: 'property-type-empty',
    ir: mutate((ir) => (ir.properties[0].type = '')),
    error: EMPTY('properties[0].type'),
  },
  {
    name: 'method-name-empty',
    ir: mutate((ir) => (ir.methods[0].name = '')),
    error: EMPTY('methods[0].name'),
  },
  {
    name: 'param-name-empty',
    ir: mutate((ir) => {
      ir.methods[0].params[0].name = '';
      ir.methods[0].body[0].value.name = '';
    }),
    error: EMPTY('methods[0].params[0].name'),
  },
  {
    name: 'param-type-empty',
    ir: mutate((ir) => (ir.methods[0].params[0].type = '')),
    error: EMPTY('methods[0].params[0].type'),
  },
  {
    name: 'params-duplicate',
    ir: mutate((ir) => ir.methods[0].params.push({ name: 'sig', type: 'Sig' })),
    error: "IR validation: methods[0].params[1].name 'sig' duplicates methods[0].params[0].name",
  },
  {
    // The brief's shape: two params both named '' — the empty rule fires on
    // the first one before the duplicate rule can.
    name: 'two-empty-params-equality',
    ir: equalityIr('', ''),
    error: EMPTY('methods[0].params[0].name'),
  },
  {
    name: 'duplicate-params-equality',
    ir: equalityIr('a', 'a'),
    error: "IR validation: methods[0].params[1].name 'a' duplicates methods[0].params[0].name",
  },
];

const DIR = mkdtempSync(join(tmpdir(), 'n207-ir-identifiers-'));
const write = (name: string, ir: unknown): string => {
  const p = join(DIR, `${name}.ir.json`);
  writeFileSync(p, JSON.stringify(ir));
  return p;
};
const CONTROL = write('control', REQUIRED.control);
const DISTINCT_EQUALITY = write('distinct-equality', equalityIr('a', 'b'));

const TIERS: Tier[] = buildIrTiers();
const available = TIERS.filter((t) => t.cmd !== null);

/** Consensus-rules spend of `lockingHex` by the push-only `unlockingHex`. */
function spends(lockingHex: string, unlockingHex: string): boolean {
  try {
    return newConsensusSpend({
      ...CONSENSUS_SPEND_CONTEXT,
      lockingScript: LockingScript.fromHex(lockingHex),
      unlockingScript: UnlockingScript.fromHex(unlockingHex),
      otherInputs: [],
      outputs: [],
    }).validate();
  } catch {
    return false;
  }
}

describe('N-207: --ir loaders refuse empty identifiers and duplicate param names (all 7 tiers)', () => {
  // -- the oracle: why a duplicate is a defect, not a style rule ------------

  it('the aliased-equality script (767c9c77) spends with UNEQUAL args; the distinct one (9c) does not', () => {
    // push 7, push 3: the two arguments differ.
    expect(spends('767c9c77', '5753')).toBe(true);
    expect(spends('9c', '5753')).toBe(false);
    expect(spends('9c', '5757')).toBe(true);
  });

  // -- vacuity guards --------------------------------------------------------

  it('every case differs from the control and carries an "IR validation:" diagnostic', () => {
    const control = JSON.stringify(REQUIRED.control);
    expect(CASES.length).toBeGreaterThanOrEqual(9);
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

  // -- TypeScript loader, in process ----------------------------------------

  it('ts loads the control and the distinct-name equality IR', () => {
    expect(() => loadANFFromJSON(JSON.stringify(REQUIRED.control))).not.toThrow();
    expect(() => loadANFFromJSON(JSON.stringify(equalityIr('a', 'b')))).not.toThrow();
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

  // -- the seven --ir CLIs ----------------------------------------------------

  for (const tier of available) {
    it(`${tier.id} ACCEPTS the control and the distinct-name equality IR`, () => {
      expect(judge(tier, CONTROL).verdict).toBe('accepted');
      expect(judge(tier, DISTINCT_EQUALITY).verdict).toBe('accepted');
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
