import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadANFFromJSON } from '../../packages/runar-compiler/src/index.js';
import { IR_TIER_IDS, Tier, buildIrTiers, judge } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-094 -- every tier's `--ir` loader refuses a `method_call` whose target is
 * a private method that EMITS OUTPUTS (`add_output` / `add_raw_output` /
 * `add_data_output`, at any depth of the helper's body) with ONE shared
 * diagnostic naming the helper:
 *   IR validation: private method '<m>' emits outputs and must be inlined;
 *   --ir method_call to it is not supported
 *
 * The defect: the frontends always inline output-emitting private helpers, so
 * such a `method_call` only arrives through hand-written `--ir`. All seven
 * tiers then failed deep in stack lowering ("value '_codePart' not found on
 * stack", Zig `VariableNotFound`) -- a refusal, but an incidental one with no
 * actionable text. The fixture `n094-helper-mc-ir.json` is the F-096 probe: a
 * stateful `Helper` whose public `bump` calls the private `emit`, which holds
 * an `add_output`.
 *
 * Cases: the call at top level, inside an `if` arm, inside a `loop` body, and
 * a helper that emits through a nested `if` arm. The control (a private helper
 * that emits NO output) must be ACCEPTED by every tier, so each refusal is
 * discriminating.
 *
 * What this does NOT prove: that a public method called via `method_call` is
 * handled (out of scope), transitive emission through a helper that only calls
 * another emitting helper (that inner call is itself refused when the walk
 * reaches the helper's own body), or the stack-lowering behaviour behind it.
 */

type Binding = { name: string; value: Record<string, unknown> };
type Ir = {
  contractName: string;
  methods: Array<{ name: string; isPublic: boolean; body: Binding[] }>;
};

const PROBE = readFileSync(join(__dirname, 'n094-helper-mc-ir.json'), 'utf8');
const clone = (): Ir => JSON.parse(PROBE) as Ir;
const method = (ir: Ir, name: string) => ir.methods.find((m) => m.name === name)!;
const callBinding = (name: string): Binding => ({
  name,
  value: {
    kind: 'method_call',
    object: 't18self',
    method: 'emit',
    args: ['t16', 't17'],
  },
});
/** Replace the original call with a harmless constant, keeping the name t18 live. */
const neutraliseOriginal = (ir: Ir): void => {
  const b = method(ir, 'bump').body.find((x) => x.name === 't18')!;
  b.value = { kind: 'load_const', value: 0 };
};
const insertAfterT17 = (ir: Ir, b: Binding): void => {
  const body = method(ir, 'bump').body;
  body.splice(body.findIndex((x) => x.name === 't17') + 1, 0, b);
};

const topLevel = clone();

const inIf = clone();
neutraliseOriginal(inIf);
insertAfterT17(inIf, {
  name: 'nif',
  value: { kind: 'if', cond: 't12', then: [callBinding('nc')], else: [] },
});

const inLoop = clone();
neutraliseOriginal(inLoop);
insertAfterT17(inLoop, {
  name: 'nloop',
  value: {
    kind: 'loop',
    count: 2,
    start: 0,
    step: 1,
    iterVar: 'i',
    body: [callBinding('nc')],
  },
});

/** The helper itself emits only from inside an `if` arm. */
const helperEmitsInArm = clone();
{
  const emit = method(helperEmitsInArm, 'emit');
  const add = emit.body.find((b) => b.value.kind === 'add_output')!;
  emit.body = emit.body.filter((b) => b !== add);
  emit.body.push({
    name: 'tif',
    value: { kind: 'if', cond: 't0', then: [add], else: [] },
  });
}

/** Control: `emit` computes a sum and emits nothing. */
const control = clone();
{
  const emit = method(control, 'emit');
  emit.body = [
    { name: 't0', value: { kind: 'load_param', name: 'sats' } },
    { name: 't1', value: { kind: 'load_param', name: 'n' } },
    { name: 't2', value: { kind: 'bin_op', op: '+', left: 't1', right: 't0' } },
  ];
}

const MSG = (m: string): string =>
  `IR validation: private method '${m}' emits outputs and must be inlined; --ir method_call to it is not supported`;

interface Case {
  name: string;
  ir: Ir;
  error: string;
}
const CASES: Case[] = [
  { name: 'helper-call-top-level', ir: topLevel, error: MSG('emit') },
  { name: 'helper-call-in-if-arm', ir: inIf, error: MSG('emit') },
  { name: 'helper-call-in-loop-body', ir: inLoop, error: MSG('emit') },
  { name: 'helper-emits-in-if-arm', ir: helperEmitsInArm, error: MSG('emit') },
];

const DIR = mkdtempSync(join(tmpdir(), 'n094-ir-output-helper-'));
const write = (name: string, ir: unknown): string => {
  const p = join(DIR, `${name}.json`);
  writeFileSync(p, JSON.stringify(ir));
  return p;
};
const CONTROL = write('control', control);

const TIERS: Tier[] = buildIrTiers();
const available = TIERS.filter((t) => t.cmd !== null);

describe('N-094: --ir loaders refuse a method_call to an output-emitting private helper (all 7 tiers)', () => {
  it('every case differs from the control and carries an "IR validation:" diagnostic', () => {
    const c0 = JSON.stringify(control);
    for (const c of CASES) {
      expect(JSON.stringify(c.ir), c.name).not.toBe(c0);
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

  it('ts loads the control', () => {
    expect(() => loadANFFromJSON(JSON.stringify(control))).not.toThrow();
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
    it(`${tier.id} ACCEPTS the non-emitting-helper control`, () => {
      expect(judge(tier, CONTROL).verdict).toBe('accepted');
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
