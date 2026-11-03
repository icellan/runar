import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compileFromANF, loadANFFromJSON } from '../../packages/runar-compiler/src/index.js';
import { IR_TIER_IDS, Tier, buildIrTiers, judge } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-094 -- every tier's `--ir` path refuses a `method_call` whose target is
 * a private method that EMITS OUTPUTS (`add_output` / `add_raw_output` /
 * `add_data_output`, at any depth of the helper's body) with ONE shared
 * diagnostic, the one N-055 already pinned (there is no second sentence for
 * this condition; N-094-FU removed the duplicate check that preempted it):
 *   output intrinsics must be called from the public method or an inlined
 *   helper; --ir method_call delegation is not supported
 * It is raised by each tier's private-method inliner during stack lowering,
 * so the TS side is checked through `compileFromANF`, not the loader.
 *
 * The defect: the frontends always inline output-emitting private helpers, so
 * such a `method_call` only arrives through hand-written `--ir`. All seven
 * tiers then failed deep in stack lowering ("value '_codePart' not found on
 * stack", Zig `VariableNotFound`) -- a refusal, but an incidental one with no
 * actionable text (N-055 then gave it the shared sentence; this file extends
 * that pin to the call shapes N-055's corpus lacks).
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
 * It does not prove the refusal for add_raw_output / add_data_output helpers
 * in these shapes (N-055's own corpus covers those at top level only).
 */

type Binding = { name: string; value: Record<string, unknown> };
type Ir = {
  contractName: string;
  methods: Array<{ name: string; isPublic: boolean; body: Binding[] }>;
};

/**
 * The base program is N-055's well-scaffolded stateful `--ir` case: its public
 * `bump` carries the full StatefulSmartContract scaffolding, so the only thing
 * wrong with it is the `method_call` (binding `d2`) to the private `emit`,
 * which holds an `add_output`. (The fixture this file first used was NOT
 * scaffolded, so a scaffolding diagnostic could pre-empt the delegation one
 * and the shared sentence was never actually reached.)
 */
const PROBE = JSON.stringify(
  (
    JSON.parse(
      readFileSync(join(__dirname, 'n055-ir-output-delegation-cases.json'), 'utf8'),
    ) as { cases: Array<{ name: string; ir: unknown }> }
  ).cases.find((c) => c.name === 'add-output-delegated')!.ir,
);
const clone = (): Ir => JSON.parse(PROBE) as Ir;
const method = (ir: Ir, name: string) => ir.methods.find((m) => m.name === name)!;
const callBinding = (name: string): Binding => ({
  name,
  value: { kind: 'method_call', object: 'd1', method: 'emit', args: ['d0'] },
});
/** Replace the original call with a harmless constant, keeping the name d2 live. */
const neutraliseOriginal = (ir: Ir): void => {
  const b = method(ir, 'bump').body.find((x) => x.name === 'd2')!;
  b.value = { kind: 'load_const', value: 0 };
};
const insertAfterD2 = (ir: Ir, b: Binding): void => {
  const body = method(ir, 'bump').body;
  body.splice(body.findIndex((x) => x.name === 'd2') + 1, 0, b);
};

const topLevel = clone();

const inIf = clone();
neutraliseOriginal(inIf);
insertAfterD2(inIf, {
  name: 'nif',
  value: { kind: 'if', cond: 't6', then: [callBinding('nc')], else: [] },
});

const inLoop = clone();
neutraliseOriginal(inLoop);
insertAfterD2(inLoop, {
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
    value: { kind: 'if', cond: 'sat', then: [add], else: [] },
  });
}

/** Control: `emit` computes a value and emits nothing. */
const control = clone();
{
  const emit = method(control, 'emit');
  emit.body = [{ name: 't0', value: { kind: 'load_param', name: 'sat' } }];
}

const MSG = (_m: string): string =>
  'output intrinsics must be called from the public method or an inlined helper; --ir method_call delegation is not supported';

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
  it('every case differs from the control', () => {
    const c0 = JSON.stringify(control);
    for (const c of CASES) {
      expect(JSON.stringify(c.ir), c.name).not.toBe(c0);
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

  it('ts loads and compiles the control', () => {
    expect(() =>
      compileFromANF(loadANFFromJSON(JSON.stringify(control)), { disableConstantFolding: true }),
    ).not.toThrow();
  });

  for (const c of CASES) {
    it(`ts refuses ${c.name} with "${c.error}"`, () => {
      let message = '<accepted>';
      try {
        compileFromANF(loadANFFromJSON(JSON.stringify(c.ir)), { disableConstantFolding: true });
      } catch (e) {
        message = (e as Error).message;
      }
      expect(message).toContain(c.error);
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
