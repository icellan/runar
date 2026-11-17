import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compile, compileFromANF, loadANFFromJSON, lowerToANF } from '../../packages/runar-compiler/src/index.js';
import { parse } from '../../packages/runar-compiler/src/passes/01-parse.js';
import { BrokenTier, IR_TIER_IDS, REPO, Tier, buildIrTiers, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * D15 — the preimage rules on the `--ir` path, in all seven tiers.
 *
 * `--ir` skips validate and typecheck, so before this an ANF program carrying
 * a SigHashPreimage property (D9), an unchecked SigHashPreimage parameter
 * (GK-GAP-010), or an extractor reading a ByteString (D14) compiled in every
 * tier. Each tier's IR loader now re-derives the three rules from the ANF
 * (spec/type-system.md 4.3, "The IR path"), with the source path's shared
 * diagnostics.
 *
 * Refused programs are the TS lowerer's own output for sources the frontend
 * refuses (lowered without validate / typecheck), plus hand mutations of
 * accepted programs. Accepted programs are the frontend's output for every
 * accepted shape of conformance/negatives/preimage-checked-cases.json, plus
 * stateful goldens: every tier must compile them to the TS bytes.
 *
 * What this proves: every tier refuses each hostile IR with the shared
 * diagnostic and without crashing, and still compiles the frontend's own
 * output for every accepted preimage shape to the same bytes as TS.
 * What it does NOT prove: that the ANF must-analysis accepts every shape the
 * source compiler accepts (it fails closed on a check only in a loop body or a
 * multi-result `if`; no accepted corpus shape or golden hits that), or anything
 * about the source path (gk-frontend-parity.test.ts covers that).
 */

const D9 = (name: string): string =>
  `property '${name}' cannot hold a SigHashPreimage: a preimage stored in a property was fixed before ` +
  'the spending transaction existed, so it can never pass checkPreimage() and every field an extractor ' +
  'reads from it is unverified';
const GK010 = (method: string, param: string): string =>
  `public method '${method}' must assert checkPreimage(${param}) on every path`;
const D14 = (fn: string): string =>
  `${fn}() needs a checked SigHashPreimage: its argument must be a SigHashPreimage parameter ` +
  '(one a public method must assert with checkPreimage()) or the implicit txPreimage of a ' +
  'StatefulSmartContract; any other value is not bound to the spending transaction, so every ' +
  'field an extractor reads from it is unverified';

/** GK-BUG-015's shared text (duplicate-method-cases.json), now also on the IR path. */
const DUP = (name: string): string =>
  `method '${name}' is already declared in this contract and cannot be re-declared`;

type Binding = { name: string; value: Record<string, unknown> };
type Method = { name: string; params: Array<{ name: string; type: string }>; body: Binding[]; isPublic: boolean };
type Ir = { properties: Array<Record<string, unknown>>; methods: Method[]; [k: string]: unknown };

const toWire = (anf: unknown): Ir =>
  JSON.parse(
    JSON.stringify(anf, (k, v: unknown) => {
      if (k === 'sourceLoc') return undefined;
      if (typeof v === 'bigint') {
        if (v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(v);
        return `${v}n`;
      }
      return v;
    }),
  ) as Ir;
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const mutate = (base: Ir, fn: (ir: Ir) => void): Ir => {
  const ir = clone(base);
  fn(ir);
  return ir;
};
const method = (ir: Ir, name: string): Method => ir.methods.find((m) => m.name === name)!;

/** The frontend's own fold-OFF ANF for an accepted source. */
function irOf(source: string, fileName: string): Ir {
  const r = compile(source, { fileName, disableConstantFolding: true });
  if (!r.success || !r.anf) throw new Error(`${fileName}: ${r.diagnostics.map((d) => d.message).join('; ')}`);
  return toWire(r.anf);
}

/** The TS lowerer's ANF for a source the frontend REFUSES (no validate / typecheck). */
function loweredUnchecked(source: string, fileName: string): Ir {
  expect(compile(source, { fileName }).success, `${fileName} must be refused by the frontend`).toBe(false);
  const parsed = parse(source, fileName);
  if (parsed.errors.length > 0 || !parsed.contract) throw new Error(parsed.errors.map((e) => e.message).join('; '));
  return toWire(lowerToANF(parsed.contract));
}

const corpus = JSON.parse(readFileSync(join(__dirname, 'preimage-checked-cases.json'), 'utf8')) as {
  refuse: Array<{ name: string; file: string; src: string; error: string }>;
  accept: Array<{ name: string; file: string; src: string }>;
};
const refuseSrc = (name: string): { src: string; file: string } => corpus.refuse.find((c) => c.name === name)!;
const acceptSrc = (name: string): { src: string; file: string } => corpus.accept.find((c) => c.name === name)!;
const golden = (fixture: string): Ir =>
  JSON.parse(readFileSync(join(REPO, `conformance/tests/${fixture}/expected-ir.json`), 'utf8')) as Ir;

const ACCEPT: Array<{ name: string; ir: Ir }> = [
  ...corpus.accept.map((c) => ({ name: `corpus ${c.name}`, ir: irOf(c.src, c.file) })),
  { name: 'golden auction', ir: golden('auction') },
  { name: 'golden private-helper-outputs', ir: golden('private-helper-outputs') },
  {
    name: 'helper-extract-amount (stateful helper reads the implicit txPreimage)',
    ir: JSON.parse(
      readFileSync(join(REPO, 'conformance/anf-interpreter/programs/helper-extract-amount.anf.json'), 'utf8'),
    ) as Ir,
  },
];

const lowered = (name: string): Ir => {
  const c = refuseSrc(name);
  return loweredUnchecked(c.src, c.file);
};
const DIRECT = irOf(acceptSrc('direct').src, acceptSrc('direct').file);

const HELPER = irOf(acceptSrc('helper').src, acceptSrc('helper').file);
/** A second private `check` that asserts nothing, placed before or after the real one. */
const withUncheckedTwin = (before: boolean): Ir =>
  mutate(HELPER, (ir) => {
    const real = method(ir, 'check');
    const twin: Method = {
      ...clone(real),
      body: [
        { name: 'u0', value: { kind: 'load_const', value: true } },
        { name: 'u1', value: { kind: 'assert', value: 'u0' } },
      ],
    };
    const at = ir.methods.indexOf(real);
    ir.methods.splice(before ? at : at + 1, 0, twin);
  });

const CASES: Array<{ name: string; ir: Ir; error: string }> = [
  // A duplicated method name lets a name-keyed lookup or memo answer for the
  // wrong body (the checked twin vouching for the one stack lowering inlines).
  { name: 'dup-helper-unchecked-twin-after', ir: withUncheckedTwin(false), error: DUP('check') },
  { name: 'dup-helper-unchecked-twin-before', ir: withUncheckedTwin(true), error: DUP('check') },
  {
    name: 'dup-public-method',
    ir: mutate(DIRECT, (ir) => {
      const spend = method(ir, 'spend');
      ir.methods.push({ ...clone(spend), params: [], body: [
        { name: 'u0', value: { kind: 'load_const', value: true } },
        { name: 'u1', value: { kind: 'assert', value: 'u0' } },
      ] });
    }),
    error: DUP('spend'),
  },
  { name: 'd9-readonly-property', ir: lowered('readonly-property-checked'), error: D9('pre') },
  { name: 'd9-mutable-property', ir: lowered('mutable-property-only-state'), error: D9('pre') },
  { name: 'gk010-extract-only', ir: lowered('extract-only'), error: GK010('spend', 'txPreimage') },
  { name: 'gk010-if-one-arm', ir: lowered('if-one-arm'), error: GK010('spend', 'txPreimage') },
  { name: 'gk010-loop-body', ir: lowered('loop-body'), error: GK010('spend', 'txPreimage') },
  { name: 'gk010-helper-one-arm', ir: lowered('helper-one-arm'), error: GK010('spend', 'txPreimage') },
  { name: 'gk010-or-right-operand', ir: lowered('or-right-operand'), error: GK010('spend', 'txPreimage') },
  { name: 'gk010-discarded', ir: lowered('discarded'), error: GK010('spend', 'txPreimage') },
  { name: 'gk010-negated', ir: lowered('negated'), error: GK010('spend', 'txPreimage') },
  { name: 'd14-bytestring-param', ir: lowered('extractor-bytestring-param'), error: D14('extractAmount') },
  { name: 'd14-bytestring-param-checked', ir: lowered('extractor-bytestring-param-checked'), error: D14('extractAmount') },
  { name: 'd14-bytestring-property', ir: lowered('extractor-bytestring-property'), error: D14('extractLocktime') },
  { name: 'd14-local-laundering', ir: lowered('extractor-local-laundering'), error: D14('extractAmount') },
  { name: 'd14-helper-arg-laundering', ir: lowered('extractor-helper-arg-laundering'), error: D14('amount') },
  { name: 'd14-helper-bytestring-param', ir: lowered('extractor-helper-bytestring-param'), error: D14('extractAmount') },
  { name: 'd14-stateful-bytestring-param', ir: lowered('extractor-stateful-bytestring-param'), error: D14('extractAmount') },
  {
    // Hand-written IR: the checked parameter retyped ByteString. The check
    // still runs, but the extractor's argument is no SigHashPreimage parameter.
    name: 'd14-param-retyped-bytestring',
    ir: mutate(DIRECT, (ir) => {
      method(ir, 'spend').params.find((p) => p.name === 'txPreimage')!.type = 'ByteString';
    }),
    error: D14('extractAmount'),
  },
  {
    // The extractor's argument name bound twice: it no longer names one value.
    name: 'd14-extractor-arg-bound-twice',
    ir: mutate(DIRECT, (ir) => {
      const spend = method(ir, 'spend');
      const call = spend.body.find((b) => b.value.kind === 'call' && b.value.func === 'extractAmount')!;
      const arg = (call.value.args as string[])[0]!;
      const at = spend.body.findIndex((b) => b === call);
      spend.body.splice(at, 0, { name: arg, value: { kind: 'load_const', value: '00' } });
    }),
    error: D14('extractAmount'),
  },
];

const DIR = mkdtempSync(join(tmpdir(), 'd15-ir-preimage-'));
const write = (name: string, ir: unknown): string => {
  const p = join(DIR, `${name.replace(/[^a-z0-9]+/gi, '-')}.ir.json`);
  writeFileSync(p, JSON.stringify(ir));
  return p;
};

const TIERS: Tier[] = buildIrTiers();
const available = TIERS.filter((t) => t.cmd !== null);

const tsHex = (ir: unknown): string =>
  compileFromANF(loadANFFromJSON(JSON.stringify(ir)), { disableConstantFolding: true }).scriptHex.toLowerCase();

function runIr(tier: Tier, input: string): { status: number; out: string; diag: string } {
  if (tier.cmd === null) throw new BrokenTier(`${tier.id}: no toolchain`);
  const argv = [...tier.prefix, ...tier.argsFor(input)];
  const res = spawnSync(tier.cmd, argv, {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  const where = `${tier.id} (${tier.cmd} ${argv.join(' ')})`;
  if (res.error) throw new BrokenTier(`${where} could not run: ${res.error.message}`);
  if (res.signal !== null) throw new BrokenTier(`${where} killed by ${res.signal}`);
  if (res.status === null) throw new BrokenTier(`${where}: no exit status`);
  return { status: res.status, out: (res.stdout ?? '').trim(), diag: `${res.stderr ?? ''}\n${res.stdout ?? ''}` };
}

describe('D15: --ir preimage rules (D9, GK-GAP-010, D14) in all 7 tiers', () => {
  it('every case differs from every accepted program', () => {
    const accepted = ACCEPT.map((a) => JSON.stringify(a.ir));
    for (const c of CASES) expect(accepted, c.name).not.toContain(JSON.stringify(c.ir));
  });

  it('the matrix names all seven IR-capable tiers', () => {
    expect(TIERS.map((t) => t.id).sort()).toEqual([...IR_TIER_IDS].sort());
  });

  it('every IR-capable tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (isCiEnv(process.env)) expect(missing).toEqual([]);
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  it('the auction golden still compiles to its golden bytes on the IR path', () => {
    const hex = readFileSync(join(REPO, 'conformance/tests/auction/expected-script.hex'), 'utf8').trim().toLowerCase();
    expect(tsHex(golden('auction'))).toBe(hex);
  });

  for (const a of ACCEPT) {
    it(`all tiers compile ${a.name} to the same bytes as TS`, () => {
      const hex = tsHex(a.ir);
      const input = write(a.name, a.ir);
      for (const tier of available) {
        expect(compileHex(tier, input), `${tier.id} on ${a.name}`).toBe(hex);
      }
    });
  }

  for (const c of CASES) {
    it(`ts refuses ${c.name} with the shared diagnostic`, () => {
      let message = '<accepted>';
      try {
        tsHex(c.ir);
      } catch (e) {
        message = (e as Error).message;
      }
      expect(message).toContain(c.error);
    });
  }

  for (const tier of available) {
    for (const c of CASES) {
      it(`${tier.id} refuses ${c.name} with the shared diagnostic, without crashing`, () => {
        const { status, out, diag } = runIr(tier, write(c.name, c.ir));
        expect(status, `${tier.id} accepted ${c.name} (emitted "${out.slice(0, 80)}")`).not.toBe(0);
        expect(diag).not.toMatch(/panic|Traceback|Exception in thread|stack backtrace/);
        expect(diag).toContain(c.error);
      });
    }
  }
});
