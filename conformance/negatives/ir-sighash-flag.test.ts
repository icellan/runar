import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compileFromANF, loadANFFromJSON } from '../../packages/runar-compiler/src/index.js';
import { BrokenTier, IR_TIER_IDS, REPO, Tier, buildIrTiers, verdict } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-059 / F-102 — `check_preimage.sighashFlag` on the `--ir` path, all 7 tiers.
 *
 * The flag is appended as `sighashFlag & 0xff` to the OP_PUSH_TX binding. Go's
 * loader refused anything outside the `@sighash` set since F-068; the other
 * six took any integer and truncated it, at exit 0:
 *
 *   999999 -> 01 3f 7e   (FORKID clear: no BSV spend can satisfy the covenant)
 *   -5     -> 01 fb 7e
 *   511    -> 01 ff 7e
 *   0      -> 01 00 7e   (explicit 0; TS/Rust/Python/Ruby/Java — Zig and Go
 *                          read it as the default)
 *
 * and every tier, Go included, let a method's script flag diverge from the
 * `sigHashType` its ABI declares (F-102): `sighashFlag: 195` with no
 * `sigHashType` binds SINGLE|ANYONECANPAY|FORKID while the artifact tells the
 * SDK to sign ALL|FORKID, so the SDK's preimage never satisfies the script.
 *
 * Every case is a checked-in golden (`stateful-counter`, or the nested control
 * below) with ONE field changed, so each refusal is graded against a control
 * the same tier is first observed accepting. Like `ir-required-fields.test.ts`
 * this file grades the exact diagnostic: the item is one shared rule with one
 * shared message, and a refusal for an unrelated reason does not count.
 *
 * Proves: every tier refuses the out-of-set, explicit-0 and mismatched flags,
 * at the top level and inside an `if` arm and a `loop` body, with the shared
 * diagnostic; every tier accepts the six valid flags (with the matching
 * `sigHashType`) and an absent flag, and all seven emit the same bytes for
 * them, with the flag byte in the binding.
 * Does not prove: that a valid flag's binding verifies on chain (the #123
 * sighash execution tests do); that a private helper's check_preimage matches
 * the public caller it is inlined into (the rule is per method).
 */

const GOLDEN = join(REPO, 'conformance/tests/stateful-counter/expected-ir.json');
const GOLDEN_HEX = readFileSync(
  join(REPO, 'conformance/tests/stateful-counter/expected-script.hex'),
  'utf8',
).trim();
const IR_DIR = join(__dirname, 'ir');

const VALID = [0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3];

const badFlag = (method: string, binding: string, flag: number): string =>
  `IR validation: method ${method} binding ${binding} check_preimage has sighashFlag ${flag}; ` +
  'sighashFlag must be one of {0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3} (ALL/NONE/SINGLE with FORKID, ' +
  'optionally ANYONECANPAY). Any other value is truncated to a sighash byte no BSV spend can satisfy.';

const mismatch = (method: string, binding: string, flag: number, declared: number): string =>
  `IR validation: method ${method} binding ${binding} check_preimage has sighashFlag ${flag} ` +
  `but the method declares sigHashType ${declared}; a public method's check_preimage must bind ` +
  'the sighash type its ABI declares, or the SDK signs a preimage the script rejects.';

type Json = Record<string, any>;

/** stateful-counter's golden with `increment` (methods[1]) edited. */
function counter(edit: (method: Json, checkPreimage: Json) => void): Json {
  const ir = JSON.parse(readFileSync(GOLDEN, 'utf8')) as Json;
  const method = ir.methods[1];
  const cp = method.body[1].value;
  if (method.name !== 'increment' || cp.kind !== 'check_preimage') {
    throw new Error('stateful-counter golden no longer has increment.t1 = check_preimage');
  }
  edit(method, cp);
  return ir;
}

/**
 * N-038: a SIGHASH_SINGLE stateful continuation commits only the same-index
 * output, so it carries no change segment and no `_changePKH` /
 * `_changeAmount`. stateful-counter's change-carrying continuation is
 * therefore not a valid SINGLE program; the SINGLE-base controls are the
 * N-038 contract's `bump` (methods[1]) instead, from the gated sdk-call IR pin
 * conformance/sdk-call/expected-ir.json — same body layout (t1 =
 * check_preimage, t5 = the pinned sighash-type constant).
 */
const SINGLE_GOLDEN = join(REPO, 'conformance/sdk-call/expected-ir.json');
function single(edit: (method: Json, checkPreimage: Json) => void): Json {
  const ir = JSON.parse(readFileSync(SINGLE_GOLDEN, 'utf8')) as Json;
  const method = ir.methods[1];
  const cp = method.body[1].value;
  if (method.name !== 'bump' || cp.kind !== 'check_preimage') {
    throw new Error('conformance/sdk-call/expected-ir.json no longer has bump.t1 = check_preimage');
  }
  edit(method, cp);
  return ir;
}

/**
 * The nested control: a check_preimage inside an `if` arm or a `loop` body.
 * No golden nests one, so this is the smallest program all six CLIs accept
 * (asserted below before any of its negatives is graded).
 */
function nested(wrap: 'if' | 'loop', flag?: number): Json {
  const cp: Json = { kind: 'check_preimage', preimage: 't0' };
  if (flag !== undefined) cp.sighashFlag = flag;
  const inner = [
    { name: 't3', value: cp },
    { name: 't4', value: { kind: 'assert', value: 't3' } },
  ];
  const block =
    wrap === 'if'
      ? { kind: 'if', cond: 't1', then: inner, else: [] }
      : { kind: 'loop', count: 1, start: 0, step: 1, iterVar: 'i', body: inner };
  return {
    contractName: 'SighashNested',
    parentClass: 'SmartContract',
    properties: [],
    methods: [
      { name: 'constructor', isPublic: false, params: [], body: [] },
      {
        name: 'unlock',
        isPublic: true,
        params: [{ name: 'txPreimage', type: 'SigHashPreimage' }],
        body: [
          { name: 't0', value: { kind: 'load_param', name: 'txPreimage' } },
          { name: 't1', value: { kind: 'load_const', value: true } },
          { name: 't2', value: block },
          { name: 't5', value: { kind: 'load_const', value: true } },
          { name: 't6', value: { kind: 'assert', value: 't5' } },
        ],
      },
    ],
  };
}

const fixture = (name: string): Json =>
  JSON.parse(readFileSync(join(IR_DIR, name), 'utf8')) as Json;

interface Case {
  name: string;
  ir: Json;
  error: string;
}

const REFUSED: Case[] = [
  // The four checked-in I-fixtures (also graded by ir-rejection-parity).
  { name: 'I43 flag 999999', ir: fixture('I43-check-preimage-sighash-flag-999999.ir.json'), error: badFlag('increment', 't1', 999999) },
  { name: 'I44 flag 0x3f', ir: fixture('I44-check-preimage-sighash-flag-0x3f.ir.json'), error: badFlag('increment', 't1', 63) },
  { name: 'I45 explicit flag 0', ir: fixture('I45-check-preimage-sighash-flag-zero.ir.json'), error: badFlag('increment', 't1', 0) },
  { name: 'I46 flag 0xc3, sigHashType absent', ir: fixture('I46-check-preimage-flag-vs-sighashtype.ir.json'), error: mismatch('increment', 't1', 195, 65) },
  // Truncation shapes Go's F-068 test pins.
  { name: 'flag -5', ir: counter((_, cp) => { cp.sighashFlag = -5; }), error: badFlag('increment', 't1', -5) },
  { name: 'flag 511', ir: counter((_, cp) => { cp.sighashFlag = 511; }), error: badFlag('increment', 't1', 511) },
  { name: 'flag 256', ir: counter((_, cp) => { cp.sighashFlag = 256; }), error: badFlag('increment', 't1', 256) },
  { name: 'flag 0x01 (ALL, no FORKID)', ir: counter((_, cp) => { cp.sighashFlag = 1; }), error: badFlag('increment', 't1', 1) },
  // An out-of-set flag is refused as such even when sigHashType agrees on its low byte.
  { name: 'flag 449 (0x1c1), sigHashType 0xc1', ir: counter((m, cp) => { cp.sighashFlag = 449; m.sigHashType = 0xc1; }), error: badFlag('increment', 't1', 449) },
  // The reverse divergence: the ABI declares a mode the script never binds.
  { name: 'sigHashType 0xc3, flag absent', ir: counter((m) => { m.sigHashType = 0xc3; }), error: mismatch('increment', 't1', 65, 195) },
  { name: 'sigHashType 0x42, flag 0x43', ir: counter((m, cp) => { m.sigHashType = 0x42; cp.sighashFlag = 0x43; }), error: mismatch('increment', 't1', 67, 66) },
  // Nested: an if arm and a loop body are still bindings of the method.
  { name: 'if arm, flag 999999', ir: nested('if', 999999), error: badFlag('unlock', 't3', 999999) },
  { name: 'loop body, flag 999999', ir: nested('loop', 999999), error: badFlag('unlock', 't3', 999999) },
  { name: 'if arm, flag 0xc1, sigHashType absent', ir: nested('if', 0xc1), error: mismatch('unlock', 't3', 193, 65) },
  { name: 'loop body, flag 0x43, sigHashType absent', ir: nested('loop', 0x43), error: mismatch('unlock', 't3', 67, 65) },
];

const ACCEPTED: Array<{ name: string; ir: Json; flag: number }> = [
  { name: 'flag absent (golden)', ir: counter(() => {}), flag: 0x41 },
  ...VALID.map((f) => ({
    name: `flag 0x${f.toString(16)} with sigHashType 0x${f.toString(16)}`,
    // N-101: the auto-injected sighash-type assert (increment.t5) pins the
    // declared mode too, as the frontend emits it for `@sighash`.
    ir: ((f & 0x1f) === 0x03 ? single : counter)((m, cp) => {
      const from = m.sigHashType ?? 0x41;
      cp.sighashFlag = f;
      m.sigHashType = f;
      const pinned = m.body[5].value;
      if (pinned.kind !== 'load_const' || pinned.value !== from) {
        throw new Error(`${m.name}.t5 is no longer load_const ${from}`);
      }
      pinned.value = f;
    }),
    flag: f,
  })),
];

const DIR = mkdtempSync(join(tmpdir(), 'n059-ir-sighash-'));
const write = (name: string, ir: Json): string => {
  const p = join(DIR, `${name.replace(/[^A-Za-z0-9]+/g, '-')}.ir.json`);
  writeFileSync(p, JSON.stringify(ir));
  return p;
};

const TIERS: Tier[] = buildIrTiers();
const available = TIERS.filter((t) => t.cmd !== null);

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
  return {
    status: res.status,
    out: (res.stdout ?? '').trim(),
    diag: `${res.stderr ?? ''}\n${res.stdout ?? ''}`,
  };
}

const tsHex = (ir: Json): string => compileFromANF(loadANFFromJSON(JSON.stringify(ir))).scriptHex;
const binding = (flag: number): string => `01${flag.toString(16).padStart(2, '0')}7e`;

describe('N-059: --ir check_preimage sighashFlag is in the @sighash set and matches sigHashType (7 tiers)', () => {
  it('the matrix names all six IR-capable CLI tiers', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...IR_TIER_IDS].sort());
  });

  it('every IR-capable tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (isCiEnv(process.env)) expect(missing).toEqual([]);
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  // -- TypeScript, in process -------------------------------------------------

  it('ts emits the golden bytes for the unedited control', () => {
    expect(tsHex(ACCEPTED[0]!.ir)).toBe(GOLDEN_HEX);
  });

  for (const wrap of ['if', 'loop'] as const) {
    it(`ts accepts the nested ${wrap} control`, () => {
      expect(() => tsHex(nested(wrap))).not.toThrow();
    });
  }

  for (const a of ACCEPTED) {
    it(`ts accepts ${a.name} and binds 0x${a.flag.toString(16)}`, () => {
      expect(tsHex(a.ir)).toContain(binding(a.flag));
    });
  }

  for (const c of REFUSED) {
    it(`ts refuses ${c.name}`, () => {
      let message = '<accepted>';
      try {
        loadANFFromJSON(JSON.stringify(c.ir));
      } catch (e) {
        message = (e as Error).message;
      }
      expect(message).toBe(c.error);
    });
  }

  // -- the six --ir CLIs --------------------------------------------------------

  for (const tier of available) {
    for (const wrap of ['if', 'loop'] as const) {
      it(`${tier.id} ACCEPTS the nested ${wrap} control (else its nested refusals are vacuous)`, () => {
        expect(verdict(tier, write(`nested-${wrap}-control`, nested(wrap)))).toBe('accepted');
      });
    }

    for (const a of ACCEPTED) {
      it(`${tier.id} accepts ${a.name} with the TS bytes`, () => {
        const { status, out, diag } = runIr(tier, write(`ok-${a.name}`, a.ir));
        expect(status, diag).toBe(0);
        expect(out).toBe(tsHex(a.ir));
      });
    }

    for (const c of REFUSED) {
      it(`${tier.id} refuses ${c.name} with the shared diagnostic`, () => {
        const { status, out, diag } = runIr(tier, write(`bad-${c.name}`, c.ir));
        expect(status, `${tier.id} accepted ${c.name} (emitted "${out.slice(0, 80)}...")`).not.toBe(0);
        expect(diag).toContain(c.error);
      });
    }
  }
});
