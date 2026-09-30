import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import {
  CONSENSUS_SPEND_CONTEXT,
  newConsensusSpend,
} from '../../packages/runar-testing/src/consensus-spend.js';
import { compileFromANF, loadANFFromJSON } from '../../packages/runar-compiler/src/index.js';
import {
  BrokenTier,
  IR_TIER_IDS,
  Tier,
  buildIrTiers,
  compileHex,
  verdict,
} from './tier-harness.js';

/**
 * N-071 — on the `--ir` path every public method must END with an assert, in
 * all seven tiers, with ONE diagnostic.
 *
 * The defect: `--ir` skips the source validator, and stack lowering leaves the
 * value of a method's last binding as the script's result. So a public method
 * whose body was `[]`, or held no assert, or kept a binding after its last
 * assert, compiled at exit 0 in TS (compileFromANF), Rust, Java, Ruby and Zig.
 * `[]` became an EMPTY script (TS/Rust/Java/Ruby) or bare OP_1 (Zig), and an
 * `if` whose else arm ended in `load_const true` became a script that any
 * keyless witness spends (all checked below with `@bsv/sdk` `Spend.validate()`
 * under consensus rules). Only Go (F-004) and Python (F-014) refused.
 *
 * The rule is the source validator's `endsWithAssert` (02-validate.ts) on ANF:
 * the last binding is an `assert`, OR an `if` whose then AND else arms both end
 * that way; a terminal `raw_script` with out_arity 1 (the UnsafeSmartContract
 * `asm()` terminal) is also accepted, because ANF carries no parentClass. The
 * diagnostic is Go's F-004 sentence, which embeds the source rule's
 * "public method '<name>' must end with an assert() call".
 *
 * The corpus (`ir-terminal-assert-cases.json`) is the N-069 P2PK control with
 * ONE method body changed per case. `accept` holds the control and a both-arm
 * `if` program; all seven tiers must compile each to the SAME bytes.
 *
 * What this does NOT prove: that the accepted programs are secure — ending in
 * an assert is necessary, not sufficient — or anything about the source path,
 * which rejection-parity.test.ts covers.
 */

interface Case {
  name: string;
  ir: unknown;
  error: string;
}
const CORPUS = JSON.parse(
  readFileSync(join(__dirname, 'ir-terminal-assert-cases.json'), 'utf8'),
) as { error: string; accept: Array<{ name: string; ir: unknown }>; cases: Case[] };

const DIR = mkdtempSync(join(tmpdir(), 'n071-ir-terminal-assert-'));
const write = (name: string, ir: unknown): string => {
  const p = join(DIR, `${name}.ir.json`);
  writeFileSync(p, JSON.stringify(ir));
  return p;
};

const TIERS: Tier[] = buildIrTiers();
const available = TIERS.filter((t) => t.cmd !== null);

/** A push of the secp256k1 generator as a compressed key: a real pubkey to
 *  bake over the `00` constructor placeholders the --ir outputs carry. */
const PK = '210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

/** Keyless, push-only witnesses: consensus Spend requires push-only unlocks. */
const KEYLESS_WITNESSES = ['', '00', '51', '5151'];

/** True if some keyless witness spends `lockingHex` under consensus rules. */
function anyoneCanSpend(lockingHex: string): boolean {
  for (const witness of KEYLESS_WITNESSES) {
    try {
      const spend = newConsensusSpend({
        ...CONSENSUS_SPEND_CONTEXT,
        lockingScript: LockingScript.fromHex(lockingHex),
        unlockingScript: UnlockingScript.fromHex(witness),
        otherInputs: [],
        outputs: [],
      });
      if (spend.validate()) return true;
    } catch {
      // A thrown validation error is a failed spend.
    }
  }
  return false;
}

/** Run a tier's `--ir` CLI; no interpretation beyond "it ran to completion". */
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

const tsHex = (ir: unknown): string =>
  compileFromANF(loadANFFromJSON(JSON.stringify(ir)), { disableConstantFolding: true })
    .scriptHex.toLowerCase();

describe('N-071: --ir public methods must end with an assert (all 7 tiers)', () => {
  // -- the oracle's own contract --------------------------------------------

  it('the oracle sees the pre-fix outputs as anyone-can-spend', () => {
    expect(anyoneCanSpend('')).toBe(true); // body [] in ts/rust/java/ruby
    expect(anyoneCanSpend('51')).toBe(true); // body [] in zig
    // if-else-arm-without-assert in ts/rust/zig/ruby/java emitted
    // `00ac76637677750067517768`; with the `pk` placeholder (00) replaced by a
    // real key, the else arm's `load_const true` is the script's result
    // whenever checkSig FAILS, so an empty signature spends it.
    expect(anyoneCanSpend(`${PK}ac76637677750067517768`)).toBe(true);
  });

  it('the oracle does NOT flag the accepted programs, which need a signature', () => {
    expect(anyoneCanSpend(`${PK}ac`)).toBe(false);
    expect(anyoneCanSpend(`767600877c51879b69637c${PK}ac7767${PK}ac7768`)).toBe(false);
  });

  // -- vacuity guards --------------------------------------------------------

  it('the corpus is non-empty and every case differs from every accepted program', () => {
    expect(CORPUS.cases.length).toBeGreaterThanOrEqual(5);
    expect(CORPUS.accept.length).toBeGreaterThanOrEqual(2);
    const accepted = CORPUS.accept.map((a) => JSON.stringify(a.ir));
    for (const c of CORPUS.cases) {
      expect(accepted, c.name).not.toContain(JSON.stringify(c.ir));
      expect(c.error, c.name).toBe(CORPUS.error);
    }
    expect(CORPUS.error).toContain("public method 'unlock' must end with an assert() call");
  });

  it('the matrix names all six IR-capable CLI tiers', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...IR_TIER_IDS].sort());
  });

  it('every IR-capable tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (process.env.CI === 'true') expect(missing).toEqual([]);
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  // -- accepted programs: byte-identical in all seven tiers -------------------

  for (const a of CORPUS.accept) {
    it(`all tiers compile ${a.name} to the same bytes`, () => {
      const input = write(a.name, a.ir);
      const want = tsHex(a.ir);
      expect(want).not.toBe('');
      for (const tier of available) {
        expect(compileHex(tier, input), `${tier.id} vs ts on ${a.name}`).toBe(want);
      }
    });
  }

  // -- TypeScript: in process (the reference tier has no --ir CLI tier here) --

  for (const c of CORPUS.cases) {
    it(`ts refuses ${c.name} with the shared diagnostic`, () => {
      let message = '<accepted>';
      try {
        tsHex(c.ir);
      } catch (e) {
        message = (e as Error).message;
      }
      expect(message).toBe(c.error);
    });
  }

  // -- the six --ir CLIs -------------------------------------------------------

  for (const tier of available) {
    it(`${tier.id} ACCEPTS the control (else its refusals are vacuous)`, () => {
      expect(verdict(tier, write('control', CORPUS.accept[0]!.ir))).toBe('accepted');
    });

    for (const c of CORPUS.cases) {
      it(`${tier.id} refuses ${c.name} with the shared diagnostic`, () => {
        const input = write(c.name, c.ir);
        const { status, out, diag } = runIr(tier, input);
        expect(status, `${tier.id} accepted ${c.name} (emitted "${out}")`).not.toBe(0);
        expect(diag).toContain(c.error);
      });
    }
  }
});
