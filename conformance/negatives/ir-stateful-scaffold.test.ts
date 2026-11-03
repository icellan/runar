import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LockingScript, PrivateKey, UnlockingScript } from '@bsv/sdk';
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
import { isCiEnv } from '../env.js';

/**
 * N-101 — on the `--ir` path, every public method of a StatefulSmartContract
 * program (declared, or inferred per N-087) must carry exactly the scaffolding
 * 04-anf-lower.ts injects, in all seven tiers, with ONE set of diagnostics.
 *
 * The defect: `--ir` skips the frontend, so the scaffolding is whatever the IR
 * says. F-107's attack body (`update_prop owner = x; assert(owner == x)`)
 * labelled StatefulSmartContract compiled to `76767b8777` in all seven tiers,
 * and the same body with no parentClass plus a dead `add_data_output` (which
 * N-087 infers to be StatefulSmartContract) compiled to the script pinned
 * below. The ATTACKER's key spends both under consensus `Spend` (checked
 * below).
 *
 * The rule (user decision R43): per public method, re-derive the scaffolding
 * the frontend would inject — the auto-injected parameters, the
 * checkPreimage / sighash-type / deserialize_state prologue and, when the
 * method mutates state or declares outputs, the state continuation over every
 * output in order — and refuse the program, naming the method and the first
 * divergence, when it is missing, reordered or different. User code between
 * prologue and continuation stays free. The corpus is
 * `ir-stateful-scaffold-cases.json`; every case is matched exactly.
 *
 * What this does NOT prove: anything about the user code, which can still say
 * whatever a source contract could; that every golden still compiles through
 * `--ir` (the --ir-parity / --ir-roundtrip runner modes do).
 */

interface Case {
  name: string;
  ir: unknown;
  error: string;
}
const CORPUS = JSON.parse(
  readFileSync(join(__dirname, 'ir-stateful-scaffold-cases.json'), 'utf8'),
) as { accept: Array<{ name: string; ir: unknown }>; cases: Case[] };

const DIR = mkdtempSync(join(tmpdir(), 'n101-ir-stateful-scaffold-'));
const write = (name: string, ir: unknown): string => {
  const p = join(DIR, `${name}.ir.json`);
  writeFileSync(p, JSON.stringify(ir));
  return p;
};

const TIERS: Tier[] = buildIrTiers();
const available = TIERS.filter((t) => t.cmd !== null);

const push = (hex: string): string => (hex.length / 2).toString(16).padStart(2, '0') + hex;
const ATTACKER_PUB = Buffer.from(PrivateKey.fromHex('22'.repeat(32)).toPublicKey().encode(true)).toString('hex');

/** What all seven tiers emitted for the two attack programs before the fix. */
const PRE_FIX_SCRIPTS: Record<string, string> = {
  'hijack-declared-stateful': '76767b8777',
  'hijack-dead-data-output-no-parent-class':
    '0000827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e7c58807c7e7876537a877777',
};

/** Consensus `Spend.validate()` of `lockingHex` against the push-only `unlockingHex`. */
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

describe('N-101: --ir re-derives the StatefulSmartContract scaffolding (all 7 tiers)', () => {
  // -- the oracle's own contract --------------------------------------------

  for (const [name, hex] of Object.entries(PRE_FIX_SCRIPTS)) {
    it(`the pre-fix ${name} script is spent by the ATTACKER's key under consensus rules`, () => {
      expect(spends(hex, push(ATTACKER_PUB))).toBe(true);
    });
  }

  it('control: a real P2PK on a different key refuses the same witness', () => {
    const victimPub = Buffer.from(PrivateKey.fromHex('11'.repeat(32)).toPublicKey().encode(true)).toString('hex');
    expect(spends(`${push(victimPub)}ac`, push(ATTACKER_PUB))).toBe(false);
  });

  // -- vacuity guards --------------------------------------------------------

  it('the corpus is non-empty, holds both attacks and every case differs from every accepted program', () => {
    expect(CORPUS.cases.length).toBeGreaterThanOrEqual(10);
    expect(CORPUS.accept.length).toBeGreaterThanOrEqual(3);
    const accepted = CORPUS.accept.map((a) => JSON.stringify(a.ir));
    for (const c of CORPUS.cases) expect(accepted, c.name).not.toContain(JSON.stringify(c.ir));
    for (const name of Object.keys(PRE_FIX_SCRIPTS)) {
      expect(CORPUS.cases.map((c) => c.name)).toContain(name);
    }
  });

  it('the matrix names all six IR-capable CLI tiers', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...IR_TIER_IDS].sort());
  });

  it('every IR-capable tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (isCiEnv(process.env)) expect(missing).toEqual([]);
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

  // -- TypeScript: in process -------------------------------------------------

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
