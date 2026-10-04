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
  REPO,
  Tier,
  buildIrTiers,
  compileHex,
  verdict,
} from './tier-harness.js';

/**
 * N-087 — on the `--ir` path the source validator's parentClass rules, and
 * Go F-004's readonly / undeclared-property write rule, hold in all seven
 * tiers with ONE set of diagnostics.
 *
 * The defect: `--ir` skips validate and typecheck. F-107's v2-mut-stateless
 * declares a SmartContract property `owner` with `readonly: false`, which the
 * source validator refuses ("Property 'owner' in SmartContract must be
 * readonly"). On `--ir` the property got no constructor slot, and
 * `update_prop owner = x; assert(owner == x)` compiled to `76767b8777` in all
 * seven tiers — a script the ATTACKER's key spends under consensus `Spend`
 * (checked below). TS, Ruby, Zig and Java also compiled a write to a readonly
 * property; a stateful-only node outside StatefulSmartContract and a
 * raw_script outside UnsafeSmartContract compiled everywhere.
 *
 * The rules, in order: (1) SmartContract / UnsafeSmartContract properties must
 * be readonly; (2) add_output / add_raw_output / add_data_output /
 * get_state_script / deserialize_state require StatefulSmartContract; (3)
 * raw_script requires UnsafeSmartContract; (4) no update_prop outside the
 * constructor on a readonly or undeclared property. IR with no parentClass
 * (written before F-038) is inferred fail-closed: StatefulSmartContract only
 * from a stateful-only node, else UnsafeSmartContract from a raw_script, else
 * SmartContract — so a mutable property with no stateful marker is refused.
 *
 * The corpus is `ir-parent-class-cases.json`. A case carrying
 * `"match": "prefix"` is a readonly write: Python's F-014 sentence names the
 * binding after the shared prefix; every other case is matched exactly.
 *
 * What this does NOT prove: that a DECLARED StatefulSmartContract body
 * enforces its state continuation. v2's body labelled StatefulSmartContract
 * still compiles to the same anyone-can-spend script — that direction is not
 * checked by these rules.
 */

interface Case {
  name: string;
  ir: unknown;
  error: string;
  match?: 'prefix';
}
const CORPUS = JSON.parse(
  readFileSync(join(__dirname, 'ir-parent-class-cases.json'), 'utf8'),
) as { accept: Array<{ name: string; ir: unknown }>; cases: Case[] };

const DIR = mkdtempSync(join(tmpdir(), 'n087-ir-parent-class-'));
const write = (name: string, ir: unknown): string => {
  const p = join(DIR, `${name}.ir.json`);
  writeFileSync(p, JSON.stringify(ir));
  return p;
};

const TIERS: Tier[] = buildIrTiers();
const available = TIERS.filter((t) => t.cmd !== null);

/** Goldens re-loaded WITHOUT parentClass: the inference must keep every one. */
const UNLABELLED_GOLDENS = ['basic-p2pkh', 'stateful-counter', 'token-ft', 'add-data-output', 'asm-raw-script'];

const unlabelled = (fixture: string): { ir: unknown; hex: string } => {
  const dir = join(REPO, 'conformance/tests', fixture);
  const ir = JSON.parse(readFileSync(join(dir, 'expected-ir.json'), 'utf8')) as Record<string, unknown>;
  delete ir.parentClass;
  return { ir, hex: readFileSync(join(dir, 'expected-script.hex'), 'utf8').trim().toLowerCase() };
};

const push = (hex: string): string => (hex.length / 2).toString(16).padStart(2, '0') + hex;
const ATTACKER_PUB = Buffer.from(PrivateKey.fromHex('22'.repeat(32)).toPublicKey().encode(true)).toString('hex');

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

const matches = (c: Case, message: string): boolean =>
  c.match === 'prefix' ? message.startsWith(c.error) : message === c.error;

describe('N-087: --ir parentClass and property-write rules (all 7 tiers)', () => {
  // -- the oracle's own contract --------------------------------------------

  it("the pre-fix v2 script is spent by the ATTACKER's key under consensus rules", () => {
    // 76767b8777 = DUP DUP ROT EQUAL NIP: whatever the spender pushes is both
    // the "owner" written by update_prop and the value compared against it.
    expect(spends('76767b8777', push(ATTACKER_PUB))).toBe(true);
    // Control: a real P2PK on a different key refuses the same witness.
    const victimPub = Buffer.from(PrivateKey.fromHex('11'.repeat(32)).toPublicKey().encode(true)).toString('hex');
    expect(spends(`${push(victimPub)}ac`, push(ATTACKER_PUB))).toBe(false);
  });

  // -- vacuity guards --------------------------------------------------------

  it('the corpus is non-empty and every case differs from every accepted program', () => {
    expect(CORPUS.cases.length).toBeGreaterThanOrEqual(10);
    expect(CORPUS.accept.length).toBeGreaterThanOrEqual(3);
    const accepted = CORPUS.accept.map((a) => JSON.stringify(a.ir));
    for (const c of CORPUS.cases) expect(accepted, c.name).not.toContain(JSON.stringify(c.ir));
    expect(CORPUS.cases.map((c) => c.name)).toContain('hijack-mutable-owner-smartcontract');
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

  for (const fixture of UNLABELLED_GOLDENS) {
    it(`all tiers compile the ${fixture} golden WITHOUT parentClass to its golden bytes`, () => {
      const { ir, hex } = unlabelled(fixture);
      expect(tsHex(ir)).toBe(hex);
      const input = write(`unlabelled-${fixture}`, ir);
      for (const tier of available) {
        expect(compileHex(tier, input), `${tier.id} on unlabelled ${fixture}`).toBe(hex);
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
      expect(matches(c, message), message).toBe(true);
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
