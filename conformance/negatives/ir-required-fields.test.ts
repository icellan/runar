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
import { loadANFFromJSON } from '../../packages/runar-compiler/src/index.js';
import { BrokenTier, IR_TIER_IDS, Tier, buildIrTiers, verdict } from './tier-harness.js';

/**
 * N-069 — required ANF IR fields, checked for presence AND JSON type, with ONE
 * diagnostic across all seven tiers.
 *
 * The defect: a public method whose `body` was simply left out loaded as a
 * method with zero bindings. Zig then exited 0 printing `51` (bare OP_TRUE) and
 * Ruby exited 0 printing an EMPTY locking script — both spendable with no key
 * (checked below by `@bsv/sdk` `Spend.validate()` under consensus rules). The
 * input that produced them is the F-084 P2PK control with that one key
 * deleted, so the checkSig the author wrote simply vanished. A wrongly typed
 * required field (`body: "not-an-array"`, `params: {}`) aborted Zig with a
 * union-access panic and surfaced as a raw runtime error in Python, Ruby and
 * TS, while TS accepted a method with no `name` at all.
 *
 * Java fixed its loader in F-084. This file holds every tier to the same rule
 * and the same words: `IR validation: required field <path> is missing` /
 * `IR validation: <path> must be <a type>, got <json type>`. The corpus
 * (`ir-required-fields-cases.json`) is the control with ONE field removed or
 * retyped per case; `error` is the exact diagnostic.
 *
 * Unlike `ir-rejection-parity.test.ts` this file DOES grade prose, and that is
 * deliberate: the item is "one shared diagnostic naming the field path", so a
 * refusal for some unrelated reason (the far-downstream "must end with an
 * assert" rule is what refused `body` omitted in Go and Python) does not count.
 *
 * What this does NOT prove: full JSON-schema conformance. Optional fields the
 * loaders default on purpose (`loop.start`/`step`, `add_output.preimage`,
 * `sourceLoc`, `initialValue`) are not required, and value-level rules (loop
 * count range, raw_script hex, arity) are other files' business. It also does
 * not close the explicit `"body": []` shape — that is the terminal-assert rule,
 * not a missing field.
 */

interface Case {
  name: string;
  ir: unknown;
  error: string;
}
const CORPUS = JSON.parse(
  readFileSync(join(__dirname, 'ir-required-fields-cases.json'), 'utf8'),
) as { control: unknown; cases: Case[] };

const DIR = mkdtempSync(join(tmpdir(), 'n069-ir-required-'));
const write = (name: string, ir: unknown): string => {
  const p = join(DIR, `${name}.ir.json`);
  writeFileSync(p, JSON.stringify(ir));
  return p;
};
const CONTROL = write('control', CORPUS.control);

const TIERS: Tier[] = buildIrTiers();
const available = TIERS.filter((t) => t.cmd !== null);

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

describe('N-069: --ir required fields are present and correctly typed (all 7 tiers)', () => {
  // -- the oracle's own contract --------------------------------------------

  it('the oracle sees the two pre-fix outputs (empty, bare OP_1) as anyone-can-spend', () => {
    expect(anyoneCanSpend('')).toBe(true); // ruby, body omitted
    expect(anyoneCanSpend('51')).toBe(true); // zig, body omitted
  });

  it('the oracle does NOT flag the control script, which needs a signature', () => {
    expect(anyoneCanSpend('00ac')).toBe(false);
    expect(anyoneCanSpend(`76a914${'00'.repeat(20)}88ac`)).toBe(false);
  });

  // -- vacuity guards --------------------------------------------------------

  it('the corpus is non-empty and every case differs from the control', () => {
    expect(CORPUS.cases.length).toBeGreaterThanOrEqual(20);
    const control = JSON.stringify(CORPUS.control);
    for (const c of CORPUS.cases) {
      expect(JSON.stringify(c.ir), c.name).not.toBe(control);
      expect(c.error, c.name).toMatch(/^IR validation: /);
    }
  });

  it('the matrix names all six IR-capable CLI tiers', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...IR_TIER_IDS].sort());
  });

  it('every IR-capable tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (process.env.CI === 'true') expect(missing).toEqual([]);
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  // -- TypeScript: in process (the reference tier has no --ir CLI tier here) --

  it('ts loads the control', () => {
    expect(() => loadANFFromJSON(JSON.stringify(CORPUS.control))).not.toThrow();
  });

  for (const c of CORPUS.cases) {
    it(`ts refuses ${c.name} with "${c.error}"`, () => {
      let message = '<accepted>';
      try {
        loadANFFromJSON(JSON.stringify(c.ir));
      } catch (e) {
        message = (e as Error).message;
      }
      expect(message).toBe(c.error);
    });
  }

  // -- the six --ir CLIs -------------------------------------------------------

  for (const tier of available) {
    it(`${tier.id} ACCEPTS the control (else its refusals are vacuous)`, () => {
      expect(verdict(tier, CONTROL)).toBe('accepted');
    });

    for (const c of CORPUS.cases) {
      it(`${tier.id} refuses ${c.name} with the shared diagnostic`, () => {
        const input = write(c.name, c.ir);
        const { status, out, diag } = runIr(tier, input);
        if (status === 0) {
          expect(
            anyoneCanSpend(out),
            `${tier.id} exited 0 for ${c.name} and emitted "${out}", which a keyless ` +
              `witness spends under consensus rules`,
          ).toBe(false);
        }
        expect(status, `${tier.id} accepted ${c.name} (emitted "${out}")`).not.toBe(0);
        expect(diag).toContain(c.error);
      });
    }
  }
});
