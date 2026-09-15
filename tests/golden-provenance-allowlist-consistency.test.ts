/**
 * Every allowlist entry must still describe the file it pins.
 *
 * `check-golden-provenance.mjs` compares only the goldens changed in a PR.
 * That is the right scope for gating a change, but it means **nothing ever
 * asserts the allowlist still describes the tree**. An entry whose file has
 * since moved is never re-examined, so stale pins accumulate silently and the
 * file degrades from a record of what was reviewed into a list of things that
 * were reviewed once, at sizes nobody can recover.
 *
 * Measured when this guard was written: of 267 entries, 199 pins matched and
 * 68 did not — 65 of them against worktree bytes byte-identical to HEAD, i.e.
 * a commit regenerated the golden and did not re-pin its entry. Three
 * independent passes (a round-two review, an EC-sweep agent, and this
 * dispatcher) each found the same thing by different methods and disagreed
 * only on the count, because the tree moved between measurements.
 *
 * The pin is content-addressed and the gate rejects a mismatch, so the
 * direction is fail-safe — a stale pin blocks a PR rather than admitting bad
 * bytes. The cost is that the blocking happens later, to someone unrelated,
 * with no record of which change actually moved the file.
 *
 * RATCHET, not a threshold. `STALE_PIN_BUDGET` is asserted EXACTLY, so the
 * number cannot drift upward and every repair is a deliberate decrement. That
 * is the shape `MAX_UNEXECUTED_GOLDENS` uses in conformance/witnesses, chosen
 * over `<=` for the same reason: a bound that only ever has to be "not worse"
 * stops being read.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ALLOWLIST = join(ROOT, 'conformance', 'golden-provenance-allowlist.json');

/**
 * Entries whose pin does not match the file today.
 *
 * Decrement as they are repaired. Raising it is never the fix: a pin that does
 * not match its file means either the file moved without review, or the entry
 * describes bytes that no longer exist.
 */
const STALE_PIN_BUDGET = 68;

interface Entry {
  path?: string;
  sha256?: string;
}

function entries(): Entry[] {
  const raw = JSON.parse(readFileSync(ALLOWLIST, 'utf8')) as
    | { entries?: Entry[] }
    | Entry[];
  return Array.isArray(raw) ? raw : (raw.entries ?? []);
}

function sha256Of(p: string): string {
  return createHash('sha256').update(readFileSync(p)).digest('hex');
}

describe('the golden-provenance allowlist describes the tree, not just a PR', () => {
  const all = entries();

  it('parses and contains a non-trivial number of entries', () => {
    // Anti-vacuity: an empty or unparseable list would make every other
    // assertion here pass without examining anything.
    expect(all.length).toBeGreaterThan(200);
  });

  it('every entry carries both a path and a sha256', () => {
    const malformed = all.filter((e) => !e.path || !e.sha256);
    expect(malformed.map((e) => e.path ?? '<no path>')).toEqual([]);
  });

  it('every pinned path still exists', () => {
    const gone = all
      .map((e) => e.path!)
      .filter((p) => !existsSync(join(ROOT, p)));
    expect(
      gone,
      'these entries pin files that no longer exist — remove the entry, or ' +
        'restore the file:\n  ' + gone.join('\n  '),
    ).toEqual([]);
  });

  it('carries exactly the budgeted number of stale pins, and no more', () => {
    const stale = all
      .filter((e) => e.path && e.sha256 && existsSync(join(ROOT, e.path)))
      .filter((e) => sha256Of(join(ROOT, e.path!)) !== e.sha256)
      .map((e) => e.path!);

    expect(
      stale.length,
      stale.length > STALE_PIN_BUDGET
        ? `${stale.length - STALE_PIN_BUDGET} NEW stale pin(s). A golden moved ` +
          `without its allowlist entry being re-pinned. Re-pin the entry in the ` +
          `same commit that moves the bytes — do NOT raise STALE_PIN_BUDGET:\n  ` +
          stale.join('\n  ')
        : `${STALE_PIN_BUDGET - stale.length} stale pin(s) repaired. Lower ` +
          `STALE_PIN_BUDGET to ${stale.length}; the budget only ratchets DOWN.`,
    ).toBe(STALE_PIN_BUDGET);
  });
});
