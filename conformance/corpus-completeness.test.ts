/**
 * The conformance summary's denominator must be DECLARED, not discovered.
 *
 * `runAllConformanceTests` prints `N passed, 0 failed (N total)` where N is
 * whatever `readdirSync` returned. Nothing anywhere compared that N against the
 * corpus the suite is supposed to hold, so a run that enumerated fewer fixtures
 * reported green and exited 0. The summary could not distinguish "every fixture
 * passed" from "I found fewer fixtures" — fail-open, in the harness that gates
 * every other guard in this repo.
 *
 * Observed, not theorised: during the R-102 work a run reported
 * `78 passed, 0 failed (78 total)` at exit 0 while `conformance/tests` held 82.
 * The four absentees were exactly the four fixtures this branch had added
 * (byte-builtins, countdown-loop, p256-encode-negate, p384-encode-negate), and
 * the cause was a stale concurrent runner's output being read as the current
 * run's. Two separate people spent time deciding whether 78 was real, because
 * a green summary is not something you think to distrust.
 *
 * `script-size-baseline.json` already carries one entry per fixture, so a
 * committed declaration of the corpus existed the whole time; nothing consulted
 * it. That file is the oracle here precisely because it is maintained for an
 * unrelated reason — script-size-check fails with `missing>0` when a fixture
 * lacks a row — so it cannot silently drift in step with a discovery bug.
 */

import { describe, it, expect } from 'vitest';
import { readdirSync, existsSync, readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertCorpusComplete, declaredCorpus } from './runner/runner.js';

const HERE = resolve(dirname(fileURLToPath(import.meta.url)));

function onDisk(): string[] {
  return readdirSync(join(HERE, 'tests'))
    .filter((d) => existsSync(join(HERE, 'tests', d, 'source.json')))
    .sort();
}

describe('the conformance corpus is complete, and the runner refuses a partial one', () => {
  it('declares a non-trivial corpus', () => {
    // Anti-vacuity. An empty or unreadable baseline would make every assertion
    // below pass while checking nothing — which is the exact failure shape this
    // file exists to close, so it must not be reintroduced here.
    expect(declaredCorpus(HERE).length).toBeGreaterThan(50);
  });

  it('declares exactly the fixtures that are on disk', () => {
    const declared = declaredCorpus(HERE);
    const disk = onDisk();

    // Both directions, and as sets rather than counts: two errors that cancel
    // out in a length comparison (one fixture added, one dropped) would
    // otherwise read as agreement.
    expect(
      declared.filter((f) => !disk.includes(f)),
      'declared in script-size-baseline.json but absent from tests/ — remove the ' +
        'baseline row in the same commit that removes the fixture',
    ).toEqual([]);
    expect(
      disk.filter((f) => !declared.includes(f)),
      'present in tests/ but not declared in script-size-baseline.json — run ' +
        'script-size-check --update so the new fixture is counted',
    ).toEqual([]);
  });

  it('throws when discovery misses a declared fixture, and names it', () => {
    const declared = declaredCorpus(HERE);
    const dropped = declared[0]!;
    const partial = declared.slice(1);

    let err: Error | undefined;
    try {
      assertCorpusComplete(partial, declared);
    } catch (e) {
      err = e as Error;
    }

    expect(err, 'a partial corpus was accepted — the guard cannot fail').toBeDefined();
    // The message must name the absentee. A bare count mismatch sends the reader
    // looking through 82 directories; the whole point is to say what went missing.
    expect(err!.message).toContain(dropped);
    expect(err!.message).toContain(String(partial.length));
    expect(err!.message).toContain(String(declared.length));
  });

  it('accepts a complete corpus, in any order', () => {
    const declared = declaredCorpus(HERE);
    // Reversed on purpose: the check is about membership, not enumeration order,
    // and a guard that quietly depended on sort order would be brittle rather
    // than strict.
    expect(() => assertCorpusComplete([...declared].reverse(), declared)).not.toThrow();
  });

  it('discovers fixtures in exactly one place, so the guard cannot be bypassed', () => {
    // The first version of this guard was wired into ONE of four identical
    // discovery blocks — `runAllConformanceTests`. The other three back
    // `--parser-only`, `--ir-parity` and `--multi-format`, and every CI
    // invocation of the runner passes one of those flags, so the two gates that
    // enforce the CLAUDE.md invariants still had a discovered denominator.
    // Hiding one fixture and running `--ir-parity` printed `81 ok, 0 failed,
    // 0 skipped` at exit 0 — the exact fail-open the guard was added to close,
    // surviving in the paths that mattered most.
    //
    // Patching the other three would have left a guard that has to be
    // remembered four times. They are collapsed into `discoverFixtureDirs`, and
    // this asserts it stays that way: one raw enumeration, inside the helper.
    // A fifth copy is how the bypass comes back.
    const src = readFileSync(join(HERE, 'runner', 'runner.ts'), 'utf8');
    const raw = src.split('\n').filter((l) => l.includes('readdirSync(testsDir'));
    expect(
      raw.length,
      'conformance/runner/runner.ts enumerates the fixture directory in more ' +
        'than one place. Route it through discoverFixtureDirs() instead — that ' +
        'is where assertCorpusComplete runs, and a second enumeration silently ' +
        'skips it:\n  ' + raw.map((l) => l.trim()).join('\n  '),
    ).toBe(1);

    const helperAt = src.indexOf('export function discoverFixtureDirs(');
    const rawAt = src.indexOf('readdirSync(testsDir');
    expect(helperAt, 'discoverFixtureDirs has been renamed or removed').toBeGreaterThan(-1);
    // The one remaining enumeration must be the helper's own, not some other
    // function that happens to be the sole survivor.
    expect(
      rawAt > helperAt && rawAt - helperAt < 2000,
      'the remaining readdirSync(testsDir) is not inside discoverFixtureDirs',
    ).toBe(true);
  });

  it('ignores extra discovered fixtures, which the other test already covers', () => {
    // A fixture on disk with no baseline row is a real problem, but it is
    // script-size-check's to report (missing>0) and the disk/declared test
    // above states it directly. Duplicating it here would mean one fix has to
    // land in two places, so this pins the division of labour deliberately.
    const declared = declaredCorpus(HERE);
    expect(() => assertCorpusComplete([...declared, 'not-a-fixture'], declared)).not.toThrow();
  });
});
