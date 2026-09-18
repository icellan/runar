/**
 * A tier that DIED must never be scored as a tier that REJECTED.
 *
 * `canonical-json-differential.ts` compares tiers by normalising any
 * `REJECT_PREFIX` output to a single `<REJECT>` token, so two tiers that reject
 * with different wording still count as agreeing. `CRASH_PREFIX` exists so the
 * other outcome — the tier's process died, or its canonicalJson blew the native
 * stack — stays OUTSIDE that equivalence class: a dead tier told us nothing
 * about what its canonicalJson would have decided.
 *
 * The driver applied CRASH_PREFIX only when the shim failed to LAUNCH. Three
 * shims catch native stack exhaustion IN-PROCESS (Ruby `SystemStackError`,
 * Python `RecursionError`, Java `StackOverflowError`) and each emitted the
 * REJECTION prefix while its own comment claimed the output was "distinguishable
 * so it cannot be scored as agreement". It was not: all three normalised to
 * `<REJECT>`, byte-identical to a clean typed rejection.
 *
 * Concretely: `guardBoundaryCases` probes `maxNesting + 1` and `maxNesting * 2`
 * expecting every tier to reject. A tier that loses its explicit nesting guard
 * recurses natively, blows its stack, and AGREES with the guarded tiers.
 *
 * The execution cases below force that exact path (a lowered CPython recursion
 * limit / a tiny Ruby VM stack) with the guard still in place, so they assert
 * the real emitted bytes rather than a claim about them. Java has no equivalent
 * lever — HotSpot refuses `-Xss` below 208k, which is already deeper than the
 * nesting guard allows — so the Java arm is asserted at the source level.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import {
  REJECT_PREFIX,
  CRASH_PREFIX,
  normaliseOutcome,
} from '../canonical-json-differential.js';

const REPO = resolve(__dirname, '../../..');
const read = (rel: string) => readFileSync(resolve(REPO, rel), 'utf8');

const PY_SHIM = resolve(REPO, 'packages/runar-py/canonicalise_shim.py');
const RB_SHIM = resolve(REPO, 'packages/runar-rb/bin/canonicalise_shim.rb');
const JAVA_SHIM = 'packages/runar-java/src/main/java/runar/lang/sdk/CanonicaliseShim.java';

function have(cmd: string, args: string[]): boolean {
  const r = spawnSync(cmd, args, { stdio: 'pipe', timeout: 10_000 });
  return !r.error && r.status === 0;
}

const havePython = have('python3', ['--version']);
const haveRuby = have('ruby', ['--version']);

/**
 * In CI a missing toolchain must FAIL, not skip: a green tick on a run that
 * never drove the shim is the same disease this whole file is about. Locally
 * the arm is skipped with a warning so a developer without ruby can still work.
 */
const TOOLCHAINS_REQUIRED =
  process.env.RUNAR_REQUIRE_TOOLCHAINS === '1' || process.env.CI === 'true';

function requireTool(present: boolean, name: string): boolean {
  if (present) return true;
  if (TOOLCHAINS_REQUIRED) {
    throw new Error(
      `${name} is not installed. This arm drives the real shim; in CI it must not be skipped.`,
    );
  }
  console.warn(`[canonical-crash-prefix] ${name} not installed — arm skipped (local run only).`);
  return false;
}

describe('canonical fuzzer: a crashed tier is not a rejecting tier', () => {
  it('normaliseOutcome keeps a crash out of the <REJECT> equivalence class', () => {
    const crash = normaliseOutcome(`${CRASH_PREFIX}StackOverflowError`);
    const reject = normaliseOutcome(`${REJECT_PREFIX}canonical JSON: nesting exceeds 100`);

    expect(crash).not.toBe(reject);
    // And a crash must not accidentally normalise to the canonical bytes of
    // some other tier either.
    expect(crash).not.toBe('[[1]]');
  });

  it('CONTROL: two differently-worded typed rejections still agree', () => {
    // The fix must not make the gate stricter about the case it was always
    // meant to allow — a healthy corpus where tiers reject with their own
    // wording has to stay green.
    expect(normaliseOutcome(`${REJECT_PREFIX}nesting exceeds 100`)).toBe(
      normaliseOutcome(`${REJECT_PREFIX}depth limit exceeded`),
    );
    // Accepted output passes through untouched.
    expect(normaliseOutcome('[[1]]')).toBe('[[1]]');
  });

  it(
    'python shim: native RecursionError emits the CRASH prefix, not the REJECT prefix',
    () => {
      if (!requireTool(havePython, 'python3')) return;
      // Force canonical_json's own recursion to exhaust the interpreter stack
      // while its depth guard (MAX_WIRE_NESTING = 100) is untouched: nest 99
      // containers under a recursion limit of 60. `runar.sdk` is imported
      // BEFORE the limit is lowered so the import itself is not what fails.
      const driver = [
        'import sys, json, hashlib',
        'import runar.sdk',
        'sys.setrecursionlimit(60)',
        `p = ${JSON.stringify(PY_SHIM)}`,
        "src = open(p).read()",
        "exec(compile(src, p, 'exec'), {'__name__': '__main__', '__file__': p})",
      ].join('\n');

      const r = spawnSync('python3', ['-c', driver], {
        input: '{"mode":"deep","depth":99,"shape":"array"}',
        encoding: 'utf-8',
        env: { ...process.env, PYTHONPATH: resolve(REPO, 'packages/runar-py') },
        timeout: 60_000,
      });

      const out = (r.stdout ?? '').trim();
      expect(out, `stderr: ${r.stderr}`).toContain('RecursionError');
      expect(out.startsWith(CRASH_PREFIX), `got: ${out}`).toBe(true);
      expect(normaliseOutcome(out)).not.toBe(normaliseOutcome(`${REJECT_PREFIX}x`));
    },
    60_000,
  );

  it(
    'CONTROL: python shim still emits the REJECT prefix for a real guard rejection',
    () => {
      if (!requireTool(havePython, 'python3')) return;
      const r = spawnSync('python3', [PY_SHIM], {
        input: '{"mode":"deep","depth":4096,"shape":"array"}',
        encoding: 'utf-8',
        env: { ...process.env, PYTHONPATH: resolve(REPO, 'packages/runar-py') },
        timeout: 60_000,
      });
      const out = (r.stdout ?? '').trim();
      expect(out.startsWith(REJECT_PREFIX), `got: ${out} / stderr: ${r.stderr}`).toBe(true);
      expect(normaliseOutcome(out)).toBe('<REJECT>');
    },
    60_000,
  );

  it(
    'ruby shim: native SystemStackError emits the CRASH prefix, not the REJECT prefix',
    () => {
      if (!requireTool(haveRuby, 'ruby')) return;
      // A 16 KiB VM stack overflows inside canonical_json well before the
      // depth guard (MAX_WIRE_NESTING = 100) can reject 99 containers.
      const r = spawnSync('ruby', [RB_SHIM], {
        input: '{"mode":"deep","depth":99,"shape":"array"}',
        encoding: 'utf-8',
        env: { ...process.env, RUBY_THREAD_VM_STACK_SIZE: '16384' },
        timeout: 60_000,
      });

      const out = (r.stdout ?? '').trim();
      expect(out, `stderr: ${r.stderr}`).toContain('SystemStackError');
      expect(out.startsWith(CRASH_PREFIX), `got: ${out}`).toBe(true);
      expect(normaliseOutcome(out)).not.toBe(normaliseOutcome(`${REJECT_PREFIX}x`));
    },
    60_000,
  );

  it(
    'CONTROL: ruby shim still emits the REJECT prefix for a real guard rejection',
    () => {
      if (!requireTool(haveRuby, 'ruby')) return;
      const r = spawnSync('ruby', [RB_SHIM], {
        input: '{"mode":"deep","depth":4096,"shape":"array"}',
        encoding: 'utf-8',
        timeout: 60_000,
      });
      const out = (r.stdout ?? '').trim();
      expect(out.startsWith(REJECT_PREFIX), `got: ${out} / stderr: ${r.stderr}`).toBe(true);
      expect(normaliseOutcome(out)).toBe('<REJECT>');
    },
    60_000,
  );

  it('java shim: the StackOverflowError handler returns the CRASH prefix', () => {
    // HotSpot refuses -Xss below 208k, which already carries canonicalJson
    // deeper than MAX_WIRE_NESTING allows, so this arm cannot be driven to a
    // real StackOverflowError through the shim protocol. Pin the handler.
    const src = read(JAVA_SHIM);
    expect(src).toContain('CRASH_PREFIX = "RUNAR_CANON_CRASH:"');
    const handler = /catch \(StackOverflowError e\) \{[\s\S]*?\n        \}/.exec(src)?.[0];
    expect(handler, 'no StackOverflowError handler found in CanonicaliseShim').toBeTruthy();
    expect(handler!).toContain('CRASH_PREFIX +');
    expect(handler!).not.toContain('REJECT_PREFIX +');
  });

  it('the Java PR gate uses the shared normaliser rather than its own', () => {
    // The same normalisation was duplicated in canonical-java-gate.ts, which
    // did not know CRASH_PREFIX existed. Importing the shared one is what
    // keeps the two gates in agreement about what "agreed" means.
    const src = read('conformance/fuzzer/canonical-java-gate.ts');
    expect(src).toContain('normaliseOutcome');
    expect(
      /const norm\s*=\s*\(s: string\): string =>/.test(src),
      'canonical-java-gate.ts still defines its own REJECT-only normaliser',
    ).toBe(false);
  });
});
