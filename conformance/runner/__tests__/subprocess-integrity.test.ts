import { describe, it, expect, beforeEach } from 'vitest';

import {
  runCmd,
  getHarnessFaults,
  resetHarnessFaults,
  compareScript,
  type CompilerOutput,
} from '../runner.js';

// NEW-003. The conformance runner intermittently reported
//
//   FAIL post-quantum-slhdsa-192f  reported success but produced empty hex: [zig, ruby]
//
// on fixtures that pass in isolation. The cause was not codegen: `runCmd`'s
// close handler did `code: code ?? 0`. Node reports `code === null` /
// `signal === 'SIGKILL'` for a child killed by a signal, so the runner mapped
// every killed subprocess onto exit status 0 — SUCCESS — and then read the
// child's half-drained stdout as that tier's compiled script.
//
// Both observed flake shapes fall out of that one line:
//   * pipe drained before anything was written -> `''` -> "produced empty hex"
//   * pipe drained mid-write -> a prefix -> "majority [6 tiers] vs [x]
//     identical up to length", i.e. a fake byte-level divergence
//
// Reproduced deliberately at concurrency 20 on an 8-core host: ruby's 30s
// budget expired on ECDemo (stdout 0B) and ECPrimitives (stdout 65536B — one
// pipe buffer), producing exactly those two messages against six innocent
// tiers.
//
// The invariant these tests pin: a child that did not exit under its own
// control has NO output worth reading, and the runner must say so.

describe('runCmd never reports a killed child as a successful run', () => {
  beforeEach(() => {
    resetHarnessFaults();
  });

  it('flags a timeout kill instead of coalescing it to exit 0', async () => {
    // Writes a partial chunk, then sleeps past the deadline. This is the
    // SLH-DSA shape in miniature: real output on the pipe, killed mid-emit.
    // `exec` so the process we SIGKILL is the one holding the pipe — a bash
    // that forked `sleep` would keep stdout open past its own death.
    const res = await runCmd('bash', ['-c', 'echo -n PARTIAL; exec sleep 30'], {
      timeoutMs: 500,
      label: 'timeout probe',
    });

    expect(res.timedOut).toBe(true);
    expect(res.signal).toBe('SIGKILL');
    // The regression: `code ?? 0` made this 0.
    expect(res.code).not.toBe(0);
    expect(res.abnormal).toBeDefined();
    expect(res.abnormal).toMatch(/timed out/i);
    // The captured prefix is still there — which is exactly why `code` must
    // never say 0. A caller trusting the status would ship "PARTIAL" as a
    // compiled script.
    expect(res.stdout).toBe('PARTIAL');

    const faults = getHarnessFaults();
    expect(faults).toHaveLength(1);
    expect(faults[0]!.kind).toBe('timeout');
    expect(faults[0]!.detail).toContain('timeout probe');
  });

  it('flags an external signal kill instead of coalescing it to exit 0', async () => {
    // No timeout configured: this is the OS-memory-pressure / crashed-compiler
    // case, where nothing in the runner asked for the kill.
    const res = await runCmd('bash', ['-c', 'kill -TERM $$; sleep 30'], {
      label: 'signal probe',
    });

    expect(res.timedOut).toBe(false);
    expect(res.signal).toBe('SIGTERM');
    expect(res.code).not.toBe(0);
    expect(res.abnormal).toMatch(/killed by SIGTERM/);

    const faults = getHarnessFaults();
    expect(faults).toHaveLength(1);
    expect(faults[0]!.kind).toBe('signal');
  });

  it('flags an over-cap capture instead of returning truncated output as success', async () => {
    // The capture cap kills the child too — and used to do it with no flag at
    // all, so the truncated prefix looked like a complete, successful compile.
    const res = await runCmd('bash', ['-c', 'yes ffffffffffffffff'], {
      maxBuffer: 64 * 1024,
      timeoutMs: 30_000,
      label: 'cap probe',
    });

    expect(res.truncated).toBe(true);
    expect(res.code).not.toBe(0);
    expect(res.abnormal).toMatch(/capture cap/);

    const faults = getHarnessFaults();
    expect(faults).toHaveLength(1);
    expect(faults[0]!.kind).toBe('output-truncated');
  });

  it('leaves a clean run alone — no fault, faithful status, full output', async () => {
    const res = await runCmd('bash', ['-c', 'echo -n COMPLETE'], { timeoutMs: 30_000 });

    expect(res.code).toBe(0);
    expect(res.signal).toBeNull();
    expect(res.timedOut).toBe(false);
    expect(res.truncated).toBe(false);
    expect(res.abnormal).toBeUndefined();
    expect(res.stdout).toBe('COMPLETE');
    expect(getHarnessFaults()).toHaveLength(0);
  });

  it('records a failed spawn rather than reporting a phantom empty result', async () => {
    const res = await runCmd('this-binary-does-not-exist-runar', [], { label: 'spawn probe' });

    expect(res.code).not.toBe(0);
    expect(res.abnormal).toMatch(/failed to spawn/);
    expect(getHarnessFaults()[0]!.kind).toBe('spawn-error');
  });

  it('reports a NON-zero clean exit as a compiler failure, not a harness fault', async () => {
    // The inverse guard: a compiler that ran and rejected the program is a
    // CONFORMANCE signal. Filing it as a harness fault would let a genuine
    // compile failure be dismissed as "the host was busy, re-run it".
    const res = await runCmd('bash', ['-c', 'echo -n oops >&2; exit 3'], { timeoutMs: 30_000 });

    expect(res.code).toBe(3);
    expect(res.abnormal).toBeUndefined();
    expect(res.stderr).toBe('oops');
    expect(getHarnessFaults()).toHaveLength(0);
  });
});

// The other half of the guarantee: hardening the harness must not blunt the
// gate. A tier whose output is genuinely wrong — truncated, empty, or merely
// different — must still be caught as a CONFORMANCE divergence and named.
describe('genuine tier defects are still caught as conformance failures', () => {
  function out(over: Partial<CompilerOutput> = {}): CompilerOutput {
    return {
      irJson: '{"a":1}',
      scriptHex: 'deadbeefcafe',
      scriptAsm: '',
      success: true,
      durationMs: 1,
      ...over,
    };
  }
  /** ts, go, rust, python, zig, ruby, java — the fixed slot order. */
  function sevenWith(slot: number, replacement: CompilerOutput): CompilerOutput[] {
    const base = Array.from({ length: 7 }, () => out());
    base[slot] = replacement;
    return base;
  }

  it('catches a tier that emits a truncated prefix of the right script', () => {
    // zig = slot 4. This is the exact shape a lost pipe used to fake — it must
    // still fail when the tier really does emit it.
    const r = compareScript(sevenWith(4, out({ scriptHex: 'deadbe' })), 7);
    expect(r.ok).toBe(false);
    expect(r.detail).toContain('zig');
    expect(r.detail).toMatch(/identical up to length/);
  });

  it('catches a tier that emits an empty script with a success status', () => {
    const r = compareScript(sevenWith(5, out({ scriptHex: '' })), 7);
    expect(r.ok).toBe(false);
    expect(r.detail).toContain('ruby');
    expect(r.detail).toMatch(/empty hex/);
  });

  it('catches a tier that emits a differing byte mid-script', () => {
    const r = compareScript(sevenWith(1, out({ scriptHex: 'deadbfefcafe' })), 7);
    expect(r.ok).toBe(false);
    expect(r.detail).toContain('go');
    expect(r.detail).toMatch(/first differs at byte 2/);
  });
});
