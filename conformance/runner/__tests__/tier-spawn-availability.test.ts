import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { generateReport } from '../report.js';
import { findJavaBinary, getOrStartJavaDaemon, shutdownJavaDaemon } from '../runner.js';
import type { ConformanceResult } from '../runner.js';

// N-374: a tier must count as "available" only if it can actually run.
//
// F-295: with `java` absent from PATH the banner listed Java as available and
// every Java compile failed with `spawn java ENOENT`. Two gaps produced that:
//   1. the Java daemon was started on the strength of the jar alone, without
//      the `java` probe that findJavaBinary() does -- so the probe and the
//      spawn disagreed about what "available" means;
//   2. the report derived `available` from "has any result", so a tier whose
//      every result was a spawn failure still read as available.
//
// Proves: (1) no daemon is started when `java` cannot be run, even with a jar
// on disk; (2) a tier whose every result is a spawn ENOENT is reported
// unavailable, while one that ran at least once stays available.
// Does not prove: the process exit code of a whole runner invocation, nor the
// behaviour of tiers other than Java under a real missing-binary run.

const out = (success: boolean, error = '') => ({
  irJson: '',
  scriptHex: '',
  scriptAsm: '',
  success,
  error,
  durationMs: 1,
});

const row = (name: string, java: ReturnType<typeof out>): ConformanceResult => ({
  testName: name,
  tsCompiler: out(true),
  javaCompiler: java,
  irMatch: true,
  scriptMatch: true,
  errors: java.success ? [] : ['Java compiler failed'],
});

describe('N-374 tier availability reflects whether the spawn can run', () => {
  describe('report', () => {
    it('a tier whose every result is a spawn ENOENT is reported unavailable', () => {
      const enoent = out(false, 'spawn java ENOENT');
      const r = generateReport([row('a', enoent), row('b', enoent)]);
      const java = r.compilers.find((c) => c.name === 'Java')!;
      expect(java.available).toBe(false);
    });

    it('a harness-wrapped spawn failure from the one-shot path counts the same way', () => {
      const e = out(false, 'HARNESS: java --emit-ir: failed to spawn java: spawn java ENOENT');
      const r = generateReport([row('a', e)]);
      expect(r.compilers.find((c) => c.name === 'Java')!.available).toBe(false);
    });

    it('a tier that ran at least once stays available even if another fixture ENOENTs', () => {
      const r = generateReport([
        row('a', out(true)),
        row('b', out(false, 'spawn java ENOENT')),
      ]);
      expect(r.compilers.find((c) => c.name === 'Java')!.available).toBe(true);
    });

    it('a tier that ran and genuinely failed stays available', () => {
      const r = generateReport([row('a', out(false, 'java --hex exit 1: boom'))]);
      expect(r.compilers.find((c) => c.name === 'Java')!.available).toBe(true);
    });
  });

  describe('java daemon probe', () => {
    const savedPath = process.env.PATH;
    const savedCwd = process.cwd();
    let dir: string | undefined;

    afterEach(async () => {
      process.env.PATH = savedPath;
      process.chdir(savedCwd);
      try { await shutdownJavaDaemon(); } catch { /* daemon never started */ }
      if (dir) rmSync(dir, { recursive: true, force: true });
      dir = undefined;
    });

    it('starts no daemon when `java` is not runnable, even though a jar is on disk', () => {
      dir = mkdtempSync(join(tmpdir(), 'n374-'));
      // A jar the locator will find via <cwd>/runar-java.jar, and a PATH with no java.
      writeFileSync(join(dir, 'runar-java.jar'), '');
      process.chdir(dir);
      process.env.PATH = dir;
      expect(findJavaBinary()).toBeNull();
      expect(getOrStartJavaDaemon()).toBeNull();
    });
  });
});
