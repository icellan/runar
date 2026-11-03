import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { buildSdkTools } from './sdk-runner.js';

// N-441: the runner used to trust any executable it found at the prebuilt
// path (go-sdk-tool-bin, rs-sdk-tool/target/release/rs-sdk-tool,
// zig-sdk-tool/zig-out/bin/zig-sdk-tool, java-driver/build/libs/*.jar). A
// binary built before an SDK change therefore kept passing, and the change
// it was supposed to exercise was never run: the Zig tool failed r062 after
// N-260/R100 and every battery stayed green because a stale Oct 4 binary was
// being executed.
//
// These tests point buildSdkTools() at a scratch tools/ directory holding fake
// "prebuilt" binaries and check, per tool, that the runner schedules a rebuild
// (preBuild) exactly when a source it was built from is newer than the binary.
// The SDK package sources (packages/runar-*) are the real ones in this
// checkout, so a binary stamped in year 2000 is stale against them by
// construction, and one stamped in 2100 is fresh against them.
//
// What this proves: the staleness decision, for all four compiled tools, for
// both the tool's own sources and the SDK package it links. What it does not
// prove: that the rebuild itself succeeds (that needs the toolchains; the
// sdk-output runner's own CI step exercises it).

const PAST = new Date('2000-01-01T00:00:00Z');
const FUTURE = new Date('2100-01-01T00:00:00Z');

let scratch: string | undefined;

afterEach(() => {
  if (scratch) rmSync(scratch, { recursive: true, force: true });
  scratch = undefined;
});

function put(path: string, mtime: Date, exec = false): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, exec ? '#!/bin/sh\nexit 0\n' : 'x\n');
  if (exec) chmodSync(path, 0o755);
  utimesSync(path, mtime, mtime);
}

/** Fake prebuilt outputs for the four compiled tools, all stamped `mtime`. */
function makeTools(mtime: Date): string {
  scratch = mkdtempSync(join(tmpdir(), 'n441-'));
  put(join(scratch, 'go-sdk-tool-bin'), mtime, true);
  put(join(scratch, 'rs-sdk-tool', 'target', 'release', 'rs-sdk-tool'), mtime, true);
  put(join(scratch, 'zig-sdk-tool', 'zig-out', 'bin', 'zig-sdk-tool'), mtime, true);
  put(join(scratch, 'java-driver', 'build', 'libs', 'java-sdk-driver-1.0.0-rc.1-all.jar'), mtime);
  return scratch;
}

const COMPILED = ['go', 'rust', 'zig', 'java'];

describe('N-441: the sdk-output runner never reuses a stale prebuilt tool', () => {
  it('schedules a rebuild of every compiled tool older than the SDK package it links', () => {
    const tools = buildSdkTools(makeTools(PAST));
    for (const name of COMPILED) {
      const t = tools.find((x) => x.name === name)!;
      expect(t.preBuild, `${name}: stale binary was accepted as-is`).toBeTypeOf('function');
    }
  });

  it('reuses a prebuilt tool newer than everything it was built from', () => {
    const tools = buildSdkTools(makeTools(FUTURE));
    for (const name of COMPILED) {
      const t = tools.find((x) => x.name === name)!;
      expect(t.preBuild, `${name}: fresh binary was rebuilt needlessly`).toBeUndefined();
    }
  });

  it('schedules a rebuild when the tool\'s OWN source is newer than its binary', () => {
    const dir = makeTools(FUTURE);
    const newer = new Date('2101-01-01T00:00:00Z');
    put(join(dir, 'go-sdk-tool.go'), newer);
    put(join(dir, 'rs-sdk-tool', 'src', 'main.rs'), newer);
    put(join(dir, 'zig-sdk-tool', 'src', 'main.zig'), newer);
    put(join(dir, 'java-driver', 'src', 'main', 'java', 'Driver.java'), newer);
    const tools = buildSdkTools(dir);
    for (const name of COMPILED) {
      const t = tools.find((x) => x.name === name)!;
      expect(t.preBuild, `${name}: edited tool source did not trigger a rebuild`).toBeTypeOf('function');
    }
  });
});
