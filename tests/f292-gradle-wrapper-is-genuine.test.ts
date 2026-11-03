/**
 * F-292 (CL-GAP-150): the committed Gradle wrapper jars were not the Gradle
 * 8.5 wrapper, and CI never used the wrapper anyway (bare `gradle`, so the
 * Gradle that built the Java compiler was whatever the runner image shipped,
 * with no wrapper-validation step anywhere).
 *
 * Proves, statically:
 *  (a) every committed gradle-wrapper.jar is byte-identical to Gradle's
 *      published 8.5 wrapper (sha256 from downloads.gradle.org/distributions/
 *      gradle-8.5-wrapper.jar.sha256);
 *  (b) every gradle-wrapper.properties points at gradle-8.5-bin.zip and pins
 *      that zip's published sha256;
 *  (c) no CI step runs bare `gradle` in a directory that has a wrapper;
 *  (d) every workflow job that runs ./gradlew validates the wrapper first;
 *  (e) every job that still runs bare `gradle` (directories without a
 *      wrapper) pins gradle-version '8.5' on its setup-gradle step.
 *
 * Does NOT prove: that the jars execute (the per-directory `./gradlew
 * --version` / build is the runtime check), or that a future commit keeps the
 * hash (this test is that gate), or that CI's hosted runner honours the pins.
 */

import { describe, it, expect } from 'vitest';
import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const WRAPPER_JAR_SHA256 = 'd3b261c2820e9e3d8d639ed084900f11f4a86050a8f83342ade7b6bc9b0d2bdd';
const BIN_ZIP_SHA256 = '9d926787066a081739e8200858338b4a69e837c3a821a33aca9db09dd4a41026';

const tracked = (glob: string): string[] =>
  execSync(`git ls-files -- '${glob}'`, { cwd: ROOT, encoding: 'utf-8' })
    .trim()
    .split('\n')
    .filter(Boolean)
    .sort();

const jars = tracked('*gradle-wrapper.jar');
const props = tracked('*gradle-wrapper.properties');
const wrapperDirs = tracked('*gradlew').map((p) => dirname(p));

const WF_DIR = join(ROOT, '.github/workflows');
const workflows = readdirSync(WF_DIR).filter((f) => f.endsWith('.yml'));

interface Job { file: string; name: string; text: string }
function jobsOf(file: string): Job[] {
  const text = readFileSync(join(WF_DIR, file), 'utf8');
  const at = text.search(/^jobs:\s*$/m);
  if (at < 0) return [];
  const body = text.slice(at).split('\n').slice(1);
  const jobs: Job[] = [];
  let cur: Job | null = null;
  for (const line of body) {
    const m = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
    if (m) { cur = { file, name: m[1]!, text: '' }; jobs.push(cur); }
    else if (cur) cur.text += line + '\n';
  }
  return jobs;
}
const jobs = workflows.flatMap(jobsOf);
const runLines = (j: Job) =>
  j.text.split('\n').filter((l) => /^\s*(-\s+)?run:/.test(l) || /^\s+(cd |\.\/gradlew|gradle )/.test(l));

describe('F-292: the Gradle wrapper is genuine and CI uses it', () => {
  it('finds the four wrapper projects and the workflows', () => {
    expect(jars.length).toBeGreaterThanOrEqual(4);
    expect(wrapperDirs.length).toBe(jars.length);
    expect(jobs.length).toBeGreaterThan(10);
  });

  it('(a) every gradle-wrapper.jar is the official Gradle 8.5 wrapper', () => {
    const bad = jars.filter(
      (j) => createHash('sha256').update(readFileSync(join(ROOT, j))).digest('hex') !== WRAPPER_JAR_SHA256,
    );
    expect(bad).toEqual([]);
  });

  it('(b) every gradle-wrapper.properties pins the 8.5 bin zip and its sha256', () => {
    const bad = props.filter((p) => {
      const t = readFileSync(join(ROOT, p), 'utf8');
      return !/^distributionUrl=.*\/gradle-8\.5-bin\.zip$/m.test(t) ||
        !new RegExp(`^distributionSha256Sum=${BIN_ZIP_SHA256}$`, 'm').test(t);
    });
    expect(bad).toEqual([]);
  });

  it('(c) no CI step runs bare `gradle` in a directory that has a wrapper', () => {
    const offenders: string[] = [];
    for (const j of jobs) {
      for (const l of j.text.split('\n')) {
        const m = /\bcd\s+(\S+)\s*&&\s*gradle\s/.exec(l);
        if (m && wrapperDirs.includes(m[1]!.replace(/\/$/, ''))) offenders.push(`${j.file}:${j.name}: ${l.trim()}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('(d) every job that runs ./gradlew validates the wrapper first', () => {
    const bad: string[] = [];
    for (const j of jobs) {
      const g = j.text.indexOf('./gradlew');
      if (g < 0) continue;
      const v = j.text.indexOf('gradle/actions/wrapper-validation');
      if (v < 0 || v > g) bad.push(`${j.file}:${j.name}`);
    }
    // The set must be non-empty: otherwise (c) was satisfied by deleting the steps.
    expect(jobs.filter((j) => j.text.includes('./gradlew')).length).toBeGreaterThanOrEqual(4);
    expect(bad).toEqual([]);
  });

  it("(e) a job that still runs bare `gradle` pins gradle-version '8.5' on setup-gradle", () => {
    const bad: string[] = [];
    for (const j of jobs) {
      if (!runLines(j).some((l) => /\bgradle\s+(-\S+\s+)*[a-zA-Z]/.test(l) && !l.includes('./gradlew') && !/^\s*#/.test(l))) continue;
      const m = /uses:\s*gradle\/actions\/setup-gradle@[^\n]*\n((?:\s+(?:with:|[a-z-]+:.*)\n?)*)/.exec(j.text);
      if (!m || !/gradle-version:\s*['"]?8\.5['"]?\s*$/m.test(m[1]!)) bad.push(`${j.file}:${j.name}`);
    }
    expect(bad).toEqual([]);
  });

  it('wrapper scripts exist next to every jar', () => {
    for (const d of wrapperDirs) expect(existsSync(join(ROOT, d, 'gradlew.bat'))).toBe(true);
  });
});
