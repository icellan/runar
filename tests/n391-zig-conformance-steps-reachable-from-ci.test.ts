/**
 * N-391: every `conformance*` build step declared in compilers/zig/build.zig
 * must be invoked by a non-comment `zig build <step>` line in a workflow.
 *
 * `conformance-goldens` (src/tests/conformance_goldens.zig, the Zig per-tier
 * byte-identical golden harness) is a separate build step that `zig build test`
 * does not depend on, so a workflow has to name it or the harness is never run.
 *
 * Proves: each such step name appears on a real (non-comment) `run:` line of a
 * workflow as `zig build <step>`. Does not prove: that the step passes, that
 * the line sits in a job that actually executes, or other invocation forms
 * (composite actions, Makefile targets); add the form here if one is introduced.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function conformanceSteps(): string[] {
  const src = readFileSync(join(ROOT, 'compilers', 'zig', 'build.zig'), 'utf8');
  const names = new Set<string>();
  for (const m of src.matchAll(/b\.step\(\s*"([^"]+)"/g)) {
    if (m[1]!.startsWith('conformance')) names.add(m[1]!);
  }
  return [...names].sort();
}

function workflowCommandLines(): string[] {
  const dir = join(ROOT, '.github', 'workflows');
  const out: string[] = [];
  for (const f of readdirSync(dir)) {
    if (!/\.ya?ml$/.test(f)) continue;
    for (const line of readFileSync(join(dir, f), 'utf8').split('\n')) {
      if (!/^\s*#/.test(line)) out.push(line);
    }
  }
  return out;
}

describe('N-391: Zig conformance build steps are invoked by CI', () => {
  const steps = conformanceSteps();
  const lines = workflowCommandLines();

  it('finds the conformance steps (anti-vacuity)', () => {
    expect(steps).toContain('conformance');
    expect(steps).toContain('conformance-goldens');
  });

  it('runs every one of them with `zig build <step>`', () => {
    const missing = steps.filter((s) => {
      const re = new RegExp(`zig build (-\\S+ )*${s.replace(/-/g, '\\-')}(\\s|$|["'])`);
      return !lines.some((l) => re.test(l));
    });
    expect(
      missing,
      `compilers/zig/build.zig declares these steps but no workflow runs them:\n  ${missing.join('\n  ')}`,
    ).toEqual([]);
  });
});
