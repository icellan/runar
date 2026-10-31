/**
 * N-484 — every example in integration/ruby/spec/wallet_client_spec.rb must
 * carry at least one real expectation.
 *
 * The file used to end with a "sentinel" example whose body was only
 * `skip ... if ENV[...].to_s.empty?`. With RUNAR_WALLET_ENDPOINT set (which is
 * exactly how CI runs it, against the mock wallet) the guard is false, the body
 * is empty, and RSpec reports a green pass with zero expectations. Its TS twin
 * was deleted under N-474.
 *
 * Proves: statically, no `it` block in the spec lacks an `expect(...)`. A
 * example reduced to a bare `skip` guard, or whose assertions are gutted,
 * fails here.
 * Does NOT prove the expectations are meaningful or that the examples pass —
 * the CI integration job runs the spec against the mock wallet for that.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SPEC = join(ROOT, 'integration', 'ruby', 'spec', 'wallet_client_spec.rb');

/** Bodies of every `it '...' do ... end` block, keyed by example title. */
function exampleBodies(src: string): Map<string, string> {
  const lines = src.split('\n');
  const out = new Map<string, string>();
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\s*)it\s+(['"])(.*)\2\s+do\s*$/.exec(lines[i]);
    if (!m) continue;
    const end = new RegExp(`^${m[1]}end\\s*$`);
    let j = i + 1;
    while (j < lines.length && !end.test(lines[j])) j++;
    expect(j, `unterminated example "${m[3]}"`).toBeLessThan(lines.length);
    out.set(m[3], lines.slice(i + 1, j).join('\n'));
  }
  return out;
}

describe('N-484 wallet_client_spec.rb has no vacuous examples', () => {
  const bodies = exampleBodies(readFileSync(SPEC, 'utf8'));

  it('finds the real round-trip example (parser floor)', () => {
    expect(bodies.size).toBeGreaterThanOrEqual(1);
  });

  it.each([...bodies.entries()])('example "%s" has an expectation', (_title, body) => {
    expect(body).toMatch(/\bexpect\s*[(\s]/);
  });
});
