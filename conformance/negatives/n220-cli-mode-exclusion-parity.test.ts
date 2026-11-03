import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { ALL_TIER_IDS, REPO, Tier, buildSourceTiers } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-220 — every compiler CLI refuses a second input mode instead of silently
 * picking one.
 *
 * Go (F-183) and Ruby (F-335) refused `--source X --ir Y` with
 * "--source and --ir are mutually exclusive; pass exactly one". TS (positional
 * files + `--from-ir`), Python, Rust and Java ran the source and ignored the
 * IR; Zig refused only through a generic "unknown flag". Go also refuses
 * `--hex --asm` ("--hex and --asm are mutually exclusive; pass exactly one");
 * Ruby silently preferred --hex.
 *
 * Proves: for a valid source file plus a valid IR file, each tier's CLI exits
 * non-zero (a real exit, not a signal or a spawn error) and its stderr carries
 * the shared sentence "mutually exclusive; pass exactly one" naming the two
 * inputs; the six tiers with `--source`/`--ir` use the verbatim Go text, TS
 * names its own flags (source files and --from-ir). Ruby given --hex and --asm
 * exits non-zero with Go's text. Go rows are green controls.
 * Does not prove: that no output is produced before the refusal (stdout is not
 * asserted), or the --hex/--asm combination in tiers other than Go and Ruby.
 */

const SRC = join(REPO, 'examples/ts/p2pkh/P2PKH.runar.ts');
const IR = join(REPO, 'conformance/tests/basic-p2pkh/expected-ir.json');

const INPUTS = 'Error: --source and --ir are mutually exclusive; pass exactly one';
const TS_INPUTS = 'Error: source files and --from-ir are mutually exclusive; pass exactly one';
const OUTPUTS = 'Error: --hex and --asm are mutually exclusive; pass exactly one';

const BOTH_INPUTS: Record<string, { args: string[]; msg: string }> = {
  ts: { args: [SRC, '--from-ir', IR, '--hex'], msg: TS_INPUTS },
  go: { args: ['--source', SRC, '--ir', IR, '--hex'], msg: INPUTS },
  rust: { args: ['--source', SRC, '--ir', IR, '--hex'], msg: INPUTS },
  python: { args: ['--source', SRC, '--ir', IR, '--hex'], msg: INPUTS },
  ruby: { args: ['--source', SRC, '--ir', IR, '--hex'], msg: INPUTS },
  java: { args: ['--source', SRC, '--ir', IR, '--hex'], msg: INPUTS },
  zig: { args: ['--source', SRC, '--ir', IR, '--hex'], msg: INPUTS },
};

function run(tier: Tier, args: string[]) {
  const res = spawnSync(tier.cmd!, [...tier.prefix, ...args], {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  return { res, text: `${res.stderr ?? ''}${res.stdout ?? ''}` };
}

const TIERS = buildSourceTiers();
const available = TIERS.filter((t) => t.cmd !== null);

describe('N-220: a CLI given both a source and an IR input refuses (7 tiers)', () => {
  it('the matrix names all seven tiers', () => {
    expect(TIERS.map((t) => t.id).sort()).toEqual([...ALL_TIER_IDS].sort());
  });

  it('every tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (isCiEnv(process.env)) expect(missing).toEqual([]);
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  for (const tier of available) {
    it(`${tier.id}: source + IR exits non-zero with the mutual-exclusion diagnostic`, () => {
      const row = BOTH_INPUTS[tier.id]!;
      const { res, text } = run(tier, row.args);
      expect(res.error, `${tier.id} could not run`).toBeUndefined();
      expect(res.signal).toBeNull();
      expect(res.status).not.toBe(0);
      expect(res.status).not.toBeNull();
      expect(text).toContain(row.msg);
    });
  }

  it('ruby: --hex together with --asm exits non-zero with Go\'s diagnostic', () => {
    for (const id of ['go', 'ruby']) {
      const tier = available.find((t) => t.id === id);
      if (!tier) continue;
      const { res, text } = run(tier, ['--source', SRC, '--hex', '--asm']);
      expect(res.error).toBeUndefined();
      expect(res.signal).toBeNull();
      expect(res.status, `${id} stdout/stderr: ${text.slice(0, 200)}`).not.toBe(0);
      expect(text).toContain(OUTPUTS);
    }
  });
});
