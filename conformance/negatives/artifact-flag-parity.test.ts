import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { ALL_TIER_IDS, BrokenTier, REPO, Tier, buildSourceTiers } from './tier-harness.js';

/**
 * N-139 — artifact `abi.methods[].isTerminal` and top-level `anf` presence
 * follow `parentClass`, identically in all seven tiers.
 *
 * Every tier derived "is this contract stateful?" for the artifact from
 * `stateFields.length > 0` (TS only for `anf`; Go, Ruby and Java for both;
 * Rust for `isTerminal` while always emitting `anf`; Zig emitted no
 * `isTerminal` at all and always emitted `anf`). For a StatefulSmartContract
 * with ZERO mutable fields (the issue-#44 `all-readonly-cleanstack` shape) the
 * tiers therefore disagreed on what the SDK is told about the contract, even
 * though the locking script is byte-identical. F-192 fixed Python alone.
 *
 * The rule, set by the TS reference: a public method of a
 * `StatefulSmartContract` that builds no continuation is terminal, and a
 * `StatefulSmartContract` artifact carries its ANF; a `SmartContract` artifact
 * carries neither.
 *
 * Proves: for the three contracts below (zero-mutable-field stateful,
 * ordinary stateful counter, stateless P2PKH control) each tier's
 * source-compiled artifact carries the expected parentClass, per-method
 * isTerminal, and presence/absence of top-level `anf`, and so all seven agree.
 * Does not prove: anything about the `--ir` path's artifact, `stateFields`
 * shape parity (Zig emits `stateFields: []` where TS omits the key), the
 * debug-only `ir` snapshot, or that the SDKs act correctly on the flags.
 */

type Flags = {
  parentClass: string | undefined;
  methods: Array<[string, boolean | null]>;
  hasAnf: boolean;
};

const CASES: Array<{ fixture: string; expected: Flags }> = [
  {
    fixture: 'all-readonly-cleanstack',
    expected: {
      parentClass: 'StatefulSmartContract',
      methods: [['claim', true]],
      hasAnf: true,
    },
  },
  {
    fixture: 'stateful-counter',
    expected: {
      parentClass: 'StatefulSmartContract',
      methods: [
        ['increment', null],
        ['decrement', null],
      ],
      hasAnf: true,
    },
  },
  {
    fixture: 'basic-p2pkh',
    expected: {
      parentClass: 'SmartContract',
      methods: [['unlock', null]],
      hasAnf: false,
    },
  },
];

function tsSource(fixture: string): string {
  const dir = join(REPO, 'conformance/tests', fixture);
  const cfg = JSON.parse(readFileSync(join(dir, 'source.json'), 'utf8')) as {
    sources: Record<string, string>;
  };
  return resolve(dir, cfg.sources['.runar.ts']!);
}

const OUT = mkdtempSync(join(tmpdir(), 'n139-artifact-flags-'));

/** Per-tier argv that writes the full artifact JSON (not `--hex`). */
function artifactArgs(tier: Tier, src: string): { args: string[]; file: string | null } {
  switch (tier.id) {
    case 'ts': {
      const dir = mkdtempSync(join(OUT, 'ts-'));
      return { args: [src, '-o', dir], file: dir };
    }
    case 'zig':
      return { args: ['compile', src], file: null };
    case 'java': {
      const file = join(mkdtempSync(join(OUT, 'java-')), 'artifact.json');
      return { args: ['--source', src, '--emit-artifact', file], file };
    }
    default:
      return { args: ['--source', src], file: null };
  }
}

function compileArtifact(tier: Tier, src: string): Record<string, any> {
  if (tier.cmd === null) throw new BrokenTier(`${tier.id}: no toolchain`);
  const { args, file } = artifactArgs(tier, src);
  const argv = [...tier.prefix, ...args];
  const res = spawnSync(tier.cmd, argv, {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  const where = `${tier.id} (${tier.cmd} ${argv.join(' ')})`;
  if (res.error) throw new BrokenTier(`${where} could not run: ${res.error.message}`);
  if (res.signal !== null) throw new BrokenTier(`${where} killed by ${res.signal}`);
  if (res.status !== 0) {
    throw new BrokenTier(`${where} exited ${res.status}: ${`${res.stderr}\n${res.stdout}`.slice(0, 600)}`);
  }
  let text: string;
  if (file === null) {
    text = res.stdout ?? '';
  } else if (tier.id === 'ts') {
    const jsons = readdirSync(file).filter((f) => f.endsWith('.json'));
    if (jsons.length !== 1) throw new BrokenTier(`${where} wrote ${jsons.length} artifacts`);
    text = readFileSync(join(file, jsons[0]!), 'utf8');
  } else {
    text = readFileSync(file, 'utf8');
  }
  return JSON.parse(text) as Record<string, any>;
}

function flags(artifact: Record<string, any>): Flags {
  return {
    parentClass: artifact.parentClass,
    methods: (artifact.abi.methods as Array<Record<string, any>>)
      .filter((m) => m.isPublic)
      .map((m) => [m.name as string, (m.isTerminal as boolean | undefined) ?? null]),
    hasAnf: artifact.anf !== undefined && artifact.anf !== null,
  };
}

const TIERS = buildSourceTiers();
const available = TIERS.filter((t) => t.cmd !== null);

describe('N-139: artifact isTerminal + anf presence follow parentClass (7 tiers)', () => {
  it('the matrix names all seven tiers', () => {
    expect(TIERS.map((t) => t.id).sort()).toEqual([...ALL_TIER_IDS].sort());
  });

  it('every tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (process.env.CI === 'true') expect(missing).toEqual([]);
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  for (const tier of available) {
    for (const c of CASES) {
      it(`${tier.id}: ${c.fixture} artifact flags`, () => {
        expect(flags(compileArtifact(tier, tsSource(c.fixture)))).toEqual(c.expected);
      });
    }
  }
});
