import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers } from './tier-harness.js';

/**
 * F-200 — seven-tier positive parity for `.runar.sol` METHOD params whose
 * name starts with `_`.
 *
 * The TS reference (01-parse-sol.ts) strips a leading `_` only from
 * CONSTRUCTOR params, and renames the constructor body to match;
 * `parseFunction` keeps method param names verbatim. Python and Ruby stripped
 * it from every param without renaming method bodies, so:
 *   - UNBOUND (`check(bigint _x) { require(_x == target); }`) failed
 *     typecheck with "Undefined variable '_x'";
 *   - SILENT (`inc(bigint _count) { count++; }`) declared a param `count`
 *     that shadowed the property, so the state write was dropped and a
 *     different script came out;
 *   - INTER is both at once.
 *
 * Go, Zig and Java shared that root cause (same unconditional strip in their
 * .sol param parser) and were fixed the same way under N-142, so every tier
 * now runs as a plain `it`.
 *
 * What this proves: every available tier's CLI (fold-ON default) compiles all
 * three shapes to the TS reference bytes, pinned by sha256 / literal so the
 * tiers drifting together still fails.
 * What it does NOT prove: on-chain spend behaviour of the bytes, fold-OFF
 * output, or the other eight surfaces (their parsers have no `_` convention).
 */

const SHAPES: Record<string, { src: string; sha256: string }> = {
  'F200Unbound.runar.sol': {
    src: `pragma runar ^0.1.0;

contract F200Unbound is SmartContract {
    bigint immutable target;

    constructor(bigint _target) {
        target = _target;
    }

    function check(bigint _x) public {
        require(_x == target);
    }
}
`,
    // hex 009c
    sha256: 'dc2b145ead28127d4aa01a70ecda4f057258e845f109b0f6fcd181ea4fc5983d',
  },
  'F200Silent.runar.sol': {
    src: `pragma runar ^0.1.0;

contract F200Silent is StatefulSmartContract {
    bigint count;

    constructor(bigint _count) {
        count = _count;
    }

    function inc(bigint _count) public {
        count++;
    }
}
`,
    sha256: '3676c0b9030628828837696cad74c710bb225d151f5ba822be8b2ed302e3a342',
  },
  'F200Inter.runar.sol': {
    src: `pragma runar ^0.1.0;

contract F200Inter is StatefulSmartContract {
    bigint count;

    constructor(bigint _count) {
        count = _count;
    }

    function inc(bigint _count) public {
        count++;
        require(_count > 0);
    }
}
`,
    sha256: '3cb777cf55b26a89a9f9a9664dd259f63f343bd347e4057c859ab0454526e521',
  },
};

function compileSha(tier: Tier, file: string): string {
  const r = spawnSync(tier.cmd!, [...tier.prefix, ...tier.argsFor(file)], {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.error) throw new Error(`${tier.id} could not run: ${r.error.message}`);
  const stdout = r.stdout ?? '';
  const hexLines = stdout.split(/\r?\n/).map((l) => l.trim()).filter((l) => /^[0-9a-f]+$/i.test(l));
  if (r.status !== 0 || hexLines.length === 0) {
    throw new Error(`${tier.id} ${file}: exit ${r.status}\n${`${stdout}\n${r.stderr ?? ''}`.slice(0, 800)}`);
  }
  return createHash('sha256').update(hexLines[hexLines.length - 1]!.toLowerCase()).digest('hex');
}

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
let dir = '';

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'f200-sol-param-underscore-'));
});

describe('F-200 .runar.sol method param leading underscore — seven-tier positive parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (process.env.CI === 'true') expect(TIERS.length).toBe(7);
  });

  for (const [name, { src, sha256 }] of Object.entries(SHAPES)) {
    for (const tier of TIERS) {
      it(`${tier.id} compiles ${name} to the TS reference bytes`, () => {
        const p = join(dir, name);
        writeFileSync(p, src);
        expect(compileSha(tier, p)).toBe(sha256);
      });
    }
  }
});
