import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-141 — seven-tier parity for the scope of a `.runar.sol` for-init variable
 * that shadows a property.
 *
 * `for (bigint count = 0; ...) { ... }` in a contract that also has a `count`
 * property: the loop variable is visible only inside the loop (the init, the
 * condition, the update and the body). After the loop a bare `count` is
 * `this.count` again. spec/semantics.md §loops treats the loop variable as a
 * compile-time constant substituted into each unrolled copy of the body, i.e.
 * it has no existence after the loop.
 *
 * The TS reference's `resolvePropertyAccess` added the for-init name to the
 * OUTER paramNames set, so it kept shadowing the property after the loop. A
 * post-loop READ happened to lower to the same bytes anyway (the unresolved
 * identifier falls back to the property later), but a post-loop WRITE
 * (`count = n;`) became an assignment to a plain identifier and the state
 * update was silently dropped: TS emitted a 956-char script, the other six
 * tiers a 1416-char one that carries the state continuation.
 *
 * What this proves: every available tier's CLI (fold-ON default) compiles the
 * post-loop read, the post-loop write, an inside-loop control and a nested-if
 * shape to the same bytes, pinned by sha256 to the block-scoped (six-tier)
 * output so the tiers drifting together still fails.
 * What it does NOT prove: on-chain spend behaviour of the bytes, fold-OFF
 * output, or the other eight surfaces (they have no bare-property syntax).
 */

const SHAPES: Record<string, { src: string; sha256: string }> = {
  'N141Read.runar.sol': {
    src: `pragma runar ^0.1.0;

contract N141Read is SmartContract {
    bigint immutable count;

    constructor(bigint _count) {
        count = _count;
    }

    function f(bigint n) public {
        for (bigint count = 0; count < 3; count++) { n = n + 1; }
        require(count == n);
    }
}
`,
    sha256: '7f4bad3f19e30d39b3a36207187783459061660c620faca35875692e11b84f25',
  },
  'N141Write.runar.sol': {
    src: `pragma runar ^0.1.0;

contract N141Write is StatefulSmartContract {
    bigint count;

    constructor(bigint _count) {
        count = _count;
    }

    function f(bigint n) public {
        for (bigint count = 0; count < 3; count++) { n = n + 1; }
        count = n;
    }
}
`,
    sha256: 'c65b82fd47da7a040cd7fe734f2717305b87ad9c2d7c3f4e953309ef54094cf6',
  },
  'N141Inside.runar.sol': {
    src: `pragma runar ^0.1.0;

contract N141Inside is SmartContract {
    bigint immutable count;

    constructor(bigint _count) {
        count = _count;
    }

    function f(bigint n) public {
        for (bigint count = 0; count < 3; count++) { n = n + count; }
        require(n == 3);
    }
}
`,
    sha256: '5e63d5cc5f54cde7d760673768e82535fecd25825e7c35e118735b906ee080b8',
  },
  'N141Nested.runar.sol': {
    src: `pragma runar ^0.1.0;

contract N141Nested is SmartContract {
    bigint immutable count;

    constructor(bigint _count) {
        count = _count;
    }

    function f(bigint n) public {
        for (bigint count = 0; count < 3; count++) {
            if (n >= 0) { n = n + count; }
        }
        if (n >= 0) { n = n + count; }
        require(n >= 0);
    }
}
`,
    sha256: '8089107bb18051464cdbc9366a0fcfa34689f13b70cff3ae03d71df944fecce3',
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
  dir = mkdtempSync(join(tmpdir(), 'n141-sol-for-init-scope-'));
});

describe('N-141 .runar.sol for-init variable scope — seven-tier positive parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [name, { src, sha256 }] of Object.entries(SHAPES)) {
    for (const tier of TIERS) {
      it(`${tier.id} compiles ${name} to the block-scoped bytes`, () => {
        const p = join(dir, name);
        writeFileSync(p, src);
        expect(compileSha(tier, p)).toBe(sha256);
      });
    }
  }
});
