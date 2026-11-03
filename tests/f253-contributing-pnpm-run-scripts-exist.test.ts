/**
 * F-253: `pnpm test:ci`'s "green here -> green CI" contract is violated when
 * CONTRIBUTING.md tells a contributor to run a command that does not exist.
 *
 * The defect: CONTRIBUTING.md's "Conformance Discipline" section said
 *
 *     SDK changes additionally need coverage in `conformance/sdk-output/`
 *     ... run `pnpm run sdk-output`.
 *
 * There is no `sdk-output` key under root package.json#scripts — the actual
 * root-runnable script is `conformance:sdk`. A contributor who copy-pastes
 * the documented command from the repo root gets a pnpm "Missing script"
 * error, not SDK coverage. The same section also documented
 * `pnpm run update-golden` without the `cd conformance &&` context that
 * script needs — `update-golden` only exists under
 * `conformance/package.json#scripts`, not the root one.
 *
 * This test parses CONTRIBUTING.md for every backtick-quoted
 * `[cd <dir> && ]pnpm run <name>` command and asserts `<name>` is a real key
 * under the scripts of whichever package.json pnpm would actually consult —
 * `<dir>/package.json` when a `cd <dir> &&` prefix is present, the root
 * `package.json` otherwise. It does not check `pnpm <name>` (no "run")
 * forms, or that the command is the RIGHT one for its surrounding prose —
 * only that a reader who runs exactly what the document says, from exactly
 * the directory the document says, gets a script pnpm can find.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CONTRIBUTING_MD = resolve(REPO_ROOT, 'CONTRIBUTING.md');

function readScripts(pkgJsonPath: string): Record<string, string> {
  const pkg = JSON.parse(readFileSync(pkgJsonPath, 'utf-8')) as { scripts?: Record<string, string> };
  return pkg.scripts ?? {};
}

describe('CONTRIBUTING.md: every documented `pnpm run <name>` command exists', () => {
  it('every `[cd <dir> &&] pnpm run <name>` backtick command names a real package.json script', () => {
    const doc = readFileSync(CONTRIBUTING_MD, 'utf-8');

    const COMMAND = /`(?:cd ([a-zA-Z0-9_/-]+) && )?pnpm run ([a-zA-Z0-9:_-]+)`/g;
    const matches = [...doc.matchAll(COMMAND)].map((m) => ({ dir: m[1], name: m[2]! }));

    // A regex that silently matches nothing proves nothing.
    expect(matches.length, 'the `pnpm run <name>` regex matched nothing — CONTRIBUTING.md changed shape').toBeGreaterThan(0);

    const missing: string[] = [];
    for (const { dir, name } of matches) {
      const pkgJsonPath = resolve(REPO_ROOT, dir ?? '.', 'package.json');
      if (!existsSync(pkgJsonPath)) {
        missing.push(`'cd ${dir} && pnpm run ${name}' — ${pkgJsonPath} does not exist`);
        continue;
      }
      const scripts = readScripts(pkgJsonPath);
      if (!(name in scripts)) {
        missing.push(
          dir ? `'cd ${dir} && pnpm run ${name}' — no '${name}' script in ${dir}/package.json`
              : `'pnpm run ${name}' — no '${name}' script in root package.json`,
        );
      }
    }

    expect(
      missing,
      `CONTRIBUTING.md documents a 'pnpm run <name>' command that does not ` +
        `resolve to a real script from the directory it names. Fix the ` +
        `document to name the real script (and/or the directory to run it from).`,
    ).toEqual([]);
  });
});
