/**
 * Locate data files shipped at the package root.
 *
 * The module runs from `<pkg>/src/` under tsx/vitest and from
 * `<pkg>/dist/src/` once built (tsconfig `rootDir: "."`), so a fixed
 * `'..'` from `__dirname` is wrong in one of the two layouts. Walk up to
 * the directory whose package.json names this package instead.
 */

import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const PACKAGE_NAME = 'runar-decompiler';

function findPackageRoot(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (;;) {
    const pj = join(dir, 'package.json');
    if (existsSync(pj)) {
      try {
        if ((JSON.parse(readFileSync(pj, 'utf8')) as { name?: string }).name === PACKAGE_NAME) {
          return dir;
        }
      } catch {
        // unreadable package.json — keep walking
      }
    }
    const parent = dirname(dir);
    if (parent === dir) {
      throw new Error(`${PACKAGE_NAME}: cannot locate package root from ${fileURLToPath(import.meta.url)}`);
    }
    dir = parent;
  }
}

/** Absolute path of `<package root>/<name>`. */
export function packageDataPath(name: string): string {
  return join(findPackageRoot(), name);
}
