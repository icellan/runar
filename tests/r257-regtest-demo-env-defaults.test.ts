/**
 * R-257 (CL-DOC-028): the regtest demos' header comments document RPC
 * credential defaults that are not the defaults.
 *
 *   ts/regtest-demo.ts:18-19          "RPC_USER - RPC username (default: rpc)"
 *   ts/regtest-demo-settle.ts:23-24   same
 *   the code, in both                 process.env.RPC_USER ?? 'bitcoin'
 *
 * The Ruby equivalent documents it correctly, which is what makes this a typo
 * rather than a convention.
 *
 * It is a demo script, so the cost is small and specific: someone configures
 * their node with rpcuser=rpc because the header told them that is what the
 * script expects, the script then authenticates as `bitcoin`, and they debug a
 * 401 against a regtest node instead of running the demo.
 *
 * The test reads the documented default out of the header and the real one out
 * of the code, for every demo that documents any, and requires them to agree —
 * so the next edit to either side has to move both.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const DEMOS = [
  'examples/end2end-example/ts/regtest-demo.ts',
  'examples/end2end-example/ts/regtest-demo-settle.ts',
];

const VARS = ['RPC_URL', 'RPC_USER', 'RPC_PASS'];

/** `RPC_USER  - RPC username (default: rpc)` -> "rpc" */
function documentedDefault(src: string, name: string): string | undefined {
  const line = src.split('\n').find((l) => l.includes(`${name} `) && l.includes('(default:'));
  return line?.match(/\(default:\s*([^)]+)\)/)?.[1]?.trim();
}

/** `process.env.RPC_USER ?? 'bitcoin'` -> "bitcoin" */
function actualDefault(src: string, name: string): string | undefined {
  return src.match(new RegExp(`process\\.env\\.${name}\\s*\\?\\?\\s*'([^']*)'`))?.[1];
}

describe('R-257: the regtest demos document the defaults they use', () => {
  it('the demos exist and the scan finds their defaults', () => {
    for (const rel of DEMOS) {
      expect(existsSync(join(ROOT, rel)), `${rel} is gone`).toBe(true);
      const src = readFileSync(join(ROOT, rel), 'utf8');
      for (const v of VARS) {
        expect(actualDefault(src, v), `${rel}: no code default found for ${v}`).toBeDefined();
        expect(documentedDefault(src, v), `${rel}: ${v} is undocumented`).toBeDefined();
      }
    }
  });

  for (const rel of DEMOS) {
    for (const v of VARS) {
      it(`${rel} documents ${v} correctly`, () => {
        const src = readFileSync(join(ROOT, rel), 'utf8');
        expect(
          documentedDefault(src, v),
          `${rel} tells the reader ${v} defaults to "${documentedDefault(src, v)}" ` +
            `while the code uses "${actualDefault(src, v)}"`,
        ).toBe(actualDefault(src, v));
      });
    }
  }
});
