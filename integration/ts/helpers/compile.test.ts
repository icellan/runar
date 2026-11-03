/**
 * Unit test for the compile helper's error reporting (N-058).
 *
 * `CompileResult` (packages/runar-compiler/src/index.ts) exposes compiler
 * failures through `diagnostics`, not `errors` — `errors` does not exist on
 * the type. `compileContract`/`compileSource` below were still reading
 * `result.errors`, which is `undefined` at runtime, so a failed compile threw
 * `Compile failed: undefined` instead of surfacing the real diagnostic.
 *
 * This test proves the thrown message carries the actual diagnostic text.
 * It does NOT prove the integration suite was "silently broken" in the sense
 * of a bad compile passing a test — the helper still throws either way, so a
 * test depending on it still fails. What was lost is the diagnostic detail
 * that would help someone understand WHY a contract failed to compile.
 *
 * Runs under the project's normal `vitest.config.ts` (which requires a live
 * regtest node via `setup.ts`) when the integration suite runs as a whole.
 * For a node-less run of just this file, point vitest at an alternate config
 * with no `globalSetup`, e.g.:
 *   npx vitest run helpers/compile.test.ts -c <alt-config-without-globalSetup>
 */

import { describe, it, expect } from 'vitest';
import { compileSource } from './compile.js';

describe('compileSource error reporting', () => {
  it('surfaces the compiler diagnostic message on a failed compile, not "undefined"', () => {
    // Missing constructor — a real, stable validate-pass diagnostic.
    const badSource = `
import { SmartContract } from 'runar-lang';
export class Bad extends SmartContract {
  public doThing(): void {}
}
`;

    let thrown: Error | undefined;
    try {
      compileSource(badSource, 'Bad.runar.ts');
    } catch (e) {
      thrown = e as Error;
    }

    expect(thrown).toBeDefined();
    expect(thrown!.message).toMatch(/constructor/i);
    expect(thrown!.message).not.toContain('undefined');
  });
});
