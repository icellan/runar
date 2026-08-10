// ---------------------------------------------------------------------------
// Tests for runar-cli/commands/decompile.ts — the --semantic divergence warning
// is driven by an ACTUAL recompile check, not an assumption.
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, beforeAll, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';

// The FTK fixture lives in the decompiler package (sibling in the workspace).
const ftkHex = readFileSync(
  new URL('../../../decompiler/__tests__/fixtures/ftk-demo.hex', import.meta.url),
  'utf8',
).trim();

describe('decompileCommand --semantic divergence warning', () => {
  let decompileCommand: typeof import('../commands/decompile.js').decompileCommand;

  beforeAll(async () => {
    decompileCommand = (await import('../commands/decompile.js')).decompileCommand;
  }, 60_000);

  afterEach(() => vi.restoreAllMocks());

  function run(opts: import('../commands/decompile.js').DecompileOptions): string {
    const errs: string[] = [];
    vi.spyOn(process, 'exit').mockImplementation(((_c?: number) => undefined) as never);
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    vi.spyOn(process.stderr, 'write').mockImplementation((s: string | Uint8Array) => {
      errs.push(String(s));
      return true;
    });
    decompileCommand(ftkHex, opts);
    return errs.join('');
  }

  it('warns that recompiling the shown source diverges (checked) by default', () => {
    const err = run({ semantic: true });
    expect(err).toContain('WARNING');
    expect(err).toContain('does NOT reproduce');
    expect(err).toContain('[semantic]');
  }, 60_000);

  it('confirms byte-identity with --byte-exact and emits no warning', () => {
    const err = run({ semantic: true, byteExact: true });
    expect(err).toContain('[byte-exact]');
    expect(err).toContain('BYTE-IDENTICAL');
    expect(err).not.toContain('WARNING');
  }, 60_000);
});
