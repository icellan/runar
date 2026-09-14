import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';

/**
 * R-209 — `@embedAlways` and `@sighash` are real compiler features that had
 * ZERO example usage anywhere: no `examples/`, no conformance fixture, no
 * mention in `docs/`. They were discoverable only by reading the compiler's own
 * unit tests.
 *
 * An example that merely compiles would not be worth much — a directive the
 * compiler silently ignored would also compile. Each case here pins the
 * OBSERVABLE the directive is for, and the last two remove the directive and
 * show the observable goes away, so the example cannot rot into decoration.
 */

const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'Directives.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

/** SIGHASH_SINGLE (0x03) | SIGHASH_FORKID (0x40). */
const SINGLE_FORKID = 0x43;

function build(src: string) {
  const r = compile(src, { fileName: FILE });
  expect(r.success, r.diagnostics.map((d) => d.message).join('; ')).toBe(true);
  return r;
}

describe('compiler directives', () => {
  it('@embedAlways keeps a readonly field the body never reads', () => {
    const r = build(source);
    // The observable is `constructorSlots` — the byte offsets the deploy-time
    // values are spliced into — NOT `abi.constructor.params`, which lists the
    // DECLARED signature and keeps the parameter either way. Asserting on the
    // ABI would pass with the directive deleted; the falsification case below
    // is what found that.
    const slots = (r.artifact!.constructorSlots ?? []).map((s) => s.name);
    expect(
      slots,
      'deployTag is referenced by no method, so only the directive gives it a slot',
    ).toContain('deployTag');
  });

  it('and compiles without the DCE warning', () => {
    const r = build(source);
    const dce = r.diagnostics.filter((d) => /eliminated by DCE/.test(d.message));
    expect(dce.map((d) => d.message)).toEqual([]);
  });

  it('@sighash sets the method it annotates, and only that one', () => {
    const r = build(source);
    const byName = new Map(r.artifact!.abi.methods.map((m) => [m.name, m]));
    expect(byName.get('spendSingle')?.sigHashType).toBe(SINGLE_FORKID);
    // The undirected method keeps the default, which the artifact omits.
    expect(byName.get('spendAll')?.sigHashType).toBeUndefined();
  });

  it('without @embedAlways the field is eliminated and the compiler says so', () => {
    // The falsification, kept in the example: if this passed with the directive
    // still present, the first case would be proving nothing.
    const stripped = source.replace('  /** @embedAlways */\n', '');
    expect(stripped, 'the directive line did not match, so this case is stale').not.toBe(source);

    const r = compile(stripped, { fileName: FILE });
    expect(r.success).toBe(true);
    const slots = (r.artifact!.constructorSlots ?? []).map((s) => s.name);
    expect(slots, 'deployTag kept its slot without the directive').not.toContain('deployTag');
    // The declared signature is unchanged — which is exactly why the ABI is the
    // wrong thing to assert on.
    expect(r.artifact!.abi.constructor.params.map((p) => p.name)).toContain('deployTag');
    expect(
      r.diagnostics.some((d) => /deployTag.*eliminated by DCE/s.test(d.message)),
      'the compiler dropped the field without warning',
    ).toBe(true);
  });

  it('without @sighash the method falls back to the default mode', () => {
    const stripped = source.replace('  /** @sighash SINGLE|FORKID */\n', '');
    expect(stripped, 'the directive line did not match, so this case is stale').not.toBe(source);

    const r = build(stripped);
    const byName = new Map(r.artifact!.abi.methods.map((m) => [m.name, m]));
    expect(byName.get('spendSingle')?.sigHashType).toBeUndefined();
  });
});
