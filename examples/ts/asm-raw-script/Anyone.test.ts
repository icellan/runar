import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';
import { ScriptVM } from 'runar-testing';

/**
 * R-106 — `asm-raw-script` is the only example of the `UnsafeSmartContract` /
 * `asm()` escape hatch (R-099) and had no test in any of the nine formats.
 *
 * `asm({ body, in_arity, out_arity })` lowers to a `raw_script` node the
 * compiler does not interpret: DCE must not remove it, and nothing verifies the
 * declared arity. "Must not be removed" is a property with a cheap, exact test —
 * the whole locking script here IS the spliced byte — so it gets one.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'Anyone.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

describe('Anyone (the asm() raw-script escape hatch)', () => {
  it('splices the byte verbatim and emits nothing else', () => {
    const r = compile(source, { fileName: FILE });
    expect(r.success, r.diagnostics.map((d) => d.message).join('\n')).toBe(true);
    expect(
      r.artifact!.script,
      'the contract body is one asm() of OP_1, so the locking script is the ' +
        'single byte 51. Anything else means the splice was rewritten, padded ' +
        'or dropped.',
    ).toBe('51');
  });

  it('the raw_script node survives to the IR (DCE must never remove it)', () => {
    const r = compile(source, { fileName: FILE });
    const unlock = r.anf!.methods.find((m) => m.name === 'unlock');
    expect(unlock, 'the unlock method must survive lowering').toBeDefined();
    const kinds = unlock!.body.map((b) => b.value.kind);
    expect(
      kinds,
      'nothing references the asm() result, so a DCE that treats raw_script as ' +
        'effect-free would delete the entire contract body and still "compile"',
    ).toContain('raw_script');
  });

  it('the emitted script is spendable with an empty unlocking script', () => {
    const r = compile(source, { fileName: FILE });
    const vm = new ScriptVM();
    const result = vm.executeHex(r.artifact!.script);
    expect(
      result.success,
      'OP_1 leaves a truthy top-of-stack — this example is deliberately ' +
        'anyone-can-spend, and that is what makes it a useful asm() smoke test',
    ).toBe(true);
  });
});
