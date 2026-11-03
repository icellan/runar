/**
 * `@bindingVariant <lowS|all>` (ports #170; original design: brendan-elas,
 * #167): parse → MethodNode → check_preimage ANF node → stack lowering, the
 * same plumbing shape as `@sighash`. Fail-closed on the eight non-TS surfaces.
 * Execution of the two blobs lives in runar-testing's binding-variant.test.ts.
 */
import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { compile } from '../index.js';
import {
  CHECK_PREIMAGE_BINDING_HEX,
  CHECK_PREIMAGE_BINDING_ALL_HEX,
} from '../passes/oppushtx-codegen.js';
import {
  extractBindingVariantDirective,
  BINDING_VARIANT_MALFORMED_ERROR,
  BINDING_VARIANT_MULTIPLE_ERROR,
} from '../passes/bindingvariant-directive.js';
import { loadANFFromJSON } from '../index.js';

function errors(src: string, fileName = 'C.runar.ts'): string {
  return parse(src, fileName).errors.filter((e) => e.severity === 'error').map((e) => e.message).join('\n');
}

const counter = (directive: string, vis = 'public') => `
  class C extends StatefulSmartContract {
    n: bigint;
    constructor(n: bigint) { super(n); this.n = n; }
    ${directive}
    ${vis} bump(): void { this.n = this.n + 1n; }
  }`;

/** Every check_preimage node in the ANF, in walk order. */
function checkPreimages(anf: unknown): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  const walk = (n: unknown): void => {
    if (Array.isArray(n)) n.forEach(walk);
    else if (n && typeof n === 'object') {
      const r = n as Record<string, unknown>;
      if (r.kind === 'check_preimage') out.push(r);
      Object.values(r).forEach(walk);
    }
  };
  walk(anf);
  return out;
}

describe('extractBindingVariantDirective', () => {
  it.each([
    ['/** @bindingVariant all */', 'all'],
    ['/** @bindingVariant lowS */', 'lowS'],
    ['// @bindingVariant all', 'all'],
    ['/**\n * Pays out.\n * @bindingVariant all\n */', 'all'],
  ])('%j → %s', (text, value) => {
    expect(extractBindingVariantDirective(text)).toEqual({ value });
  });

  it('returns null without a marker', () => {
    expect(extractBindingVariantDirective('/** @sighash ALL|FORKID */')).toBeNull();
  });

  it.each([
    '/** @bindingVariant */',
    '/** @bindingVariant: all */',
    '/** @bindingVariant all; */',
    '/** @bindingVariantall */',
    '/** see @bindingVariant all — nVersion=1 */',
  ])('%j is malformed', (text) => {
    expect(extractBindingVariantDirective(text)).toEqual({ error: BINDING_VARIANT_MALFORMED_ERROR });
  });

  it.each(['All', 'low_s', 'high', 'all extra'])('unknown value %j is refused', (v) => {
    const r = extractBindingVariantDirective(`/** @bindingVariant ${v} */`);
    expect(r && 'error' in r ? r.error : '').toContain('unknown variant');
  });

  it('a second marker is refused', () => {
    expect(extractBindingVariantDirective('/** @bindingVariant all */\n// @bindingVariant lowS')).toEqual({
      error: BINDING_VARIANT_MULTIPLE_ERROR,
    });
  });
});

describe('@bindingVariant on the .runar.ts surface', () => {
  it('sets MethodNode.bindingVariant', () => {
    const r = parse(counter('/** @bindingVariant all */'), 'C.runar.ts');
    expect(r.errors.filter((e) => e.severity === 'error')).toEqual([]);
    expect(r.contract!.methods.find((m) => m.name === 'bump')!.bindingVariant).toBe('all');
  });

  it('refuses it on a private method', () => {
    expect(errors(counter('/** @bindingVariant all */', 'private'))).toContain(
      "@bindingVariant directive on non-public method 'bump' has no effect",
    );
  });

  it('refuses a malformed directive instead of defaulting', () => {
    expect(errors(counter('/** @bindingVariant: all */'))).toContain(BINDING_VARIANT_MALFORMED_ERROR);
  });

  it('refuses a directive that is not attached to a method (N-199 parity)', () => {
    const src = `
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        public bump(): void { this.n = this.n + 1n; } // @bindingVariant all
      }`;
    expect(errors(src)).toContain('@bindingVariant directive is not attached to any method');
  });
});

describe('@bindingVariant fails closed on the eight non-TS surfaces', () => {
  it.each([
    ['C.runar.sol', 'Solidity'],
    ['C.runar.move', 'Move'],
    ['C.runar.py', 'Python'],
    ['C.runar.go', 'Go DSL'],
    ['C.runar.rs', 'Rust'],
    ['C.runar.rb', 'Ruby'],
    ['C.runar.zig', 'Zig'],
    ['C.runar.java', 'Java'],
  ])('%s', (file, surface) => {
    expect(errors('// @bindingVariant all\n', file)).toBe(
      `@bindingVariant directive is not supported by the ${surface} surface parser; write the contract in TypeScript (.runar.ts), where @bindingVariant is honoured`,
    );
  });
});

describe('@bindingVariant through ANF and codegen', () => {
  it('absent ⇒ ANF carries no bindingVariant and the script holds the lowS blob', () => {
    const r = compile(counter(''), { fileName: 'C.runar.ts' });
    expect(r.success).toBe(true);
    expect(checkPreimages(r.anf).every((c) => !('bindingVariant' in c))).toBe(true);
    expect(r.artifact!.script).toContain(CHECK_PREIMAGE_BINDING_HEX);
  });

  it('explicit lowS ⇒ byte-identical to absent (ANF and script)', () => {
    const a = compile(counter(''), { fileName: 'C.runar.ts' });
    const b = compile(counter('/** @bindingVariant lowS */'), { fileName: 'C.runar.ts' });
    expect(b.artifact!.script).toBe(a.artifact!.script);
    const j = (x: unknown) => JSON.stringify(x, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
    expect(j(b.anf)).toBe(j(a.anf));
  });

  it("all ⇒ the auto-injected check_preimage carries bindingVariant 'all' and the all blob", () => {
    const r = compile(counter('/** @bindingVariant all */'), { fileName: 'C.runar.ts' });
    expect(r.success).toBe(true);
    expect(checkPreimages(r.anf).map((c) => c.bindingVariant)).toEqual(['all']);
    expect(r.artifact!.script).toContain(CHECK_PREIMAGE_BINDING_ALL_HEX);
    expect(r.artifact!.script).not.toContain(CHECK_PREIMAGE_BINDING_HEX);
  });

  it('composes with @sighash: the flag byte moves inside the all blob', () => {
    const r = compile(counter('/**\n * @sighash ALL|ANYONECANPAY|FORKID\n * @bindingVariant all\n */'), { fileName: 'C.runar.ts' });
    expect(r.success, (r.diagnostics ?? []).map((d) => d.message).join('\n')).toBe(true);
    expect(r.artifact!.script).toContain(CHECK_PREIMAGE_BINDING_ALL_HEX.replace(/0141(7e21[0-9a-f]{66}ad)$/, '01c1$1'));
  });

  it('nested loop and ternary arms inherit the method variant', () => {
    const src = `
      class G extends SmartContract {
        constructor() { super(); }
        /** @bindingVariant all */
        public unlock(a: SigHashPreimage, b: SigHashPreimage, c: SigHashPreimage, d: boolean) {
          for (let i = 0n; i < 1n; i++) {
            assert(checkPreimage(a));
          }
          const ok = d ? checkPreimage(b) : checkPreimage(c);
          assert(ok);
        }
      }`;
    const r = compile(src, { fileName: 'G.runar.ts' });
    expect(r.success, (r.diagnostics ?? []).map((d) => d.message).join('\n')).toBe(true);
    const nodes = checkPreimages(r.anf);
    expect(nodes.length).toBeGreaterThanOrEqual(3);
    expect(nodes.every((c) => c.bindingVariant === 'all')).toBe(true);
    expect(r.artifact!.script).not.toContain(CHECK_PREIMAGE_BINDING_HEX);
  });

  it('--ir: the loader accepts lowS/all and refuses any other bindingVariant', () => {
    const r = compile(counter('/** @bindingVariant all */'), { fileName: 'C.runar.ts' });
    const json = JSON.stringify(r.anf, (_k, v) => (typeof v === 'bigint' ? Number(v) : v));
    expect(() => loadANFFromJSON(json)).not.toThrow();
    const bad = json.replace('"bindingVariant":"all"', '"bindingVariant":"high"');
    expect(bad).not.toBe(json);
    expect(() => loadANFFromJSON(bad)).toThrow('bindingVariant must be "lowS" or "all"');
  });
});
