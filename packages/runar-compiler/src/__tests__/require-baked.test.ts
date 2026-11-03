/**
 * `requireBaked` compile option — kills the silent-elimination footgun.
 *
 * A readonly property no method references is dropped from the compiled
 * script entirely; its value then exists nowhere on-chain and cannot be
 * verified by any downstream contract. `requireBaked: ['prop']` turns that
 * silent elimination into a compile error, in both template mode (no
 * constructorArgs — SDK bakes at deploy) and baked mode (constructorArgs
 * provided at compile time).
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

const SOURCE = `
import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class EacShaped extends StatefulSmartContract {
  owner: PubKey;
  quantityWh: bigint;

  readonly issuer: PubKey;
  readonly source: bigint;
  /** Never referenced — the compiler eliminates it. */
  readonly tokenId: ByteString;

  constructor(owner: PubKey, quantityWh: bigint, issuer: PubKey, source: bigint, tokenId: ByteString) {
    super(owner, quantityWh, issuer, source, tokenId);
    this.owner = owner;
    this.quantityWh = quantityWh;
    this.issuer = issuer;
    this.source = source;
    this.tokenId = tokenId;
  }

  public withdraw(sig: Sig, outputSatoshis: bigint) {
    assert(checkSig(sig, this.issuer));
    assert(this.source >= 1n);
    assert(outputSatoshis >= 1n);
    this.addOutput(outputSatoshis, this.owner, this.quantityWh);
  }
}
`;

const OWNER = '02' + '11'.repeat(32);
const ISSUER = '03' + 'ab'.repeat(32);

describe('requireBaked (template mode)', () => {
  it('passes for referenced readonly props (they become constructor slots)', () => {
    const result = compile(SOURCE, {
      fileName: 'EacShaped.runar.ts',
      requireBaked: ['issuer', 'source'],
    });
    expect(result.success, JSON.stringify(result.diagnostics)).toBe(true);
    const slotNames = result.artifact!.constructorSlots!.map(s => s.name);
    expect(slotNames).toContain('issuer');
    expect(slotNames).toContain('source');
  });

  it('FAILS for an eliminated (unreferenced) readonly prop — the iteration-003 footgun', () => {
    const result = compile(SOURCE, {
      fileName: 'EacShaped.runar.ts',
      requireBaked: ['tokenId'],
    });
    expect(result.success).toBe(false);
    expect(result.artifact).toBeUndefined();
    const msgs = result.diagnostics.map(d => d.message).join('\n');
    expect(msgs).toMatch(/tokenId.*not referenced by any method body/s);
    expect(msgs).toMatch(/ELIMINATES/);
  });

  it('FAILS for an unknown property name', () => {
    const result = compile(SOURCE, {
      fileName: 'EacShaped.runar.ts',
      requireBaked: ['isuer'], // typo
    });
    expect(result.success).toBe(false);
    expect(result.diagnostics.map(d => d.message).join('\n'))
      .toMatch(/'isuer' is not a property/);
  });

  it('FAILS for a mutable state field (state tail, not a code slot)', () => {
    const result = compile(SOURCE, {
      fileName: 'EacShaped.runar.ts',
      requireBaked: ['quantityWh'],
    });
    expect(result.success).toBe(false);
    expect(result.diagnostics.map(d => d.message).join('\n'))
      .toMatch(/'quantityWh' is mutable state/);
  });
});

describe('requireBaked (baked mode — constructorArgs at compile time)', () => {
  const constructorArgs = {
    owner: OWNER,
    quantityWh: 10n,
    issuer: ISSUER,
    source: 1n,
    tokenId: 'deadbeef',
  };

  it('passes for referenced props baked via constructorArgs', () => {
    const result = compile(SOURCE, {
      fileName: 'EacShaped.runar.ts',
      constructorArgs,
      requireBaked: ['issuer', 'source'],
    });
    expect(result.success, JSON.stringify(result.diagnostics)).toBe(true);
    // The baked issuer bytes are really in the script.
    expect(result.artifact!.script).toContain(ISSUER);
  });

  it('FAILS for an eliminated prop even when a value was supplied for it', () => {
    const result = compile(SOURCE, {
      fileName: 'EacShaped.runar.ts',
      constructorArgs,
      requireBaked: ['tokenId'],
    });
    expect(result.success).toBe(false);
    expect(result.diagnostics.map(d => d.message).join('\n'))
      .toMatch(/tokenId.*not referenced by any method body/s);
  });
});

describe('requireBaked is opt-in', () => {
  it('omitting the option changes nothing (eliminated prop still compiles)', () => {
    const result = compile(SOURCE, { fileName: 'EacShaped.runar.ts' });
    expect(result.success).toBe(true);
    expect(result.artifact!.constructorSlots!.find(s => s.name === 'tokenId')).toBeUndefined();
  });
});

/**
 * F-111: the pre-fold reference check alone is not enough in baked mode.
 * Constant folding (ANF) and stack-level folding/peephole can erase the only
 * push of a baked required value — e.g. `this.source * 0n === 0n` folds to
 * `OP_0 OP_0 OP_NUMEQUALVERIFY` — leaving no commitment to it in the script.
 *
 * Proves: for each refuter body, in both baked modes (property initializer and
 * constructorArgs), compilation FAILS with the shared diagnostic; legitimate
 * baked/template uses still compile and the baked value's push is present.
 * Does NOT prove: that a surviving push is semantically load-bearing (a
 * value that is pushed and compared still counts as committed), nor anything
 * about non-TS tiers (requireBaked is a TS-compiler-only option).
 */
describe('requireBaked survives optimization (F-111)', () => {
  const mk = (mode: 'init' | 'args' | 'template', body: string) => `
import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  readonly source: bigint${mode === 'init' ? ' = 1n' : ''};

  constructor(${mode === 'init' ? '' : 'source: bigint'}) {
    super(${mode === 'init' ? '' : 'source'});
    ${mode === 'init' ? '' : 'this.source = source;'}
  }

  public m(x: bigint) {
    ${body}
    assert(x >= 0n);
  }
}
`;
  const opts = (mode: 'init' | 'args' | 'template') => ({
    fileName: 'C.runar.ts',
    requireBaked: ['source'],
    ...(mode === 'args' ? { constructorArgs: { source: 1n } } : {}),
  });

  const ERASING_BODIES = [
    'assert(this.source * 0n === 0n);',
    'assert(this.source - this.source === 0n);',
    'const k = this.source; assert(k + 1n > 1n);',
  ];

  for (const mode of ['init', 'args'] as const) {
    for (const body of ERASING_BODIES) {
      it(`FAILS when optimization erases the baked commitment (${mode}): ${body}`, () => {
        const result = compile(mk(mode, body), opts(mode));
        expect(result.success, result.artifact?.asm).toBe(false);
        expect(result.artifact).toBeUndefined();
        expect(result.diagnostics.map(d => d.message).join('\n')).toMatch(
          /requireBaked property 'source' has no on-chain commitment after optimization/,
        );
      });
    }

    it(`passes when the baked value survives (${mode}): assert(this.source >= 1n)`, () => {
      const result = compile(mk(mode, 'assert(this.source >= 1n);'), opts(mode));
      expect(result.success, JSON.stringify(result.diagnostics)).toBe(true);
      expect(result.artifact!.asm).toMatch(/^OP_1 OP_1 OP_GREATERTHANOREQUAL/);
    });

    it(`erasing bodies still compile without requireBaked (${mode}) — opt-in`, () => {
      const { requireBaked: _unused, ...rest } = opts(mode);
      void _unused;
      const result = compile(mk(mode, ERASING_BODIES[0]!), rest);
      expect(result.success, JSON.stringify(result.diagnostics)).toBe(true);
    });
  }

  for (const body of ERASING_BODIES) {
    it(`template mode keeps the constructor slot: ${body}`, () => {
      const result = compile(mk('template', body), opts('template'));
      expect(result.success, JSON.stringify(result.diagnostics)).toBe(true);
      expect(result.artifact!.constructorSlots!.map(s => s.name)).toContain('source');
    });
  }
});
