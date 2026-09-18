/**
 * Issue #109 — `/** @embedAlways *\/` readonly-field DCE opt-out.
 *
 * The compiler eliminates a readonly property that no method references
 * (an emergent effect of ANF dead-binding DCE: the dead `load_prop` is
 * dropped, so no constructor slot is emitted). This silently removes
 * deploy-time metadata fields an author intends to recover from the
 * on-chain script later.
 *
 * Two surfaces land here (TypeScript reference tier):
 *   - Option 1: a `/** @embedAlways *\/` comment directive on a readonly
 *     field forces it into the locking script (a constructor slot).
 *   - Option 4: an un-annotated, unreferenced readonly field emits a
 *     compile WARNING pointing at the directive.
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { parse } from '../passes/01-parse.js';

// A stateless contract with a metadata field the body never reads.
// `DIRECTIVE` is spliced in immediately before the `metadataId` field.
function source(directive: string): string {
  return `
import { SmartContract, assert, Addr, PubKey, Sig, ByteString, hash160, checkSig } from 'runar-lang';

class Meta extends SmartContract {
  readonly pubKeyHash: Addr;
  ${directive}
  readonly metadataId: ByteString;

  constructor(pubKeyHash: Addr, metadataId: ByteString) {
    super(pubKeyHash, metadataId);
    this.pubKeyHash = pubKeyHash;
    this.metadataId = metadataId;
  }

  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
`;
}

const WARN_RE =
  /readonly field 'metadataId' is not referenced .* eliminated by DCE.*@embedAlways/s;

describe('#109 parser: @embedAlways directive', () => {
  it('sets embedAlways on a field with a /** @embedAlways */ JSDoc directive', () => {
    const r = parse(source('/** @embedAlways */'), 'Meta.runar.ts');
    expect(r.errors.filter(e => e.severity === 'error')).toEqual([]);
    const prop = r.contract!.properties.find(p => p.name === 'metadataId')!;
    expect(prop.embedAlways).toBe(true);
    // Un-annotated sibling stays unset.
    const other = r.contract!.properties.find(p => p.name === 'pubKeyHash')!;
    expect(other.embedAlways).toBeFalsy();
  });

  it('recognizes a // @embedAlways line-comment directive too', () => {
    const r = parse(source('// @embedAlways'), 'Meta.runar.ts');
    const prop = r.contract!.properties.find(p => p.name === 'metadataId')!;
    expect(prop.embedAlways).toBe(true);
  });

  it('leaves embedAlways unset when there is no directive', () => {
    const r = parse(source(''), 'Meta.runar.ts');
    const prop = r.contract!.properties.find(p => p.name === 'metadataId')!;
    expect(prop.embedAlways).toBeFalsy();
  });
});

describe('#109 preservation: @embedAlways survives DCE into a constructor slot', () => {
  it('un-annotated: unreferenced readonly field is eliminated (no slot)', () => {
    const r = compile(source(''), { fileName: 'Meta.runar.ts' });
    expect(r.success, JSON.stringify(r.diagnostics)).toBe(true);
    const slotNames = r.artifact!.constructorSlots!.map(s => s.name);
    expect(slotNames).toContain('pubKeyHash');
    expect(slotNames).not.toContain('metadataId');
  });

  it('annotated: /** @embedAlways */ field is preserved (slot present)', () => {
    const r = compile(source('/** @embedAlways */'), { fileName: 'Meta.runar.ts' });
    expect(r.success, JSON.stringify(r.diagnostics)).toBe(true);
    const slotNames = r.artifact!.constructorSlots!.map(s => s.name);
    expect(slotNames).toContain('pubKeyHash');
    expect(slotNames).toContain('metadataId');
  });

  it('annotated hex carries more bytes than un-annotated (field bytes present)', () => {
    const off = compile(source(''), { fileName: 'Meta.runar.ts' });
    const on = compile(source('/** @embedAlways */'), { fileName: 'Meta.runar.ts' });
    expect(on.scriptHex).not.toEqual(off.scriptHex);
    expect(on.scriptHex!.length).toBeGreaterThan(off.scriptHex!.length);
  });
});

describe('#109 warning: eliminated un-annotated readonly field', () => {
  it('emits a DCE warning for an un-annotated unreferenced readonly field', () => {
    const r = compile(source(''), { fileName: 'Meta.runar.ts' });
    expect(r.success).toBe(true); // warning is non-fatal
    const warnings = r.diagnostics.filter(d => d.severity === 'warning');
    const msgs = warnings.map(w => w.message).join('\n');
    expect(msgs).toMatch(WARN_RE);
  });

  it('does NOT warn when the field is annotated /** @embedAlways */', () => {
    const r = compile(source('/** @embedAlways */'), { fileName: 'Meta.runar.ts' });
    const warnings = r.diagnostics.filter(d => d.severity === 'warning');
    const msgs = warnings.map(w => w.message).join('\n');
    expect(msgs).not.toMatch(/metadataId/);
  });

  it('does NOT warn for a readonly field that IS referenced in a method', () => {
    const referenced = `
import { SmartContract, assert, Addr, PubKey, Sig, hash160, checkSig } from 'runar-lang';

class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
`;
    const r = compile(referenced, { fileName: 'P2PKH.runar.ts' });
    expect(r.success).toBe(true);
    const warnings = r.diagnostics.filter(d => d.severity === 'warning');
    expect(warnings.map(w => w.message).join('\n')).not.toMatch(/pubKeyHash/);
  });
});

// ---------------------------------------------------------------------------
// #109 regression — @embedAlways must survive a FIXED-POINT DCE.
//
// The preservation used to be an alias pair: the injected `load_prop` plus a
// `load_const("@ref:<t>")` binding whose only job was to make the `load_prop`
// look referenced. That survives ONE DCE sweep but not the fixed-point loop in
// `optimizer/dce.ts`: sweep 1 drops the now-unreferenced alias, sweep 2 then
// drops the `load_prop` it was protecting, and BOTH halves vanish.
//
// DCE only runs from inside the EC optimizer's changed-gate (`optimizeEC`
// returns the program untouched when no rule fired), so the probe below has to
// arm it: `ecMulGen(1n)` folds to the generator constant (rule 6), which flips
// `changed` and lets dead-binding elimination run. Every pre-existing test in
// this file uses an EC-free contract, so DCE never ran on them at all.
//
// Zig marks the injected `load_prop` itself with `preserve = true` and reads
// that flag in `hasSideEffect`; this tier now does the same.
// ---------------------------------------------------------------------------

/**
 * EC-armed probe. `metadataId` carries DIRECTIVE; `droppedField` is an
 * un-annotated, unreferenced control that MUST still be eliminated, so a
 * passing test cannot be satisfied by "retain everything".
 */
function ecSource(directive: string): string {
  return `
import { SmartContract, assert, Addr, PubKey, Sig, ByteString, hash160, checkSig, ecMulGen, ecPointX } from 'runar-lang';

class EcMeta extends SmartContract {
  readonly pubKeyHash: Addr;
  ${directive}
  readonly metadataId: ByteString;
  readonly droppedField: ByteString;

  constructor(pubKeyHash: Addr, metadataId: ByteString, droppedField: ByteString) {
    super(pubKeyHash, metadataId, droppedField);
    this.pubKeyHash = pubKeyHash;
    this.metadataId = metadataId;
    this.droppedField = droppedField;
  }

  public unlock(sig: Sig, pubKey: PubKey) {
    const g = ecMulGen(1n);
    assert(ecPointX(g) > 0n);
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
`;
}

describe('#109 preservation survives fixed-point DCE (EC-armed)', () => {
  it('annotated: metadataId keeps its constructor slot after the EC optimizer runs DCE', () => {
    const r = compile(ecSource('/** @embedAlways */'), { fileName: 'EcMeta.runar.ts' });
    expect(r.success, JSON.stringify(r.diagnostics)).toBe(true);
    const slotNames = r.artifact!.constructorSlots!.map(s => s.name);
    expect(slotNames).toContain('metadataId');
  });

  it('control: un-annotated dead field is STILL eliminated', () => {
    for (const directive of ['', '/** @embedAlways */']) {
      const r = compile(ecSource(directive), { fileName: 'EcMeta.runar.ts' });
      expect(r.success, JSON.stringify(r.diagnostics)).toBe(true);
      const slotNames = r.artifact!.constructorSlots!.map(s => s.name);
      expect(slotNames, `directive=${JSON.stringify(directive)}`).not.toContain('droppedField');
    }
  });

  it('annotated hex is longer than un-annotated in the EC-armed contract', () => {
    const off = compile(ecSource(''), { fileName: 'EcMeta.runar.ts' });
    const on = compile(ecSource('/** @embedAlways */'), { fileName: 'EcMeta.runar.ts' });
    expect(on.scriptHex).not.toEqual(off.scriptHex);
    expect(on.scriptHex!.length).toBeGreaterThan(off.scriptHex!.length);
  });

  it('the preserve flag is never serialized into the emitted ANF IR JSON', () => {
    const r = compile(ecSource('/** @embedAlways */'), { fileName: 'EcMeta.runar.ts' });
    expect(r.success, JSON.stringify(r.diagnostics)).toBe(true);
    const json = JSON.stringify(r.anf, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v));
    expect(json).not.toContain('preserve');
  });
});
