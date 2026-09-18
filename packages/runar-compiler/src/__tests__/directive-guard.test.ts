import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';

// The `@sighash` (#123) and `@embedAlways` (#109) comment directives are
// honoured only on the TypeScript (.runar.ts) surface, which reads leading
// trivia. The non-TS surface parsers (.sol/.move/.py/.java/...) ignore
// comments, so the dispatcher must FAIL CLOSED there rather than silently drop
// a security-critical directive. These tests pin both halves of that policy.

function errorMessages(src: string, fileName: string): string {
  return parse(src, fileName)
    .errors.filter((e) => e.severity === 'error')
    .map((e) => e.message)
    .join('\n');
}

describe('fail-closed directive guard (issues #123 / #109)', () => {
  it('honours @sighash on the .runar.ts surface', () => {
    const src = `
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash SINGLE|FORKID */
        public bump(): void { this.n = this.n + 1n; }
      }`;
    const r = parse(src, 'C.runar.ts');
    expect(r.errors.filter((e) => e.severity === 'error')).toEqual([]);
    expect(r.contract!.methods.find((m) => m.name === 'bump')!.sighashType).toBe(0x43);
  });

  it('honours @embedAlways on the .runar.ts surface', () => {
    const src = `
      class Meta extends SmartContract {
        /** @embedAlways */
        readonly metadataId: ByteString;
        constructor(metadataId: ByteString) { super(metadataId); this.metadataId = metadataId; }
        public unlock(): void {}
      }`;
    const r = parse(src, 'Meta.runar.ts');
    expect(r.errors.filter((e) => e.severity === 'error')).toEqual([]);
    expect(r.contract!.properties.find((p) => p.name === 'metadataId')!.embedAlways).toBe(true);
  });

  it('rejects @sighash on a non-TS (.runar.sol) surface', () => {
    const src = `
      contract Counter {
        // @sighash SINGLE|FORKID
        function unlock() public {}
      }`;
    const joined = errorMessages(src, 'Counter.runar.sol');
    expect(joined).toContain('@sighash');
    expect(joined).toContain('#123');
  });

  it('rejects @embedAlways on a non-TS (.runar.move) surface', () => {
    const src = `
      module Counter {
        // @embedAlways
        x: u64;
      }`;
    const joined = errorMessages(src, 'Counter.runar.move');
    expect(joined).toContain('@embedAlways');
    expect(joined).toContain('#109');
  });

  it('does not trip the guard on a non-directive identifier (word boundary)', () => {
    // A field named `sighashType` must NOT trip the `@sighash\b` guard.
    const src = `
      class C extends SmartContract {
        readonly sighashType: bigint;
        constructor(sighashType: bigint) { super(sighashType); this.sighashType = sighashType; }
        public unlock(): void {}
      }`;
    const joined = errorMessages(src, 'C.runar.ts');
    expect(joined).not.toContain('not supported');
  });

  it('honours @bindingVariant on the .runar.ts surface', () => {
    const src = `
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @bindingVariant all */
        public bump(): void { this.n = this.n + 1n; }
      }`;
    const r = parse(src, 'C.runar.ts');
    expect(r.errors.filter((e) => e.severity === 'error')).toEqual([]);
    expect(r.contract!.methods.find((m) => m.name === 'bump')!.bindingVariant).toBe('all');
  });

  it('rejects an unknown @bindingVariant value', () => {
    const src = `
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @bindingVariant high */
        public bump(): void { this.n = this.n + 1n; }
      }`;
    const joined = errorMessages(src, 'C.runar.ts');
    expect(joined).toContain('@bindingVariant');
    expect(joined).toContain('unknown variant');
  });

  it('rejects @bindingVariant on a non-TS (.runar.sol) surface', () => {
    const src = `
      contract Counter {
        // @bindingVariant all
        function unlock() public {}
      }`;
    const joined = errorMessages(src, 'Counter.runar.sol');
    expect(joined).toContain('@bindingVariant');
    expect(joined).toContain('not supported');
  });
});
