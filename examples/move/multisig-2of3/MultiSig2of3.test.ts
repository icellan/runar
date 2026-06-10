import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';
import { compile } from 'runar-compiler';
import { ScriptVM } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'MultiSig2of3.runar.move'), 'utf8');
const FILE_NAME = 'MultiSig2of3.runar.move';

const PK1 = '02' + 'aa'.repeat(32);
const PK2 = '02' + 'bb'.repeat(32);
const PK3 = '02' + 'cc'.repeat(32);
const SIG1 = '30' + '11'.repeat(35);
const SIG2 = '30' + '22'.repeat(35);

function encodePush(hex: string): string {
  const n = hex.length / 2;
  if (n === 0) return '00';
  if (n < 0x4c) return n.toString(16).padStart(2, '0') + hex;
  if (n < 0x100) return '4c' + n.toString(16).padStart(2, '0') + hex;
  throw new Error('push too large');
}

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function buildLockingScript(pks: [string, string, string]): string {
  const r = compile(source, { fileName: FILE_NAME });
  if (!r.success || !r.scriptHex || !r.artifact) throw new Error('compile failed');
  let s = r.scriptHex.toLowerCase();
  const sorted = [...(r.artifact.constructorSlots ?? [])].sort((a, b) => b.byteOffset - a.byteOffset);
  for (const slot of sorted) {
    const enc = encodePush(pks[slot.paramIndex]!);
    const off = slot.byteOffset * 2;
    s = s.slice(0, off) + enc + s.slice(off + 2);
  }
  return s;
}

describe('MultiSig2of3 (Move)', () => {
  it('compiles and exposes pubkeys', () => {
    const c = TestContract.fromSource(source, { pk1: PK1, pk2: PK2, pk3: PK3 }, FILE_NAME);
    expect(c.state.pk1).toBeDefined();
    expect(c.state.pk2).toBeDefined();
    expect(c.state.pk3).toBeDefined();
  });

  // BUG-009 regression: ScriptVM-level adversarial coverage.

  it('rejects all-empty signatures', () => {
    const locking = buildLockingScript([PK1, PK2, PK3]);
    const unlocking = encodePush('') + encodePush('');
    const vm = new ScriptVM({ checkSigCallback: (sig) => sig.length > 0 });
    expect(vm.execute(hexToBytes(unlocking), hexToBytes(locking)).success).toBe(false);
  });

  it('rejects sigs in wrong order', () => {
    const locking = buildLockingScript([PK1, PK2, PK3]);
    const unlocking = encodePush(SIG2) + encodePush(SIG1);
    const cb = (sig: Uint8Array, pk: Uint8Array) => {
      const sh = Array.from(sig, x => x.toString(16).padStart(2, '0')).join('');
      const ph = Array.from(pk, x => x.toString(16).padStart(2, '0')).join('');
      return (sh === SIG1 && ph === PK1) || (sh === SIG2 && ph === PK2);
    };
    expect(new ScriptVM({ checkSigCallback: cb }).execute(hexToBytes(unlocking), hexToBytes(locking)).success).toBe(false);
  });

  it('accepts a valid 2-of-3 unlock', () => {
    const locking = buildLockingScript([PK1, PK2, PK3]);
    const unlocking = encodePush(SIG1) + encodePush(SIG2);
    const cb = (sig: Uint8Array, pk: Uint8Array) => {
      const sh = Array.from(sig, x => x.toString(16).padStart(2, '0')).join('');
      const ph = Array.from(pk, x => x.toString(16).padStart(2, '0')).join('');
      return (sh === SIG1 && ph === PK1) || (sh === SIG2 && ph === PK2);
    };
    expect(new ScriptVM({ checkSigCallback: cb }).execute(hexToBytes(unlocking), hexToBytes(locking)).success).toBe(true);
  });
});
