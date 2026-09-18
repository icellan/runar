/**
 * W2 / OutputInception — `requireOutputP2PKH(i, ...)` read output `i` at byte
 * `i * 34`, and Bitcoin outputs are not 34 bytes each.
 *
 * ANF lowering authenticates the `_serialisedOutputs` witness against the
 * preimage's `hashOutputs` and then slices `[i*34, i*34+34)` out of it, which
 * is only the start of output `i` when every preceding output happens to be
 * exactly 34 bytes. An output is `value[8] || CompactSize(len) || script[len]`,
 * so an attacker who controls output 0 picks its length. Put the promised
 * 34-byte P2PKH serialisation inside an earlier output's OP_RETURN payload, at
 * global offset `i*34`, and the slice matches while the transaction's real
 * output `i` pays whoever the attacker likes.
 *
 * Index 0 is the one sound case: offset 0 is a genuine output boundary, so
 * matching the 34 bytes there forces output 0 to BE that P2PKH.
 *
 * ORACLE. `@bsv/sdk`'s `Spend` — the production interpreter — over a real
 * BIP-143 context. Never `TestContract`: its interpreter clones the same
 * `idx * 34` arithmetic (`interpreter.ts`, `offset = Number(idx * 34n)`), so it
 * would have agreed with the compiler and called the theft valid.
 */

import { describe, it, expect } from 'vitest';
import { compile, parse, lowerToANF } from 'runar-compiler';

const BOND_PKH = 'ab'.repeat(20);
const ATTACKER_PKH = 'cd'.repeat(20);
const BOND_AMOUNT = 100_000;

/**
 * The contract from the report: terminal, no outputs of its own, asserting
 * that output ONE pays the bond. Output 0 is entirely attacker-chosen.
 */
const PHANTOM_BOND_SRC = `import { StatefulSmartContract, ByteString, requireOutputP2PKH } from 'runar-lang';

export class PhantomBond extends StatefulSmartContract {
  readonly bondPKH: ByteString;
  readonly bondAmount: bigint;
  count: bigint;

  constructor(bondPKH: ByteString, bondAmount: bigint, count: bigint) {
    super(bondPKH, bondAmount, count);
    this.bondPKH = bondPKH;
    this.bondAmount = bondAmount;
    this.count = count;
  }

  public settle() {
    requireOutputP2PKH(1n, this.bondPKH, this.bondAmount);
  }
}
`;

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}
function bytesToHex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}
function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
function u64LE(v: number): Uint8Array {
  const out = new Uint8Array(8);
  let x = BigInt(v);
  for (let i = 0; i < 8; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}
function compactSize(n: number): Uint8Array {
  if (n < 0xfd) return Uint8Array.from([n]);
  if (n <= 0xffff) return Uint8Array.from([0xfd, n & 0xff, (n >> 8) & 0xff]);
  throw new Error('compactSize: test only needs 1- and 3-byte forms');
}
function pushDataHex(bytes: Uint8Array): string {
  const hex = bytesToHex(bytes);
  const n = bytes.length;
  if (n === 0) return '00';
  if (n < 0x4c) return n.toString(16).padStart(2, '0') + hex;
  if (n <= 0xff) return '4c' + n.toString(16).padStart(2, '0') + hex;
  const lo = (n & 0xff).toString(16).padStart(2, '0');
  const hi = ((n >> 8) & 0xff).toString(16).padStart(2, '0');
  return '4d' + lo + hi + hex;
}

/** `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG` — 25 bytes. */
function p2pkhScript(pkhHex: string): Uint8Array {
  return concat(
    Uint8Array.from([0x76, 0xa9, 0x14]),
    hexToBytes(pkhHex),
    Uint8Array.from([0x88, 0xac]),
  );
}

/** One serialised output: value[8] || CompactSize(len) || script. */
function serialiseOutput(satoshis: number, script: Uint8Array): Uint8Array {
  return concat(u64LE(satoshis), compactSize(script.length), script);
}

/** The exact 34 bytes `requireOutputP2PKH` compares against. */
function expectedP2PKHBlock(satoshis: number, pkhHex: string): Uint8Array {
  return serialiseOutput(satoshis, p2pkhScript(pkhHex));
}

describe('W2 — the 34-byte stride is not an output boundary', () => {
  const promised = expectedP2PKHBlock(BOND_AMOUNT, BOND_PKH);

  it('a serialised P2PKH output is 34 bytes', () => {
    expect(promised.length).toBe(34);
  });

  it('an OP_RETURN output can place those 34 bytes at global offset 34', () => {
    // Output 0: an OP_RETURN whose payload contains `promised` starting at
    // global offset 34. Solve for the filler rather than asserting it —
    //   8 (value) + 1 (CompactSize) + 2 (OP_FALSE OP_RETURN) + 1 (push len) + f = 34
    // gives f = 22, and a wrong constant would make this test vacuous.
    // Nothing about the resulting output is unusual to a node.
    let script: Uint8Array | undefined;
    let filler = -1;
    for (let f = 0; f < 60; f++) {
      const candidatePayload = concat(new Uint8Array(f), promised, new Uint8Array(10));
      const candidate = concat(
        Uint8Array.from([0x00, 0x6a]), // OP_FALSE OP_RETURN
        hexToBytes(pushDataHex(candidatePayload)),
      );
      const o = serialiseOutput(0, candidate);
      if (o.length > 34 && bytesToHex(o.slice(34, 68)) === bytesToHex(promised)) {
        script = candidate;
        filler = f;
        break;
      }
    }
    expect(script, 'no OP_RETURN filler lands the promised bytes at offset 34').toBeDefined();
    expect(filler).toBe(22);
    const out0 = serialiseOutput(0, script!);
    const out1 = serialiseOutput(BOND_AMOUNT, p2pkhScript(ATTACKER_PKH));
    const outputs = concat(out0, out1);

    // The compiler reads output "1" here...
    expect(bytesToHex(outputs.slice(34, 68))).toBe(bytesToHex(promised));
    // ...and a transaction parser reads it there, paying the attacker.
    expect(out0.length).toBeGreaterThan(34);
    expect(bytesToHex(outputs.slice(out0.length))).toBe(bytesToHex(out1));
    expect(bytesToHex(out1)).not.toBe(bytesToHex(promised));
  });

  it('index 0 has no such gap: offset 0 IS an output boundary', () => {
    const out0 = serialiseOutput(BOND_AMOUNT, p2pkhScript(BOND_PKH));
    const outputs = concat(out0, serialiseOutput(1, p2pkhScript(ATTACKER_PKH)));
    // Matching bytes [0,34) forces output 0 to be exactly the promised P2PKH —
    // there is no earlier output for the bytes to hide inside.
    expect(bytesToHex(outputs.slice(0, 34))).toBe(bytesToHex(promised));
  });
});

// ---------------------------------------------------------------------------
// The spend itself, on the real engine.
// ---------------------------------------------------------------------------

describe('W2 — PhantomBond.settle on @bsv/sdk Spend', () => {
  const compiled = compile(PHANTOM_BOND_SRC, {
    fileName: 'PhantomBond.runar.ts',
    constructorArgs: { bondPKH: BOND_PKH, bondAmount: BigInt(BOND_AMOUNT), count: 0n },
  });

  it('the contract is REFUSED at compile time', () => {
    const errors = compiled.diagnostics
      .filter((d) => d.severity === 'error')
      .map((d) => d.message);
    expect(compiled.success, `compiled cleanly: ${JSON.stringify(errors)}`).toBe(false);
    expect(errors.join('\n')).toMatch(/requireOutputP2PKH/);
    expect(errors.join('\n')).toMatch(/outputIndex/);
  });

  it('no locking script is produced, so there is nothing to spend', () => {
    // Before this fix the same source compiled, and the transaction the block
    // above builds — OP_RETURN at output 0 carrying the promised bytes at
    // offset 34, attacker P2PKH at output 1 — was accepted by
    // `Spend.validate()`. Measured, not asserted from reading: see the commit
    // message for the before/after.
    expect(compiled.scriptHex).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// The refusal must not live in one pass (R-012).
// ---------------------------------------------------------------------------

describe('W2 — the index rule survives a caller that skips typecheck', () => {
  it('parse() -> lowerToANF() throws instead of emitting the i*34 slice', () => {
    const parsed = parse(PHANTOM_BOND_SRC, 'PhantomBond.runar.ts');
    expect(parsed.contract, JSON.stringify(parsed.errors)).toBeDefined();
    // `lowerToANF` is a public export of runar-compiler, so this path runs no
    // validator and no typechecker. Before the backstop it produced a perfectly
    // good ANF program carrying `load_const 34` as the offset.
    expect(() => lowerToANF(parsed.contract!)).toThrow(/outputIndex must be 0/);
  });

  it('index 0 still lowers through that same path', () => {
    const ok = PHANTOM_BOND_SRC.replace('requireOutputP2PKH(1n,', 'requireOutputP2PKH(0n,');
    const parsed = parse(ok, 'PhantomBond.runar.ts');
    expect(parsed.contract).toBeDefined();
    expect(() => lowerToANF(parsed.contract!)).not.toThrow();
  });
});
