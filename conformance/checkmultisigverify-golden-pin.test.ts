/**
 * N-456: no conformance golden contained the fused OP_CHECKMULTISIGVERIFY.
 *
 * `assert(checkMultiSig(...))` as the LAST statement leaves its result on the
 * stack as the script's truthy final value and ends in a bare OP_CHECKMULTISIG
 * (0xae) -- that is the `multisig` fixture. When more logic follows, the
 * emitter writes OP_CHECKMULTISIG OP_VERIFY and the peephole pass fuses the
 * pair into OP_CHECKMULTISIGVERIFY (0xaf). Before this test the opcode walk
 * of every expected-script.hex found 0xaf in zero fixtures (OP_CHECKSIGVERIFY
 * was in 51), so that fusion was unpinned in every tier.
 *
 * Proves: the committed goldens contain 0xaf as a real, walked OPCODE (not a
 * 0xaf byte inside push data or a hex substring), and that the
 * `multisig-verify-fused` golden has it while its bare-0xae `multisig`
 * sibling does not.
 *
 * Does not prove: that the bytes are CORRECT. Execution evidence is the
 * real-crypto witness `witnesses/real-crypto/multisig-verify-fused.json`
 * (run by `witnesses/real-crypto-execution.test.ts`); cross-tier byte
 * identity is the runner's golden / --multi-format modes.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = resolve(dirname(fileURLToPath(import.meta.url)));
const TESTS = join(HERE, 'tests');

/** Pushdata-aware opcode walk. Push payloads are skipped, never reported. */
function walkOpcodes(hex: string): number[] {
  const b = Buffer.from(hex.trim(), 'hex');
  const ops: number[] = [];
  let i = 0;
  while (i < b.length) {
    const op = b[i]!;
    ops.push(op);
    i += 1;
    let len = 0;
    if (op >= 0x01 && op <= 0x4b) len = op;
    else if (op === 0x4c) { len = b[i] ?? 0; i += 1; }
    else if (op === 0x4d) { len = b.readUInt16LE(i); i += 2; }
    else if (op === 0x4e) { len = b.readUInt32LE(i); i += 4; }
    if (i + len > b.length) break; // truncated tail (state data after OP_RETURN)
    i += len;
  }
  return ops;
}

function goldenOps(fixture: string): number[] | null {
  const p = join(TESTS, fixture, 'expected-script.hex');
  return existsSync(p) ? walkOpcodes(readFileSync(p, 'utf8')) : null;
}

describe('N-456: OP_CHECKMULTISIGVERIFY (0xaf) is pinned by a golden', () => {
  it('some golden contains a walked 0xaf opcode', () => {
    const holders = readdirSync(TESTS).filter((d) => goldenOps(d)?.includes(0xaf));
    expect(holders, 'no expected-script.hex contains OP_CHECKMULTISIGVERIFY').not.toEqual([]);
  });

  it('multisig-verify-fused fuses the verify; multisig keeps a bare CHECKMULTISIG', () => {
    const fused = goldenOps('multisig-verify-fused');
    expect(fused, 'conformance/tests/multisig-verify-fused/expected-script.hex').not.toBeNull();
    expect(fused).toContain(0xaf);
    expect(fused).not.toContain(0xae); // fused: no unfused CHECKMULTISIG remains

    const bare = goldenOps('multisig')!;
    expect(bare).toContain(0xae);
    expect(bare).not.toContain(0xaf);
  });
});
