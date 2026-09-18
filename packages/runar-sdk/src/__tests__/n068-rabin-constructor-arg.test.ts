// ---------------------------------------------------------------------------
// N-068 — a `RabinSig` / `RabinPubKey` constructor argument deploys, and it
// deploys to the SAME bytes as the equivalent `bigint` slot.
// ---------------------------------------------------------------------------
//
// The reported finding was that the SDK "cannot deploy a RabinSig constructor
// argument at all" — that the arg encoder has no RabinSig case, so the splice
// produces non-hex and `LockingScript.fromHex` rejects it. That is not what the
// code does, and these tests are the refutation.
//
// `encodeArg` has no per-type table for ANY type. It dispatches on the RUNTIME
// value (bigint -> script number, boolean -> OP_0/OP_1, string -> push data), so
// there is nothing for a type to be missing FROM. `RabinSig` and `RabinPubKey`
// are `bigint` aliases at the type level (packages/runar-lang/src/types.ts:68),
// a developer passes a bigint, and a bigint is exactly what the script wants:
// `emitVerifyRabinSig` consumes the modulus with `OP_MOD`, i.e. as a Script
// NUMBER (packages/runar-compiler/src/passes/rabin-codegen.ts). All seven SDKs
// are built this way, and the cross-SDK pin agrees — the oracle-price case in
// `conformance/sdk-output/tests/oracle-price/` declares `oraclePubKey:
// RabinPubKey` and feeds it `{"type":"bigint","value":"12345678901234567890"}`.
//
// So the invariant worth having is the one nothing asserted yet: a Rabin-typed
// slot and a bigint-typed slot are the same slot. If a future change gives
// `encodeArg` a type-directed branch — the obvious "fix" for the reported
// finding — these go red, because such a branch would splice the Rabin slot as
// a raw data push while `OP_MOD` still reads it as a little-endian number. The
// deployed modulus would be byte-reversed, the covenant could never verify, and
// the funds in that output would be unspendable.
//
// What these tests do NOT cover: `extractConstructorArgs` reads the slot back
// as a hex string rather than a bigint, because `interpretScriptElement` keys
// on the ABI type and has no `RabinSig` / `RabinPubKey` case (nor `boolean` —
// only the `bool` alias). That is a real defect in a wire-format-gated file in
// all seven tiers and is reported separately; it is deliberately not pinned
// here, in either direction.

import { describe, it, expect } from 'vitest';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import type { RunarArtifact } from 'runar-ir-schema';

// Private key "1" — the smallest valid secp256k1 private key.
const PRIV_KEY =
  '0000000000000000000000000000000000000000000000000000000000000001';

/**
 * One-slot artifact whose single constructor param carries `type`. The script
 * is the OP_0 placeholder followed by OP_DROP OP_TRUE, so the slot is the only
 * thing that can differ between two of these.
 */
function slotArtifact(type: string): RunarArtifact {
  return {
    version: 'runar-v0.1.0',
    compilerVersion: '0.1.0',
    contractName: 'RabinSlot',
    asm: '',
    buildTimestamp: '2026-03-02T00:00:00.000Z',
    script: '007551', // OP_0 (placeholder) OP_DROP OP_TRUE
    abi: {
      constructor: { params: [{ name: 'k', type }] },
      methods: [{ name: 'unlock', params: [], isPublic: true }],
    },
    constructorSlots: [
      {
        paramIndex: 0,
        byteOffset: 0,
        name: 'k',
        type,
        // What the compiler's `slotValueEncoding()` emits for this type today.
        valueEncoding: type === 'bigint' ? 'scriptnum' : 'data',
      },
    ],
  };
}

async function fundedProvider(satoshis: number) {
  const signer = new LocalSigner(PRIV_KEY);
  const provider = new MockProvider('testnet');
  provider.addUtxo(await signer.getAddress(), {
    txid: 'aa'.repeat(32),
    outputIndex: 0,
    satoshis,
    script: buildP2PKHScript(await signer.getPublicKey()),
  });
  return { provider, signer };
}

// A Rabin modulus is a large integer — 1024-bit here, the smallest size the
// oracle pattern uses in practice. It exercises the PUSHDATA1 path and the
// sign-extension byte (the top magnitude byte has its high bit set).
const MODULUS = (1n << 1023n) + 12345n;

describe('N-068 — Rabin-typed constructor args', () => {
  it.each(['RabinPubKey', 'RabinSig'])(
    'a %s constructor arg splices to valid hex and deploys through MockProvider',
    async (type) => {
      const { provider, signer } = await fundedProvider(100_000);
      const contract = new RunarContract(slotArtifact(type), [MODULUS]);

      const locking = contract.getLockingScript();
      expect(locking).toMatch(/^[0-9a-f]+$/);

      await contract.deploy(provider, signer, { satoshis: 50_000 });

      const broadcast = provider.getBroadcastedTxs();
      expect(broadcast).toHaveLength(1);
      // The deployed output really carries the spliced script, so the splice
      // survived transaction assembly and not just `getLockingScript()`.
      expect(broadcast[0]).toContain(locking);
    },
  );

  it.each(['RabinPubKey', 'RabinSig'])(
    'a %s slot deploys byte-identically to the equivalent bigint slot',
    (type) => {
      const rabin = new RunarContract(slotArtifact(type), [MODULUS]);
      const plain = new RunarContract(slotArtifact('bigint'), [MODULUS]);

      expect(rabin.getLockingScript()).toBe(plain.getLockingScript());
    },
  );

  it('the spliced Rabin modulus is the little-endian script number OP_MOD reads', () => {
    // 1024-bit magnitude = 128 bytes, plus one 0x00 sign byte because the top
    // magnitude byte is 0x80 — 129 bytes, so PUSHDATA1 (0x4c 0x81).
    const locking = new RunarContract(slotArtifact('RabinPubKey'), [MODULUS]).getLockingScript();

    expect(locking.slice(0, 4)).toBe('4c81');
    const pushed = locking.slice(4, 4 + 129 * 2);
    expect(pushed).toHaveLength(129 * 2);

    // Little-endian sign-magnitude: low byte first (12345 = 0x3039), high byte
    // 0x80 (bit 1023), then the explicit non-negative sign byte.
    expect(pushed.slice(0, 4)).toBe('3930');
    expect(pushed.slice(-4)).toBe('8000');

    // ...and the template tail is untouched: OP_DROP OP_TRUE.
    expect(locking.slice(4 + 129 * 2)).toBe('7551');
  });
});
