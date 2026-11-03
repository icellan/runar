/**
 * Unit tests for `assembleMultiContractCall` — cross-artifact tx assembly.
 *
 * Two DIFFERENT artifacts compose one spending tx:
 *   input 0: OutputBinder.release  (terminal — binds the output set via hashOutputs)
 *   input 1: BumpToken.bump        (stateful continuation + P2PKH change)
 *
 * Both unlocks are validated through @bsv/sdk's production Spend interpreter
 * (real ECDSA, real BIP-143) — no regtest node needed. The companion regtest
 * suite (multi-contract-call.regtest.test.ts) broadcasts the same shape.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract, encodePushData } from '../contract.js';
import {
  assembleMultiContractCall,
  dryRunMultiContractInput,
} from '../multi-contract.js';
import { LocalSigner } from '../signers/local.js';
import { Hash, Utils } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

// ---------------------------------------------------------------------------
// Contracts (inline, neutral)
// ---------------------------------------------------------------------------

const TOKEN_SOURCE = `
import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

class BumpToken extends StatefulSmartContract {
  owner: PubKey;
  value: bigint;

  constructor(owner: PubKey, value: bigint) {
    super(owner, value);
    this.owner = owner;
    this.value = value;
  }

  public bump(sig: Sig, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);
    this.addOutput(outputSatoshis, this.owner, this.value + 1n);
  }

  public freeze(sig: Sig, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);
    this.addOutput(outputSatoshis, this.owner, this.value);
  }
}
`;

const BINDER_SOURCE = `
import { StatefulSmartContract, assert, checkSig, hash256, extractOutputHash } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class OutputBinder extends StatefulSmartContract {
  owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  public release(sig: Sig, expectedOutputs: ByteString) {
    assert(checkSig(sig, this.owner));
    assert(hash256(expectedOutputs) === extractOutputHash(this.txPreimage));
  }
}
`;

function compileSource(source: string, fileName: string): RunarArtifact {
  const result = compile(source, { fileName });
  if (!result.artifact) {
    throw new Error(`compile failed for ${fileName}: ${JSON.stringify(result.diagnostics)}`);
  }
  return result.artifact;
}

const tokenArtifact = compileSource(TOKEN_SOURCE, 'BumpToken.runar.ts');
const binderArtifact = compileSource(BINDER_SOURCE, 'OutputBinder.runar.ts');

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const OWNER_KEY = '0000000000000000000000000000000000000000000000000000000000000001';
const WRONG_KEY = '0000000000000000000000000000000000000000000000000000000000000002';

const ownerSigner = new LocalSigner(OWNER_KEY);
const wrongSigner = new LocalSigner(WRONG_KEY);
const ownerPub = await ownerSigner.getPublicKey();

const hash160hex = (pubKeyHex: string): string =>
  Utils.toHex(Hash.hash160(Utils.toArray(pubKeyHex, 'hex')));
const u64le = (n: bigint): string => {
  const b = new DataView(new ArrayBuffer(8));
  b.setBigUint64(0, n, true);
  return Utils.toHex(Array.from(new Uint8Array(b.buffer)));
};

const changePKH = hash160hex(ownerPub);
const changeScript = '76a914' + changePKH + '88ac';

interface Fixture {
  token: RunarContract;
  binder: RunarContract;
  tokenUtxo: { txid: string; outputIndex: number; satoshis: number; script: string };
  binderUtxo: { txid: string; outputIndex: number; satoshis: number; script: string };
  contScript: string;
  outputs: Array<{ satoshis: number; script: string }>;
  expectedOutputs: string;
}

function makeFixture(): Fixture {
  const token = new RunarContract(tokenArtifact, [ownerPub, 5n]);
  const binder = new RunarContract(binderArtifact, [ownerPub]);
  const tokenScript = token.getLockingScript();
  const binderScript = binder.getLockingScript();
  const tokenUtxo = { txid: 'aa'.repeat(32), outputIndex: 0, satoshis: 5000, script: tokenScript };
  const binderUtxo = { txid: 'bb'.repeat(32), outputIndex: 0, satoshis: 6000, script: binderScript };

  // bump continuation: value 5n -> 6n, 2000 sats; plus the unconditional P2PKH change (1000 sats).
  const tokenNext = new RunarContract(tokenArtifact, [ownerPub, 5n]);
  tokenNext.setState({ owner: ownerPub, value: 6n });
  const contScript = tokenNext.getLockingScript();
  const outputs = [
    { satoshis: 2000, script: contScript },
    { satoshis: 1000, script: changeScript },
  ];
  const varint1 = (n: number): string => n.toString(16).padStart(2, '0'); // scripts here < 0xfd? cont may exceed
  const varintHex = (n: number): string => {
    if (n < 0xfd) return varint1(n);
    const lo = (n & 0xff).toString(16).padStart(2, '0');
    const hi = ((n >> 8) & 0xff).toString(16).padStart(2, '0');
    return 'fd' + lo + hi;
  };
  const expectedOutputs =
    u64le(2000n) + varintHex(contScript.length / 2) + contScript +
    u64le(1000n) + varintHex(changeScript.length / 2) + changeScript;
  return { token, binder, tokenUtxo, binderUtxo, contScript, outputs, expectedOutputs };
}

function inputsFor(f: Fixture, opts: { signer0?: LocalSigner; signer1?: LocalSigner } = {}) {
  return [
    {
      contract: f.binder,
      method: 'release',
      args: [null, f.expectedOutputs],
      utxo: f.binderUtxo,
      signer: opts.signer0 ?? ownerSigner,
    },
    {
      contract: f.token,
      method: 'bump',
      args: [null, 2000n],
      utxo: f.tokenUtxo,
      signer: opts.signer1 ?? ownerSigner,
      changePKH,
      changeAmount: 1000n,
    },
  ];
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

describe('assembleMultiContractCall — two different artifacts in one tx', () => {
  it('assembles a tx whose EVERY covenant input passes the Spend interpreter', async () => {
    const f = makeFixture();
    const assembled = await assembleMultiContractCall(inputsFor(f), f.outputs);

    // dryRun defaults to true, so reaching here means both inputs validated.
    // Re-validate explicitly through the exported helper anyway.
    const r0 = dryRunMultiContractInput(assembled.txHex, 0, f.binderUtxo.script, f.binderUtxo.satoshis);
    expect(r0.error).toBeUndefined();
    expect(r0.valid).toBe(true);
    const r1 = dryRunMultiContractInput(assembled.txHex, 1, f.tokenUtxo.script, f.tokenUtxo.satoshis);
    expect(r1.error).toBeUndefined();
    expect(r1.valid).toBe(true);

    expect(assembled.tx.inputs.length).toBe(2);
    expect(assembled.tx.outputs.length).toBe(2);
    expect(assembled.unlocks.length).toBe(2);
    expect(assembled.preimages.length).toBe(2);
  });

  it('unlock layout: continuation input is prefixed with _codePart and suffixed with its method selector', async () => {
    const f = makeFixture();
    const assembled = await assembleMultiContractCall(inputsFor(f), f.outputs);

    // input 1 (BumpToken.bump, method index 0 of 2 public methods):
    // [_codePart] [_opPushTxSig] [sig] [outputSatoshis] [_changePKH] [_changeAmount] [preimage] [selector=OP_0]
    const codePartPush = encodePushData(f.token.getCodePartHex());
    expect(assembled.unlocks[1]!.startsWith(codePartPush)).toBe(true);
    expect(assembled.unlocks[1]!.endsWith(encodePushData(assembled.preimages[1]!) + '00')).toBe(true);

    // input 0 (OutputBinder.release, single public method): no codePart, no selector;
    // the unlock ends with the raw preimage push.
    expect(assembled.unlocks[0]!.startsWith(codePartPush)).toBe(false);
    expect(assembled.unlocks[0]!.endsWith(encodePushData(assembled.preimages[0]!))).toBe(true);
  });

  it('each input signature commits to ITS OWN input slot (swapped unlocks fail both inputs)', async () => {
    const f = makeFixture();
    const assembled = await assembleMultiContractCall(inputsFor(f), f.outputs);
    // The two preimages must differ (different outpoints, different scriptCode).
    expect(assembled.preimages[0]).not.toBe(assembled.preimages[1]);

    // Rebuild the SAME tx shape fresh (never mutate a serialized Transaction —
    // @bsv/sdk caches hex) with the two unlocking scripts swapped.
    const { Transaction, UnlockingScript, LockingScript } = await import('@bsv/sdk');
    const swapped = new Transaction();
    swapped.addInput({
      sourceTXID: f.binderUtxo.txid, sourceOutputIndex: f.binderUtxo.outputIndex,
      unlockingScript: UnlockingScript.fromHex(assembled.unlocks[1]!), sequence: 0xffffffff,
    });
    swapped.addInput({
      sourceTXID: f.tokenUtxo.txid, sourceOutputIndex: f.tokenUtxo.outputIndex,
      unlockingScript: UnlockingScript.fromHex(assembled.unlocks[0]!), sequence: 0xffffffff,
    });
    for (const out of f.outputs) {
      swapped.addOutput({ satoshis: out.satoshis, lockingScript: LockingScript.fromHex(out.script) });
    }
    const swappedHex = swapped.toHex();
    expect(dryRunMultiContractInput(swappedHex, 0, f.binderUtxo.script, f.binderUtxo.satoshis).valid).toBe(false);
    expect(dryRunMultiContractInput(swappedHex, 1, f.tokenUtxo.script, f.tokenUtxo.satoshis).valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The dryRun gate
// ---------------------------------------------------------------------------

describe('assembleMultiContractCall — dryRun gate', () => {
  it('THROWS (and never returns a broadcastable hex) when a covenant input cannot validate', async () => {
    const f = makeFixture();
    // Wrong owner key signs the binder input -> checkSig fails offline.
    await expect(
      assembleMultiContractCall(inputsFor(f, { signer0: wrongSigner }), f.outputs),
    ).rejects.toThrow(/offline validation FAILED for input 0/);
  });

  it('dryRun:false returns the (invalid) assembly for inspection', async () => {
    const f = makeFixture();
    const assembled = await assembleMultiContractCall(
      inputsFor(f, { signer1: wrongSigner }), f.outputs, { dryRun: false },
    );
    const r1 = dryRunMultiContractInput(assembled.txHex, 1, f.tokenUtxo.script, f.tokenUtxo.satoshis);
    expect(r1.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

describe('assembleMultiContractCall — argument validation', () => {
  it('rejects an unknown method', async () => {
    const f = makeFixture();
    const inputs = inputsFor(f);
    inputs[0] = { ...inputs[0]!, method: 'nope' };
    await expect(assembleMultiContractCall(inputs, f.outputs)).rejects.toThrow(/'nope' not found/);
  });

  it('rejects a user-arg count mismatch', async () => {
    const f = makeFixture();
    const inputs = inputsFor(f);
    inputs[1] = { ...inputs[1]!, args: [null] }; // bump expects (sig, outputSatoshis)
    await expect(assembleMultiContractCall(inputs, f.outputs)).rejects.toThrow(/expects 2 args, got 1/);
  });

  it('rejects a missing UTXO', async () => {
    const f = makeFixture();
    const inputs = inputsFor(f);
    inputs[0] = { ...inputs[0]!, utxo: undefined }; // binder never deployed/connected
    await expect(assembleMultiContractCall(inputs, f.outputs)).rejects.toThrow(/has no UTXO/);
  });

  it('rejects a null Sig arg without a signer', async () => {
    const f = makeFixture();
    const inputs = inputsFor(f);
    inputs[0] = { ...inputs[0]!, signer: undefined };
    await expect(assembleMultiContractCall(inputs, f.outputs)).rejects.toThrow(/no `signer`/);
  });

  it('rejects a continuation method without changePKH (ABI declares _changePKH)', async () => {
    const f = makeFixture();
    const inputs = inputsFor(f);
    inputs[1] = { ...inputs[1]!, changePKH: undefined };
    await expect(assembleMultiContractCall(inputs, f.outputs)).rejects.toThrow(/requires `changePKH`/);
  });

  // N-149: the arity filter must be the shared `isSdkSuppliedParam`, which
  // treats SigHashPreimage as SDK-supplied ONLY on stateful contracts. The
  // old local filter dropped it unconditionally. Proves: on a stateless
  // artifact whose method declares a SigHashPreimage param, that param counts
  // as a user arg (2 args are accepted, no arity error). Does not prove the
  // assembled tx for such a contract validates (the arity check is the
  // first gate; later stages are exercised by the happy-path suites above).
  it('counts a SigHashPreimage param as a user arg on a STATELESS contract', async () => {
    const f = makeFixture();
    const statelessArtifact: RunarArtifact = {
      version: 'runar-v0.1.0',
      compilerVersion: '0.0.0',
      contractName: 'PlainPre',
      abi: {
        constructor: { params: [] },
        methods: [
          {
            name: 'spend',
            params: [
              { name: 'x', type: 'bigint' },
              { name: 'pre', type: 'SigHashPreimage' },
            ],
            isPublic: true,
          },
        ],
      },
      script: '51',
      asm: 'OP_1',
      stateFields: [],
      constructorSlots: [],
      parentClass: 'SmartContract',
      buildTimestamp: '2024-01-01T00:00:00.000Z',
    } as unknown as RunarArtifact;
    const plain = new RunarContract(statelessArtifact, []);
    const utxo = { txid: 'cc'.repeat(32), outputIndex: 0, satoshis: 1000, script: '51' };
    const inputs = [{ contract: plain, method: 'spend', args: [1n, 'aa'], utxo, signer: ownerSigner }];
    let message = '';
    try {
      await assembleMultiContractCall(inputs, f.outputs);
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).not.toMatch(/expects \d+ args/);
  });

  it('rejects empty inputs / outputs', async () => {
    const f = makeFixture();
    await expect(assembleMultiContractCall([], f.outputs)).rejects.toThrow(/at least one input/);
    await expect(assembleMultiContractCall(inputsFor(f), [])).rejects.toThrow(/at least one output/);
  });
});
