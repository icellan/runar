/**
 * #198 pre-refactor characterization pin. `assembleMultiContractCall` is about
 * to be re-expressed through the exported per-input `buildContractUnlock`; the
 * assembled bytes for the existing two-artifact vector (binder@0 + token@1,
 * deterministic RFC6979 signatures) must not move by one byte.
 *
 * Proves: the txHex and every unlock/preimage of this vector are byte-stable
 * across the extraction. Does not prove: anything about vectors this file
 * does not construct (the multi-contract-call suite covers the rest).
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { Hash, Utils } from '@bsv/sdk';
import { RunarContract } from '../contract.js';
import { assembleMultiContractCall } from '../multi-contract.js';
import { LocalSigner } from '../signers/local.js';
import type { RunarArtifact } from 'runar-ir-schema';

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
  if (!result.artifact) throw new Error(`compile failed: ${JSON.stringify(result.diagnostics)}`);
  return result.artifact;
}

const sha256hex = (hex: string): string => Utils.toHex(Hash.sha256(Utils.toArray(hex, 'hex')));
const u64le = (n: bigint): string => {
  const b = new DataView(new ArrayBuffer(8));
  b.setBigUint64(0, n, true);
  return Utils.toHex(Array.from(new Uint8Array(b.buffer)));
};
const varintHex = (n: number): string => {
  if (n < 0xfd) return n.toString(16).padStart(2, '0');
  return 'fd' + (n & 0xff).toString(16).padStart(2, '0') + ((n >> 8) & 0xff).toString(16).padStart(2, '0');
};

describe('assembleMultiContractCall byte-stability pin (#198)', () => {
  it('the binder@0 + token@1 vector assembles to pinned bytes', async () => {
    const tokenArtifact = compileSource(TOKEN_SOURCE, 'BumpToken.runar.ts');
    const binderArtifact = compileSource(BINDER_SOURCE, 'OutputBinder.runar.ts');
    const signer = new LocalSigner('0000000000000000000000000000000000000000000000000000000000000001');
    const ownerPub = await signer.getPublicKey();
    const changePKH = Utils.toHex(Hash.hash160(Utils.toArray(ownerPub, 'hex')));
    const changeScript = '76a914' + changePKH + '88ac';

    const token = new RunarContract(tokenArtifact, [ownerPub, 5n]);
    const binder = new RunarContract(binderArtifact, [ownerPub]);
    const tokenUtxo = { txid: 'aa'.repeat(32), outputIndex: 0, satoshis: 5000, script: token.getLockingScript() };
    const binderUtxo = { txid: 'bb'.repeat(32), outputIndex: 0, satoshis: 6000, script: binder.getLockingScript() };
    const next = new RunarContract(tokenArtifact, [ownerPub, 5n]);
    next.setState({ owner: ownerPub, value: 6n });
    const contScript = next.getLockingScript();
    const outputs = [
      { satoshis: 2000, script: contScript },
      { satoshis: 1000, script: changeScript },
    ];
    const expectedOutputs =
      u64le(2000n) + varintHex(contScript.length / 2) + contScript +
      u64le(1000n) + varintHex(changeScript.length / 2) + changeScript;

    const assembled = await assembleMultiContractCall(
      [
        { contract: binder, method: 'release', args: [null, expectedOutputs], utxo: binderUtxo, signer },
        { contract: token, method: 'bump', args: [null, 2000n], utxo: tokenUtxo, signer, changePKH, changeAmount: 1000n },
      ],
      outputs,
    );

    expect({
      txHex: sha256hex(assembled.txHex),
      unlock0: sha256hex(assembled.unlocks[0]!),
      unlock1: sha256hex(assembled.unlocks[1]!),
      pre0: sha256hex(assembled.preimages[0]!),
      pre1: sha256hex(assembled.preimages[1]!),
    }).toEqual({
      txHex: '81e1d313f233062230fca2f5e98a39cdc6705e94e17ca0658605716946c80c4e',
      unlock0: '37cb3a4529b6361d19f9a6ad7a9232e521897867a634a9134cc7f7fe7c73cad8',
      unlock1: 'a200df1f862014d546ddee829d221d5f380ca48fefab5cf9422dda0f5529394f',
      pre0: '58fba90bfb8c46eb67f6aace38d5c263cb4d251543d08b72d2fac5696335e350',
      pre1: '2c5eda8b4a52dcbf8b190c5df2b84af77f6129f49276d8fe8f98925d4d6bd5fe',
    });
  });
});
