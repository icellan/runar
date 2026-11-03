/**
 * N-189: the off-chain `scriptCode` that `call()` hands the ANF interpreter
 * (what `extractScriptCode(txPreimage)` returns while the SDK predicts the
 * post-state) must be the BIP-143 scriptCode the call actually signs.
 *
 * BIP-143's scriptCode is the SPENT UTXO's locking script after the executed
 * OP_CODESEPARATOR — for a stateful contract that is the code AND the
 * `OP_RETURN <state>` tail. R67 built the mock from the bare template
 * codePart instead, which omits the state tail, so any method whose
 * post-state depends on its own scriptCode (its length, or a read of its own
 * state tail, the way FungibleToken.merge reads the companion's) committed a
 * different continuation than the script re-derives on-chain: the covenant's
 * hashOutputs check then rejects the call.
 *
 * Oracle: @bsv/sdk `Spend.validate()` on freshly-parsed deploy + call bytes.
 *
 * What this proves: for a contract whose new state is `len(extractScriptCode
 * (txPreimage))` and one that copies the last 8 bytes of its own scriptCode
 * (its own serialized state field), the state the SDK commits equals the
 * on-chain value and the call validates under consensus.
 * What it does not prove: contracts that read other preimage fields, or
 * multi-input calls (each extra contract input is spent by its own preimage,
 * not by this prediction).
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { Spend, LockingScript, Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

const SIGNER_KEY = '1'.repeat(63) + '7';
const FILE_NAME = 'ScLen.runar.ts';

/** New state = the length of this input's own BIP-143 scriptCode. */
const LEN_SOURCE = `import { StatefulSmartContract, extractScriptCode, len } from 'runar-lang';

class ScLen extends StatefulSmartContract {
  n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }

  public rec(): void {
    this.n = len(extractScriptCode(this.txPreimage));
  }
}`;

/**
 * New state = the last 8 bytes of this input's own scriptCode, i.e. its own
 * serialized state field (num2bin(n, 8)), plus one. With the template mock
 * those 8 bytes are code, not state.
 */
const TAIL_SOURCE = `import { StatefulSmartContract, extractScriptCode, len, substr, bin2num } from 'runar-lang';

class ScLen extends StatefulSmartContract {
  n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }

  public rec(): void {
    const sc = extractScriptCode(this.txPreimage);
    this.n = bin2num(substr(sc, len(sc) - 8n, 8n)) + 1n;
  }
}`;

function compileSource(source: string): RunarArtifact {
  const result = compile(source, { fileName: FILE_NAME });
  if (!result.artifact) {
    const errors = (result.diagnostics || [])
      .filter((d: { severity: string }) => d.severity === 'error')
      .map((d: { message: string }) => d.message);
    throw new Error(`Compile failed: ${errors.join('; ')}`);
  }
  return result.artifact;
}

function validateSpend(tx: Transaction, sourceTx: Transaction): boolean {
  const input = tx.inputs[0]!;
  const sourceOutput = sourceTx.outputs[input.sourceOutputIndex]!;
  const spend = new Spend({
    sourceTXID: input.sourceTXID!,
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis: sourceOutput.satoshis!,
    lockingScript: LockingScript.fromHex(sourceOutput.lockingScript.toHex()),
    transactionVersion: tx.version,
    otherInputs: tx.inputs.slice(1).map((inp, idx) => ({
      inputIndex: idx + 1,
      sourceOutputIndex: inp.sourceOutputIndex,
      sourceTXID: inp.sourceTXID!,
      sequence: inp.sequence,
      unlockingScript: undefined as never,
      sourceSatoshis: 0,
      lockingScript: LockingScript.fromHex(''),
    })),
    outputs: tx.outputs.map((o) => ({ lockingScript: o.lockingScript, satoshis: o.satoshis ?? 0 })),
    unlockingScript: input.unlockingScript!,
    inputIndex: 0,
    inputSequence: input.sequence ?? 0xffffffff,
    lockTime: tx.lockTime,
  });
  return spend.validate();
}

async function deployAndCall(
  artifact: RunarArtifact,
  initial: bigint,
): Promise<{ deployTx: Transaction; callTx: Transaction; contract: RunarContract }> {
  const signer = new LocalSigner(SIGNER_KEY);
  const provider = new MockProvider();
  provider.addUtxo(await signer.getAddress(), {
    txid: 'ee'.repeat(32),
    outputIndex: 0,
    satoshis: 1_000_000,
    script: buildP2PKHScript(await signer.getPublicKey()),
  });
  const contract = new RunarContract(artifact, [initial] as unknown[]);
  contract.connect(provider, signer);
  await contract.deploy({ satoshis: 50_000 });
  await contract.call('rec', [], {});
  const [deployHex, callHex] = provider.getBroadcastedTxs();
  return {
    deployTx: Transaction.fromHex(deployHex!),
    callTx: Transaction.fromHex(callHex!),
    contract,
  };
}

/** The real BIP-143 scriptCode length for input 0: UTXO script after the codesep. */
function realScriptCodeLen(contract: RunarContract, deployTx: Transaction): number {
  const utxoHex = deployTx.outputs[0]!.lockingScript.toHex();
  const body = contract.getSubscriptForSigning(utxoHex, 0);
  const n = body.length / 2;
  // CompactSize prefix as carried in the preimage field.
  return n + (n < 0xfd ? 1 : n <= 0xffff ? 3 : 5);
}

describe('N-189: extractScriptCode prediction includes the UTXO state tail', () => {
  it('commits len(scriptCode) as the network computes it, and validates', async () => {
    const { deployTx, callTx, contract } = await deployAndCall(compileSource(LEN_SOURCE), 0n);
    // RED: the committed n is the template length (state tail missing).
    expect(contract.state.n).toBe(BigInt(realScriptCodeLen(contract, deployTx)));
    expect(validateSpend(callTx, deployTx)).toBe(true);
  });

  it('commits a value read from its own state tail, and validates', async () => {
    const { deployTx, callTx, contract } = await deployAndCall(compileSource(TAIL_SOURCE), 41n);
    // RED: the "last 8 bytes" are code bytes under the template mock.
    expect(contract.state.n).toBe(42n);
    expect(validateSpend(callTx, deployTx)).toBe(true);
  });
});
