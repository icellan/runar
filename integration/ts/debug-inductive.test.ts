import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';
import { Transaction, Spend, LockingScript, UnlockingScript } from '@bsv/sdk';

const ZERO_SENTINEL = '00'.repeat(36);
const ZERO_PROOF = '00'.repeat(256);

describe('Debug InductiveSmartContract', () => {
  it('traces first spend through BSV SDK Spend to find failures', async () => {
    const artifact = compileContract('examples/ts/inductive-token/InductiveToken.runar.ts');
    const provider = createProvider();
    const { signer, pubKeyHex } = await createFundedWallet(provider, 2.0);
    const tokenIdHex = Buffer.from('DEBUG-01').toString('hex');

    const contract = new RunarContract(artifact, [
      pubKeyHex, 1000n, tokenIdHex,
      ZERO_SENTINEL, ZERO_PROOF,
    ]);

    // Connect and deploy
    contract.connect(provider, signer);
    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 500_000 });
    expect(deployTxid).toBeTruthy();

    // Prepare first call
    const BOB = '02' + 'bb'.repeat(32);
    const prepared = await contract.prepareCall('send', [null, BOB, 400_000n]);

    // Intercept broadcast to capture tx hex
    let capturedTxHex: string | undefined;
    const origBroadcast = provider.broadcast.bind(provider);
    provider.broadcast = async (txHex: string) => {
      capturedTxHex = txHex;
      return origBroadcast(txHex);
    };

    try {
      await contract.finalizeCall(prepared, provider, signer);
    } catch {
      // expected to fail
    }

    expect(capturedTxHex).toBeTruthy();

    // Parse the spending tx
    const spendTx = Transaction.fromHex(capturedTxHex!);

    // Get deploy tx for locking script
    const deployTxRaw = await provider.getTransaction(deployTxid);
    const deployTx = Transaction.fromHex(deployTxRaw.raw!);
    const lockingScriptHex = deployTx.outputs[0]!.lockingScript.toHex();
    const unlockingScriptHex = spendTx.inputs[0]!.unlockingScript.toHex();

    console.log('Locking script:', lockingScriptHex.length / 2, 'bytes');
    console.log('Unlocking script:', unlockingScriptHex.length / 2, 'bytes');
    console.log('Deploy outputs:', deployTx.outputs.length);
    console.log('Spend inputs:', spendTx.inputs.length, 'outputs:', spendTx.outputs.length);

    // Use Spend to verify
    const spend = new Spend({
      sourceTXID: deployTxid,
      sourceOutputIndex: 0,
      sourceSatoshis: 500_000,
      lockingScript: LockingScript.fromHex(lockingScriptHex),
      transactionVersion: spendTx.version,
      otherInputs: spendTx.inputs.map((inp, i) => ({
        sourceOutputIndex: inp.sourceOutputIndex,
        sourceTXID: inp.sourceTXID!,
        sequence: inp.sequence,
        unlockingScript: inp.unlockingScript,
      })),
      inputIndex: 0,
      unlockingScript: UnlockingScript.fromHex(unlockingScriptHex),
      outputs: spendTx.outputs.map(o => ({
        lockingScript: o.lockingScript,
        satoshis: o.satoshis ?? 0,
      })),
      inputSequence: spendTx.inputs[0]!.sequence,
      lockTime: spendTx.lockTime,
    });

    try {
      const valid = spend.validate();
      console.log('Spend.validate() returned:', valid);
    } catch (e: any) {
      console.log('\nSpend.validate() error:', e.message);

      // Extract pc/step info from error message if available
      if (e.programCounter !== undefined) {
        console.log('Program counter:', e.programCounter);
      }
      if (e.instructionPointer !== undefined) {
        console.log('Instruction pointer:', e.instructionPointer);
      }

      // Try to get more details
      const errStr = e.toString();
      const pcMatch = errStr.match(/pc[:\s]*(\d+)/i);
      if (pcMatch) {
        console.log('PC from error:', pcMatch[1]);
        const pc = parseInt(pcMatch[1]);
        const opcode = parseInt(lockingScriptHex.slice(pc * 2, pc * 2 + 2), 16);
        console.log(`Opcode at PC ${pc}: 0x${opcode.toString(16)}`);
      }
    }
  });
});
