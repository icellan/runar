/**
 * Debug script: compile InductiveToken contract, build deploy + first spend,
 * then run through BSV SDK interpreter to find the exact failing opcode.
 */
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';
import { Transaction as BsvTransaction, Interpreter, Script as BsvScript } from '@aspect-run/bsv';

const ZERO_SENTINEL = '00'.repeat(36);
const ZERO_PROOF = '00'.repeat(256);

async function main() {
  const artifact = compileContract('examples/ts/inductive-token/InductiveToken.runar.ts');
  const provider = createProvider();
  const { signer, pubKeyHex } = await createFundedWallet(provider, 2.0);
  const tokenIdHex = Buffer.from('DEBUG-TOKEN').toString('hex');

  const contract = new RunarContract(artifact, [
    pubKeyHex, 1000n, tokenIdHex,
    ZERO_SENTINEL, ZERO_PROOF,
  ]);

  // Deploy
  const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 500_000 });
  console.log('Deploy txid:', deployTxid);

  // Prepare the first call (send)
  const BOB = '02' + 'bb'.repeat(32);
  const prepared = await contract.prepareCall('send', {
    sig: null,
    to: BOB,
    outputSatoshis: 400_000n,
  }, provider, signer);

  // Finalize and capture the tx hex
  try {
    const { txid } = await contract.finalizeCall(prepared, provider, signer);
    console.log('Spend txid:', txid);
  } catch (err: any) {
    console.error('Spend failed:', err.message);

    // Get the failing tx from the contract's internal state
    // Let's try to manually build and debug
    console.log('\n--- Attempting BSV SDK interpreter debug ---');
    console.log('Locking script length:', contract.currentUtxo?.script?.length ?? 'N/A', 'hex chars');
    console.log('UTXO satoshis:', contract.currentUtxo?.satoshis);
  }
}

main().catch(e => { console.error(e); process.exit(1); });
