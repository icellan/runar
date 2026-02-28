/**
 * TSOP SDK Usage Examples -- TypeScript
 *
 * Comprehensive examples showing how to compile, deploy, and spend/unlock
 * all 8 TSOP example contracts using the tsop-compiler and tsop-sdk packages.
 *
 * Each section follows the same pattern:
 *   1. Compile the contract source to a TSOPArtifact
 *   2. Instantiate a TSOPContract with constructor arguments
 *   3. Deploy: create a locking-script UTXO on chain
 *   4. Call/spend: build an unlocking script that satisfies the contract
 *
 * For stateful contracts (Counter, FT, NFT, Auction, CovenantVault) the
 * examples also explain the OP_PUSH_TX technique:
 *   - The sighash preimage is the BIP-143 serialization of the spending tx
 *   - A special ECDSA signature is computed with private key = 1 (point G)
 *   - r = Gx (constant), s = (sighash + r) mod n
 *   - Both preimage and signature are pushed in the unlocking script
 *   - Reference: https://wiki.bitcoinsv.io/index.php/OP_PUSH_TX
 *
 * Prerequisites:
 *   npm install tsop-compiler tsop-sdk tsop-lang
 *   (or use the monorepo workspace packages)
 */

import { readFileSync } from 'node:fs';
import { compile } from 'tsop-compiler';
import type { CompileResult } from 'tsop-compiler';
import type { TSOPArtifact } from 'tsop-ir-schema';
import {
  TSOPContract,
  MockProvider,
  LocalSigner,
  serializeState,
  deserializeState,
} from 'tsop-sdk';

// =============================================================================
// Helper: compile a .tsop.ts file and return the artifact
// =============================================================================

function compileContract(filePath: string): TSOPArtifact {
  const source = readFileSync(filePath, 'utf-8');
  const result: CompileResult = compile(source, { fileName: filePath });

  if (!result.success) {
    const errors = result.diagnostics
      .filter(d => d.severity === 'error')
      .map(d => `  ${d.message} (${d.loc?.line}:${d.loc?.column})`)
      .join('\n');
    throw new Error(`Compilation failed for ${filePath}:\n${errors}`);
  }

  if (!result.artifact) {
    throw new Error(
      `Compilation produced no artifact for ${filePath}. ` +
      `Passes 5-6 (stack-lower + emit) may not have completed.`
    );
  }

  console.log(`Compiled ${result.artifact.contractName}: ${result.scriptAsm}`);
  console.log(`  Script hex (${result.scriptHex!.length / 2} bytes): ${result.scriptHex!.slice(0, 60)}...`);
  console.log(`  Methods: ${result.artifact.abi.methods.filter(m => m.isPublic).map(m => m.name).join(', ')}`);

  if (result.artifact.stateFields && result.artifact.stateFields.length > 0) {
    console.log(`  State fields: ${result.artifact.stateFields.map(f => `${f.name}: ${f.type}`).join(', ')}`);
  }

  return result.artifact;
}

// =============================================================================
// Helper: compile from an inline string (alternative to file-based compilation)
// =============================================================================

function compileInline(source: string, name: string): TSOPArtifact {
  const result = compile(source, { fileName: `${name}.tsop.ts` });

  if (!result.success || !result.artifact) {
    const errors = result.diagnostics
      .filter(d => d.severity === 'error')
      .map(d => d.message)
      .join('; ');
    throw new Error(`Inline compilation failed for ${name}: ${errors}`);
  }

  return result.artifact;
}

// =============================================================================
// Helper: set up a mock environment for examples
// =============================================================================

function createTestEnvironment() {
  const provider = new MockProvider('testnet');

  // Two signers representing different parties
  const aliceKey = 'a'.repeat(64);  // 32-byte hex private key (test only!)
  const bobKey   = 'b'.repeat(64);
  const carolKey = 'c'.repeat(64);

  const alice = new LocalSigner(aliceKey);
  const bob   = new LocalSigner(bobKey);
  const carol = new LocalSigner(carolKey);

  return { provider, alice, bob, carol };
}

/**
 * Seed a MockProvider with a funding UTXO for a given signer.
 * In production you would query the blockchain; here we inject test data.
 */
async function seedFunding(
  provider: MockProvider,
  signer: LocalSigner,
  satoshis: number = 100_000,
): Promise<void> {
  const address = await signer.getAddress();
  const pubKey = await signer.getPublicKey();
  const p2pkhScript = '76a914' + simpleHash160(pubKey) + '88ac';

  provider.addUtxo(address, {
    txid: 'f'.repeat(64),  // dummy funding txid
    outputIndex: 0,
    satoshis,
    script: p2pkhScript,
  });
}

/** Minimal hash160 placeholder for test addresses. */
function simpleHash160(hex: string): string {
  let hash = 0;
  for (let i = 0; i < hex.length; i++) {
    hash = ((hash << 5) - hash + hex.charCodeAt(i)) | 0;
  }
  return Math.abs(hash).toString(16).padStart(40, '0').slice(0, 40);
}


// #############################################################################
//
//  1. P2PKH -- Pay to Public Key Hash
//
//  The simplest Bitcoin smart contract: locks funds to a public key hash.
//  Spending requires a valid signature and the matching public key.
//
// #############################################################################

async function exampleP2PKH() {
  console.log('\n' + '='.repeat(72));
  console.log('  1. P2PKH -- Pay to Public Key Hash');
  console.log('='.repeat(72));

  // ---- Step 1: Compile the contract ----
  const artifact = compileContract('examples/p2pkh/P2PKH.tsop.ts');

  // The P2PKH ABI expects one constructor param: pubKeyHash (Addr = 20 bytes)
  // and one public method: unlock(sig: Sig, pubKey: PubKey)
  console.log('\nABI constructor params:', artifact.abi.constructor.params);
  console.log('ABI methods:', artifact.abi.methods.map(m => `${m.name}(${m.params.map(p => p.name + ': ' + p.type).join(', ')})`));

  // ---- Step 2: Set up the environment ----
  const { provider, alice } = createTestEnvironment();
  await seedFunding(provider, alice);

  // Alice's public key hash (20 bytes). In production this would come from
  // hash160(compressedPubKey).
  const alicePubKey = await alice.getPublicKey();
  const alicePubKeyHash = simpleHash160(alicePubKey);

  // ---- Step 3: Deploy -- create a UTXO locked to Alice's pubkey hash ----
  const contract = new TSOPContract(artifact, [alicePubKeyHash]);

  console.log('\nLocking script hex:', contract.getLockingScript().slice(0, 80) + '...');

  const deployResult = await contract.deploy(provider, alice, {
    satoshis: 50_000,
  });
  console.log('Deployed P2PKH txid:', deployResult.txid);

  // ---- Step 4: Spend -- Alice provides her signature and public key ----
  // The unlocking script pushes: <sig> <pubKey> onto the stack.
  // The locking script then checks: hash160(pubKey) == pubKeyHash && checkSig(sig, pubKey)
  const dummySig = await alice.sign(deployResult.tx.raw ?? '', 0, contract.getLockingScript(), 50_000);

  const callResult = await contract.call(
    'unlock',
    [dummySig, alicePubKey],
    provider,
    alice,
  );
  console.log('Spent P2PKH txid:', callResult.txid);

  // You can also compile P2PKH inline:
  const inlineArtifact = compileInline(`
    import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'tsop-lang';

    class P2PKH extends SmartContract {
      readonly pubKeyHash: Addr;

      constructor(pubKeyHash: Addr) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
      }

      public unlock(sig: Sig, pubKey: PubKey) {
        assert(hash160(pubKey) === this.pubKeyHash);
        assert(checkSig(sig, pubKey));
      }
    }
  `, 'P2PKH-inline');
  console.log('Inline P2PKH compiled successfully:', inlineArtifact.contractName);
}


// #############################################################################
//
//  2. ESCROW -- Multi-party escrow with arbiter
//
//  Locks funds requiring authorization from buyer, seller, or arbiter.
//  Four spending paths: releaseBySeller, releaseByArbiter,
//  refundToBuyer, refundByArbiter.
//
// #############################################################################

async function exampleEscrow() {
  console.log('\n' + '='.repeat(72));
  console.log('  2. ESCROW -- Multi-party Escrow');
  console.log('='.repeat(72));

  // ---- Step 1: Compile ----
  const artifact = compileContract('examples/escrow/Escrow.tsop.ts');

  // The Escrow contract has 3 constructor params (buyer, seller, arbiter PubKeys)
  // and 4 public methods, each requiring a single Sig argument.
  console.log('\nPublic methods:', artifact.abi.methods.filter(m => m.isPublic).map(m => m.name));

  // ---- Step 2: Environment ----
  const { provider, alice, bob, carol } = createTestEnvironment();
  // alice = buyer, bob = seller, carol = arbiter
  await seedFunding(provider, alice);

  const buyerPubKey  = await alice.getPublicKey();
  const sellerPubKey = await bob.getPublicKey();
  const arbiterPubKey = await carol.getPublicKey();

  // ---- Step 3: Deploy -- buyer funds the escrow ----
  const escrow = new TSOPContract(artifact, [buyerPubKey, sellerPubKey, arbiterPubKey]);

  const deployResult = await escrow.deploy(provider, alice, {
    satoshis: 75_000,
  });
  console.log('\nDeployed Escrow txid:', deployResult.txid);
  console.log('Escrow locking script:', escrow.getLockingScript().slice(0, 80) + '...');

  // ---- Step 4a: Release by seller (happy path) ----
  // The seller signs to release funds. Method index 0 in the ABI.
  const sellerSig = await bob.sign(deployResult.tx.raw ?? '', 0, escrow.getLockingScript(), 75_000);

  // Note: since the contract has 4 public methods, the unlocking script
  // includes a method selector (index) appended by buildUnlockingScript.
  const unlockScript = escrow.buildUnlockingScript('releaseBySeller', [sellerSig]);
  console.log('Unlock script for releaseBySeller (hex):', unlockScript.slice(0, 60) + '...');

  // We need to re-seed because the first contract UTXO was consumed
  await seedFunding(provider, alice);

  const releaseResult = await escrow.call(
    'releaseBySeller',
    [sellerSig],
    provider,
    alice,
  );
  console.log('Released by seller, txid:', releaseResult.txid);

  // ---- Step 4b: Refund by arbiter (dispute path) ----
  // In a dispute scenario, the arbiter signs a refund to the buyer.
  // First re-deploy for this example path.
  await seedFunding(provider, alice);
  const escrow2 = new TSOPContract(artifact, [buyerPubKey, sellerPubKey, arbiterPubKey]);
  const deploy2 = await escrow2.deploy(provider, alice, { satoshis: 75_000 });

  const arbiterSig = await carol.sign(deploy2.tx.raw ?? '', 0, escrow2.getLockingScript(), 75_000);
  await seedFunding(provider, alice);

  const refundResult = await escrow2.call(
    'refundByArbiter',
    [arbiterSig],
    provider,
    alice,
  );
  console.log('Refunded by arbiter, txid:', refundResult.txid);
}


// #############################################################################
//
//  3. STATEFUL COUNTER -- OP_PUSH_TX pattern
//
//  A counter that persists across transactions. Each spend increments or
//  decrements the count and propagates the updated state into a new UTXO.
//
//  This contract uses the OP_PUSH_TX technique:
//    - The unlocking script provides the BIP-143 sighash preimage
//    - checkPreimage() verifies it against an ECDSA signature with privkey=1
//    - The contract reads the preimage to enforce output constraints
//    - hash256(getStateScript()) must match the output hash in the preimage
//
// #############################################################################

async function exampleCounter() {
  console.log('\n' + '='.repeat(72));
  console.log('  3. STATEFUL COUNTER -- OP_PUSH_TX');
  console.log('='.repeat(72));

  // ---- Step 1: Compile ----
  const artifact = compileContract('examples/stateful-counter/Counter.tsop.ts');

  // The Counter has one state field: count (bigint), which is NOT readonly.
  // State fields appear in artifact.stateFields.
  console.log('\nState fields:', artifact.stateFields);
  console.log('Methods:', artifact.abi.methods.filter(m => m.isPublic).map(m =>
    `${m.name}(${m.params.map(p => p.name + ': ' + p.type).join(', ')})`
  ));

  // ---- Step 2: Environment ----
  const { provider, alice } = createTestEnvironment();
  await seedFunding(provider, alice, 200_000);

  // ---- Step 3: Deploy with initial count = 0 ----
  const counter = new TSOPContract(artifact, [0n]);

  console.log('\nInitial state:', counter.state);
  console.log('Locking script (with state):', counter.getLockingScript().slice(0, 80) + '...');

  const deployResult = await counter.deploy(provider, alice, {
    satoshis: 10_000,
  });
  console.log('Deployed Counter txid:', deployResult.txid);
  console.log('State after deploy:', counter.state);

  // ---- Step 4: Increment the counter ----
  //
  // HOW OP_PUSH_TX WORKS:
  //
  // 1. Build the spending transaction with the new contract UTXO as output[0].
  //    The output script is the contract code + OP_RETURN + serialized(count=1).
  //
  // 2. Compute the BIP-143 sighash preimage of that transaction.
  //    The preimage is a serialization of:
  //      nVersion || hashPrevouts || hashSequence || outpoint || scriptCode
  //      || value || nSequence || hashOutputs || nLockTime || sigHashType
  //
  // 3. Compute sighash = SHA256d(preimage).
  //
  // 4. Create an ECDSA signature using private key = 1:
  //      - The public key for privkey=1 is the generator point G.
  //      - r = Gx (the x-coordinate of G, a secp256k1 constant)
  //      - s = (sighash + r) mod n  (since privkey k=1, s = z + r*k = z + r)
  //
  // 5. Push [preimage, signature] as the unlocking script.
  //    The locking script runs checkPreimage() which:
  //      a) Verifies the signature against pubkey=G using OP_CHECKSIG
  //      b) This implicitly proves the preimage is the real sighash preimage
  //    Then the contract logic extracts hashOutputs from the preimage and
  //    compares it to hash256(this.getStateScript()) to enforce the new state.
  //
  // In practice, the SDK handles most of this. The caller just provides the
  // txPreimage argument to the method call:

  // For a full manual construction, you would do:
  //
  //   import { Transaction, Hash } from '@bsv/sdk';
  //
  //   // Build the tx with the new output
  //   const spendTx = new Transaction();
  //   spendTx.addInput({ ... previous contract UTXO ... });
  //   spendTx.addOutput({ lockingScript: newLockingScript, satoshis: 10000 });
  //
  //   // Compute BIP-143 preimage
  //   const preimage = spendTx.getPreimage(0, lockingScript, 10000, 0x41);
  //
  //   // Sign with privkey=1
  //   const sighash = Hash.sha256d(preimage);
  //   const Gx = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
  //   const n  = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
  //   const r  = Gx;
  //   const s  = (BigInt('0x' + sighash) + r) % n;
  //   const sig = derEncode(r, s) + '41'; // append SIGHASH_ALL|FORKID
  //
  //   // The unlocking script is: <sig> <preimage>
  //   spendTx.inputs[0].setScript(Script.fromASM(`${sig} ${preimage}`));

  // Using the SDK, the preimage is passed as an argument to the method.
  // Here we pass a placeholder since MockProvider does not do real tx signing.
  const fakeTxPreimage = '00'.repeat(181); // BIP-143 preimage is ~181 bytes

  await seedFunding(provider, alice, 200_000);

  const incrementResult = await counter.call(
    'increment',
    [fakeTxPreimage],
    provider,
    alice,
    { satoshis: 10_000 }, // carry forward the same satoshis
  );
  console.log('Incremented counter, txid:', incrementResult.txid);
  console.log('State after increment:', counter.state);

  // ---- State serialization/deserialization ----
  if (artifact.stateFields) {
    const stateHex = serializeState(artifact.stateFields, { count: 1n });
    console.log('Serialized state (count=1):', stateHex);

    const decoded = deserializeState(artifact.stateFields, stateHex);
    console.log('Deserialized state:', decoded);
  }

  // ---- Step 5: Decrement back to 0 ----
  await seedFunding(provider, alice, 200_000);

  const decrementResult = await counter.call(
    'decrement',
    [fakeTxPreimage],
    provider,
    alice,
    { satoshis: 10_000 },
  );
  console.log('Decremented counter, txid:', decrementResult.txid);
  console.log('State after decrement:', counter.state);
}


// #############################################################################
//
//  4. FUNGIBLE TOKEN -- Stateful ownership transfer
//
//  A simple fungible token with a stateful owner field and an immutable supply.
//  Transfer requires the current owner's signature and uses OP_PUSH_TX to
//  propagate the new owner into the next UTXO.
//
// #############################################################################

async function exampleFungibleToken() {
  console.log('\n' + '='.repeat(72));
  console.log('  4. FUNGIBLE TOKEN -- Stateful Ownership Transfer');
  console.log('='.repeat(72));

  // ---- Step 1: Compile ----
  const artifact = compileContract('examples/token-ft/FungibleTokenExample.tsop.ts');

  console.log('\nState fields:', artifact.stateFields);
  // State: owner (PubKey) is mutable; supply (bigint) is readonly.

  // ---- Step 2: Environment ----
  const { provider, alice, bob } = createTestEnvironment();
  await seedFunding(provider, alice, 200_000);

  const alicePubKey = await alice.getPublicKey();
  const bobPubKey   = await bob.getPublicKey();

  // ---- Step 3: Deploy -- Alice mints 1,000,000 tokens ----
  const token = new TSOPContract(artifact, [alicePubKey, 1_000_000n]);

  const deployResult = await token.deploy(provider, alice, {
    satoshis: 10_000,
  });
  console.log('\nDeployed FT txid:', deployResult.txid);
  console.log('Initial state:', token.state);
  console.log('Locking script:', token.getLockingScript().slice(0, 80) + '...');

  // ---- Step 4: Transfer ownership from Alice to Bob ----
  //
  // The transfer method requires:
  //   1. sig: Sig         -- current owner (Alice) signs
  //   2. newOwner: PubKey -- Bob's public key
  //   3. txPreimage: SigHashPreimage -- OP_PUSH_TX preimage
  //
  // The contract verifies:
  //   - checkSig(sig, this.owner)  -- Alice authorized the transfer
  //   - checkPreimage(txPreimage)  -- preimage is authentic
  //   - After updating this.owner = newOwner:
  //     hash256(getStateScript()) === extractOutputHash(txPreimage)
  //     This ensures the spending tx's output contains the contract with
  //     the updated owner field set to Bob's pubkey.

  const aliceSig = await alice.sign('', 0, token.getLockingScript(), 10_000);
  const fakeTxPreimage = '00'.repeat(181);

  await seedFunding(provider, alice, 200_000);

  const transferResult = await token.call(
    'transfer',
    [aliceSig, bobPubKey, fakeTxPreimage],
    provider,
    alice,
    { satoshis: 10_000 },
  );
  console.log('Transferred FT to Bob, txid:', transferResult.txid);
  console.log('State after transfer:', token.state);

  // ---- Verify the new locking script has Bob as owner ----
  // After transfer, the locking script's state section should now encode
  // Bob's pubkey as the owner. The supply remains immutable in the code.
  console.log('New locking script:', token.getLockingScript().slice(0, 80) + '...');
}


// #############################################################################
//
//  5. NFT -- Non-Fungible Token with transfer and burn
//
//  An NFT with immutable tokenId and metadata, plus a mutable owner.
//  Supports two spending paths:
//    - transfer: change ownership (stateful, uses OP_PUSH_TX)
//    - burn: destroy the token (non-stateful, no state continuation)
//
// #############################################################################

async function exampleNFT() {
  console.log('\n' + '='.repeat(72));
  console.log('  5. NFT -- Non-Fungible Token');
  console.log('='.repeat(72));

  // ---- Step 1: Compile ----
  const artifact = compileContract('examples/token-nft/NFTExample.tsop.ts');

  console.log('\nState fields:', artifact.stateFields);
  // State: owner (PubKey) is mutable; tokenId and metadata are readonly.

  // ---- Step 2: Environment ----
  const { provider, alice, bob } = createTestEnvironment();
  await seedFunding(provider, alice, 200_000);

  const alicePubKey = await alice.getPublicKey();
  const bobPubKey   = await bob.getPublicKey();

  // Token metadata: a unique ID and a metadata URI/hash
  const tokenId = Buffer.from('TSOP-NFT-0001').toString('hex');
  const metadata = Buffer.from('ipfs://QmExample123').toString('hex');

  // ---- Step 3: Deploy -- Alice mints the NFT ----
  const nft = new TSOPContract(artifact, [alicePubKey, tokenId, metadata]);

  const deployResult = await nft.deploy(provider, alice, {
    satoshis: 5_000,
  });
  console.log('\nDeployed NFT txid:', deployResult.txid);
  console.log('Token ID:', tokenId, '=', Buffer.from(tokenId, 'hex').toString());
  console.log('Metadata:', metadata, '=', Buffer.from(metadata, 'hex').toString());
  console.log('Initial owner:', alicePubKey.slice(0, 20) + '...');

  // ---- Step 4: Transfer NFT from Alice to Bob ----
  // Same OP_PUSH_TX pattern as the fungible token: the spending transaction
  // must contain an output with the updated locking script (new owner = Bob).
  const aliceSig = await alice.sign('', 0, nft.getLockingScript(), 5_000);
  const fakeTxPreimage = '00'.repeat(181);

  await seedFunding(provider, alice, 200_000);

  const transferResult = await nft.call(
    'transfer',
    [aliceSig, bobPubKey, fakeTxPreimage],
    provider,
    alice,
    { satoshis: 5_000 },
  );
  console.log('Transferred NFT to Bob, txid:', transferResult.txid);

  // ---- Step 5: Burn the NFT (Bob destroys it) ----
  // The burn method only requires the owner's signature. There is no state
  // continuation -- the UTXO is consumed with no contract output, effectively
  // destroying the NFT.
  const bobSig = await bob.sign('', 0, nft.getLockingScript(), 5_000);

  await seedFunding(provider, alice, 200_000);

  const burnResult = await nft.call(
    'burn',
    [bobSig],
    provider,
    alice,
  );
  console.log('Burned NFT, txid:', burnResult.txid);
  console.log('NFT is now destroyed -- no state continuation UTXO.');
}


// #############################################################################
//
//  6. AUCTION -- Stateful bidding with deadline
//
//  An on-chain auction where:
//    - Anyone can bid (must exceed the current highest bid)
//    - Bidding is open until the deadline (enforced via nLockTime)
//    - Only the auctioneer can close the auction after the deadline
//
//  Uses OP_PUSH_TX for both bid() and close():
//    - bid: updates highestBidder and highestBid in the state
//    - close: no state continuation (auction ends)
//
// #############################################################################

async function exampleAuction() {
  console.log('\n' + '='.repeat(72));
  console.log('  6. AUCTION -- Stateful Bidding');
  console.log('='.repeat(72));

  // ---- Step 1: Compile ----
  const artifact = compileContract('examples/auction/Auction.tsop.ts');

  console.log('\nState fields:', artifact.stateFields);
  // State: highestBidder (PubKey) and highestBid (bigint) are mutable.
  // Readonly: auctioneer (PubKey) and deadline (bigint).

  // ---- Step 2: Environment ----
  const { provider, alice, bob, carol } = createTestEnvironment();
  // alice = auctioneer, bob/carol = bidders
  await seedFunding(provider, alice, 500_000);

  const auctioneerPubKey = await alice.getPublicKey();
  const bobPubKey        = await bob.getPublicKey();
  const carolPubKey      = await carol.getPublicKey();

  // ---- Step 3: Deploy the auction ----
  // Constructor: auctioneer, initialBidder, initialBid, deadline (block height)
  const deadline = 800_000n; // block height at which the auction closes
  const initialBid = 1000n;  // starting bid in satoshis

  const auction = new TSOPContract(artifact, [
    auctioneerPubKey, // auctioneer
    auctioneerPubKey, // initial highest bidder (auctioneer as placeholder)
    initialBid,       // initial highest bid
    deadline,         // block height deadline
  ]);

  const deployResult = await auction.deploy(provider, alice, {
    satoshis: 50_000,
  });
  console.log('\nDeployed Auction txid:', deployResult.txid);
  console.log('Deadline block height:', deadline.toString());
  console.log('Starting bid:', initialBid.toString(), 'satoshis');
  console.log('State:', auction.state);

  // ---- Step 4: Bob places a bid ----
  //
  // The bid method takes:
  //   1. bidder: PubKey          -- Bob's public key
  //   2. bidAmount: bigint       -- must exceed current highest bid
  //   3. txPreimage: SigHashPreimage
  //
  // The contract enforces:
  //   - bidAmount > this.highestBid
  //   - extractLocktime(txPreimage) < this.deadline  (auction still open)
  //   - State is updated: highestBidder = Bob, highestBid = bidAmount
  //   - Output hash matches the updated state script
  //
  // In a real implementation, the previous highest bidder should receive a
  // refund output. This simplified example focuses on the state transition.

  const fakeTxPreimage = '00'.repeat(181);
  await seedFunding(provider, alice, 500_000);

  const bid1Result = await auction.call(
    'bid',
    [bobPubKey, 5000n, fakeTxPreimage],
    provider,
    alice,
    { satoshis: 50_000 },
  );
  console.log('\nBob bid 5000 sats, txid:', bid1Result.txid);
  console.log('State after bid:', auction.state);

  // ---- Step 5: Carol outbids Bob ----
  await seedFunding(provider, alice, 500_000);

  const bid2Result = await auction.call(
    'bid',
    [carolPubKey, 10000n, fakeTxPreimage],
    provider,
    alice,
    { satoshis: 50_000 },
  );
  console.log('Carol bid 10000 sats, txid:', bid2Result.txid);
  console.log('State after outbid:', auction.state);

  // ---- Step 6: Auctioneer closes the auction ----
  // The close method requires:
  //   1. sig: Sig                 -- auctioneer's signature
  //   2. txPreimage: SigHashPreimage
  //
  // Enforcement:
  //   - checkSig(sig, this.auctioneer) -- only the auctioneer can close
  //   - extractLocktime(txPreimage) >= this.deadline -- deadline has passed
  //   - No state continuation -- the auction UTXO is consumed.
  //
  // The nLockTime of the spending transaction must be >= deadline. This is
  // enforced on-chain by reading the locktime from the preimage.

  const auctioneerSig = await alice.sign('', 0, auction.getLockingScript(), 50_000);
  await seedFunding(provider, alice, 500_000);

  const closeResult = await auction.call(
    'close',
    [auctioneerSig, fakeTxPreimage],
    provider,
    alice,
  );
  console.log('Auction closed by auctioneer, txid:', closeResult.txid);
  console.log('Winner: Carol (highest bidder). Auction UTXO consumed.');
}


// #############################################################################
//
//  7. ORACLE PRICE FEED -- Rabin signature verification
//
//  A contract that pays out only when an oracle-signed price exceeds a
//  threshold. The oracle signs the price using a Rabin signature scheme,
//  which is cheap to verify in Bitcoin Script.
//
//  This contract does NOT use OP_PUSH_TX -- it is non-stateful.
//
// #############################################################################

async function exampleOraclePriceFeed() {
  console.log('\n' + '='.repeat(72));
  console.log('  7. ORACLE PRICE FEED -- Rabin Signature');
  console.log('='.repeat(72));

  // ---- Step 1: Compile ----
  const artifact = compileContract('examples/oracle-price/OraclePriceFeed.tsop.ts');

  console.log('\nABI methods:', artifact.abi.methods.filter(m => m.isPublic).map(m =>
    `${m.name}(${m.params.map(p => p.name + ': ' + p.type).join(', ')})`
  ));

  // ---- Step 2: Environment ----
  const { provider, alice } = createTestEnvironment();
  await seedFunding(provider, alice, 200_000);

  const receiverPubKey = await alice.getPublicKey();

  // The oracle's Rabin public key (a large integer, hex-encoded).
  // In production, the oracle publishes this key and signs price data off-chain.
  // Rabin signatures are particularly efficient in Bitcoin Script because
  // verification only requires modular exponentiation (OP_MUL, OP_MOD).
  const oracleRabinPubKey = 'ab'.repeat(32); // 256-bit placeholder

  // ---- Step 3: Deploy ----
  const oracle = new TSOPContract(artifact, [oracleRabinPubKey, receiverPubKey]);

  const deployResult = await oracle.deploy(provider, alice, {
    satoshis: 25_000,
  });
  console.log('\nDeployed OraclePriceFeed txid:', deployResult.txid);
  console.log('Oracle Rabin pubkey:', oracleRabinPubKey.slice(0, 20) + '...');
  console.log('Receiver:', receiverPubKey.slice(0, 20) + '...');

  // ---- Step 4: Settle -- oracle provides a signed price ----
  //
  // The settle method requires:
  //   1. price: bigint        -- the price value (e.g., BTC/USD in cents)
  //   2. rabinSig: RabinSig   -- oracle's Rabin signature over num2bin(price, 8)
  //   3. padding: ByteString  -- Rabin signature padding bytes
  //   4. sig: Sig             -- receiver's ECDSA signature
  //
  // The contract verifies:
  //   - verifyRabinSig(num2bin(price, 8), rabinSig, padding, oraclePubKey)
  //     This proves the oracle attested to this specific price.
  //   - price > 50000  (threshold check -- only pays out above $50,000)
  //   - checkSig(sig, receiver)  -- receiver must also authorize
  //
  // Rabin signature verification in script:
  //   Given message m, signature s, padding p, and public key n:
  //   Verify that s^2 mod n == m + p
  //   This is extremely cheap in Bitcoin Script compared to ECDSA.

  const price = 65000n;  // BTC price = $65,000, above the $50,000 threshold
  const rabinSig = 'cd'.repeat(32);  // placeholder Rabin signature
  const padding  = 'ef'.repeat(8);   // placeholder padding
  const receiverSig = await alice.sign('', 0, oracle.getLockingScript(), 25_000);

  await seedFunding(provider, alice, 200_000);

  const settleResult = await oracle.call(
    'settle',
    [price, rabinSig, padding, receiverSig],
    provider,
    alice,
  );
  console.log('Settled OraclePriceFeed at price $' + price.toString() + ', txid:', settleResult.txid);
  console.log('Funds released to receiver since price > $50,000 threshold.');
}


// #############################################################################
//
//  8. COVENANT VAULT -- Spending constraints via OP_PUSH_TX
//
//  A vault that enforces spending constraints: only the owner can spend,
//  and each spend must meet a minimum output amount. Uses OP_PUSH_TX
//  to inspect the spending transaction's outputs.
//
// #############################################################################

async function exampleCovenantVault() {
  console.log('\n' + '='.repeat(72));
  console.log('  8. COVENANT VAULT -- Spending Constraints');
  console.log('='.repeat(72));

  // ---- Step 1: Compile ----
  const artifact = compileContract('examples/covenant-vault/CovenantVault.tsop.ts');

  console.log('\nABI:', artifact.abi.methods.filter(m => m.isPublic).map(m =>
    `${m.name}(${m.params.map(p => p.name + ': ' + p.type).join(', ')})`
  ));

  // ---- Step 2: Environment ----
  const { provider, alice } = createTestEnvironment();
  await seedFunding(provider, alice, 500_000);

  const ownerPubKey = await alice.getPublicKey();

  // The recipient address (20-byte hash) and a minimum withdrawal amount.
  // The covenant ensures every spend sends at least minAmount to the recipient.
  const recipientAddr = simpleHash160('recipient-cold-storage');
  const minAmount = 10_000n; // minimum 10,000 satoshis per withdrawal

  // ---- Step 3: Deploy ----
  const vault = new TSOPContract(artifact, [ownerPubKey, recipientAddr, minAmount]);

  const deployResult = await vault.deploy(provider, alice, {
    satoshis: 100_000,
  });
  console.log('\nDeployed CovenantVault txid:', deployResult.txid);
  console.log('Owner:', ownerPubKey.slice(0, 20) + '...');
  console.log('Recipient addr:', recipientAddr);
  console.log('Min amount:', minAmount.toString(), 'satoshis');

  // ---- Step 4: Spend from the vault ----
  //
  // The spend method requires:
  //   1. sig: Sig                 -- owner's signature
  //   2. amount: bigint           -- amount to send (must be >= minAmount)
  //   3. txPreimage: SigHashPreimage
  //
  // The contract enforces:
  //   - checkSig(sig, this.owner)      -- only owner can authorize
  //   - checkPreimage(txPreimage)       -- preimage is authentic (OP_PUSH_TX)
  //   - amount >= this.minAmount        -- covenant constraint
  //
  // The preimage allows the contract to inspect the spending transaction.
  // A production vault would also verify that the output script matches
  // buildP2PKH(this.recipient) and that the output value matches the amount.
  //
  // OP_PUSH_TX details for the vault:
  //   The BIP-143 preimage contains hashOutputs, which is the double-SHA256
  //   of all serialized outputs. The contract can extract this and compare it
  //   to an expected hash, thereby constraining WHERE the funds can go and
  //   HOW MUCH is sent. This is what makes it a "covenant" -- the script
  //   restricts future spending beyond just who can sign.

  const ownerSig = await alice.sign('', 0, vault.getLockingScript(), 100_000);
  const amount = 25_000n; // withdrawing 25,000 sats (above the 10,000 minimum)
  const fakeTxPreimage = '00'.repeat(181);

  await seedFunding(provider, alice, 500_000);

  const spendResult = await vault.call(
    'spend',
    [ownerSig, amount, fakeTxPreimage],
    provider,
    alice,
  );
  console.log('Spent from vault:', amount.toString(), 'sats, txid:', spendResult.txid);

  // ---- Attempting to spend below minimum (would fail on-chain) ----
  console.log('\nNote: spending amount < minAmount (e.g. 5000 < 10000) would');
  console.log('cause the script to fail with OP_VERIFY, rejecting the transaction.');
}


// #############################################################################
//
//  OP_PUSH_TX Deep Dive
//
//  Detailed explanation of the OP_PUSH_TX technique used in stateful
//  contracts (Counter, FT, NFT, Auction, CovenantVault).
//
// #############################################################################

function opPushTxExplainer() {
  console.log('\n' + '='.repeat(72));
  console.log('  OP_PUSH_TX -- Technical Deep Dive');
  console.log('='.repeat(72));

  console.log(`
OP_PUSH_TX is a technique that allows a Bitcoin script to introspect the
transaction that is spending it. Here is how it works:

1. BIP-143 SIGHASH PREIMAGE
   Bitcoin's OP_CHECKSIG computes a hash of a "sighash preimage" -- a
   serialization of the transaction being verified. BIP-143 defines this
   preimage format for SegWit (and BSV uses the same format):

     nVersion          (4 bytes)
     hashPrevouts      (32 bytes) -- double-SHA256 of all input outpoints
     hashSequence      (32 bytes) -- double-SHA256 of all input sequences
     outpoint          (36 bytes) -- txid + vout of the input being signed
     scriptCode        (variable) -- the locking script being executed
     value             (8 bytes)  -- satoshis of the UTXO being spent
     nSequence         (4 bytes)  -- sequence number of the input
     hashOutputs       (32 bytes) -- double-SHA256 of all serialized outputs
     nLockTime         (4 bytes)  -- transaction locktime
     sigHashType       (4 bytes)  -- sighash flags

2. THE TRICK: SIGN WITH PRIVATE KEY = 1
   If we use private key k=1, the public key is the generator point G.
   The ECDSA signature (r, s) becomes:
     r = Gx  (a known constant: 0x79BE667E...16F81798)
     s = (z + r * k) / k = z + r  (since k=1, and k_nonce=1)
   where z = sighash = SHA256d(preimage).

   Since r is a constant and s depends only on z and r, we can compute
   the signature WITHOUT knowing the private key of the UTXO owner.
   We just need the preimage itself.

3. HOW THE SCRIPT USES IT
   The unlocking script pushes: <preimage> <sig>
   The locking script:
     a) Runs OP_CHECKSIG with pubkey=G, which passes if sig is valid for
        the actual spending transaction. This proves the preimage is real.
     b) Now the script can parse the preimage to extract fields like
        hashOutputs, nLockTime, value, etc.
     c) The contract computes hash256(expectedOutputScript) and compares
        it to the hashOutputs extracted from the preimage.
     d) If they match, the spending transaction MUST contain the expected
        outputs, effectively constraining future state.

4. SECP256K1 CONSTANTS
   Generator point G:
     Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
     Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
   Curve order n:
     n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

   Compressed public key for G: 0279BE667E...16F81798 (33 bytes)

5. REFERENCE
   https://wiki.bitcoinsv.io/index.php/OP_PUSH_TX
   https://github.com/bitcoin-sv/bitcoin-sv/blob/master/doc/abc/replay-protected-sighash.md
`);
}


// #############################################################################
//
//  Advanced: Production transaction construction with @bsv/sdk
//
//  The @bsv/sdk (https://github.com/bsv-blockchain/ts-sdk) is the official
//  TypeScript SDK for BSV. It provides PrivateKey, Transaction, P2PKH, ARC,
//  and other primitives for building and broadcasting real transactions.
//
//  Install:  npm install @bsv/sdk
//
//  Below is a documented walkthrough of how to use @bsv/sdk with TSOP
//  artifacts. The code is written as a reference — to run it, install @bsv/sdk
//  and uncomment the import.
//
// #############################################################################

// @bsv/sdk (https://github.com/bsv-blockchain/ts-sdk) is an ESM-only package.
// Now that the monorepo uses "type": "module", we can import directly:
import { PrivateKey, Transaction, P2PKH, ARC, Hash, LockingScript, UnlockingScript } from '@bsv/sdk';

/**
 * Production-grade @bsv/sdk integration.
 *
 * This function demonstrates how to use the official BSV TypeScript SDK
 * (https://github.com/bsv-blockchain/ts-sdk) alongside TSOP-compiled
 * artifacts for real transaction construction.
 */
async function advancedBsvSdkIntegration() {
  console.log('\n' + '='.repeat(72));
  console.log('  Advanced: @bsv/sdk Integration');
  console.log('='.repeat(72));

  // ---- Step 1: Compile a contract ----
  const artifact = compileContract('examples/p2pkh/P2PKH.tsop.ts');

  // ---- Step 2: Create keys using @bsv/sdk ----
  const privKey = PrivateKey.fromRandom();
  const pubKey = privKey.toPublicKey();
  const pubKeyHex = pubKey.encode(true, 'hex') as string;
  const pubKeyHash = Hash.ripemd160(Hash.sha256(pubKey.encode(true) as number[]));
  console.log('\n@bsv/sdk key creation:');
  console.log('  privKey:', typeof privKey);
  console.log('  pubKeyHex:', pubKeyHex.slice(0, 20) + '...');
  console.log('  pubKeyHash:', pubKeyHash.length, 'bytes');

  // ---- Step 3: Build the locking script from the TSOP artifact ----
  const dummyPubKeyHash = 'ab'.repeat(20);
  const contract = new TSOPContract(artifact, [dummyPubKeyHash]);
  const lockingScriptHex = contract.getLockingScript();
  console.log('Locking script:', lockingScriptHex.slice(0, 40) + '...');
  console.log('Locking script length:', lockingScriptHex.length / 2, 'bytes');

  // ---- Step 4: Deploy using @bsv/sdk Transaction ----
  //
  // In production, you would have a funded UTXO. Here we show the API shape
  // using actual @bsv/sdk types. The Transaction class supports:
  //   - addInput() with sourceTransaction and unlockingScriptTemplate
  //   - addOutput() with lockingScript and satoshis
  //   - fee() to calculate and add change
  //   - sign() to sign all inputs
  //   - broadcast() to send to the network via ARC
  //
  // Example (requires a funded sourceTransaction):
  //
  //   const lockingScript = LockingScript.fromHex(lockingScriptHex);
  //   const deployTx = new Transaction();
  //   deployTx.addInput({
  //     sourceTransaction: fundingTx,
  //     sourceOutputIndex: 0,
  //     unlockingScriptTemplate: new P2PKH().unlock(privKey),
  //   });
  //   deployTx.addOutput({
  //     lockingScript: lockingScript,
  //     satoshis: 10_000,
  //   });
  //   deployTx.addOutput({
  //     lockingScript: new P2PKH().lock(privKey.toAddress()),
  //     change: true,
  //   });
  //   await deployTx.fee();
  //   await deployTx.sign();
  //   const broadcaster = new ARC('https://arc.taal.com');
  //   const deployResult = await deployTx.broadcast(broadcaster);

  // Demonstrate that we can construct @bsv/sdk objects:
  const bsvLockingScript = LockingScript.fromHex(lockingScriptHex);
  console.log('\nDeploy TX pattern:');
  console.log('  LockingScript from @bsv/sdk:', bsvLockingScript.toHex().slice(0, 40) + '...');
  console.log('  Input:  funding UTXO with P2PKH().unlock(privKey)');
  console.log('  Output: TSOP lockingScript (' + lockingScriptHex.length / 2 + ' bytes) + 10,000 sats');
  console.log('  Output: P2PKH change');

  // ---- Step 5: Spend/unlock the contract ----
  //
  // For TSOP contracts, the unlocking script is built from the ABI:
  //   1. Push method parameters in reverse order (so first param ends up on top)
  //   2. For multi-method contracts, push the method selector index
  //
  // The contract.buildUnlockingScript() method handles this encoding.
  //
  // Example (requires a deployed sourceTransaction):
  //
  //   const spendTx = new Transaction();
  //   spendTx.addInput({
  //     sourceTransaction: deployTx,
  //     sourceOutputIndex: 0,
  //     unlockingScript: UnlockingScript.fromHex(
  //       contract.buildUnlockingScript('unlock', [sigHex, pubKeyHex])
  //     ),
  //   });
  //   spendTx.addOutput({
  //     lockingScript: new P2PKH().lock(recipientAddress),
  //     satoshis: 9_500,
  //   });
  //   await spendTx.fee();
  //   await spendTx.sign();
  //   const spendResult = await spendTx.broadcast(broadcaster);

  console.log('\nSpend TX pattern:');
  console.log('  Input:  TSOP UTXO with unlockingScript from buildUnlockingScript()');
  console.log('  Output: P2PKH to recipient');

  // ---- Step 6: OP_PUSH_TX for stateful contracts ----
  console.log('\nOP_PUSH_TX with @bsv/sdk:');
  console.log('  1. Build the spending Transaction with all inputs/outputs');
  console.log('  2. Extract the BIP-143 sighash preimage for the contract input');
  console.log('  3. Compute the OP_PUSH_TX signature (privkey=1, pubkey=G):');
  console.log('     const Gx = BigInt("0x79BE667E...16F81798")');
  console.log('     const sighash = Hash.hash256(preimage)');
  console.log('     const s = (BigInt("0x" + toHex(sighash)) + Gx) % n');
  console.log('  4. DER-encode (Gx, s) with sighash type 0x41');
  console.log('  5. Push <opPushTxSig> <preimage> in the unlocking script');
  console.log('  6. The locking script verifies via OP_CHECKSIG with pubkey G');

  // The @bsv/sdk classes used above (PrivateKey, Transaction, P2PKH, ARC,
  // LockingScript, UnlockingScript, Hash) are imported at the top of this file.
  // With "type": "module" in package.json, the ESM-only @bsv/sdk works directly.

  console.log(`
@bsv/sdk reference: https://github.com/bsv-blockchain/ts-sdk
OP_PUSH_TX reference: https://wiki.bitcoinsv.io/index.php/OP_PUSH_TX
`);
}

// #############################################################################
//
//  Main entry point -- run all examples
//
// #############################################################################

async function main() {
  console.log('TSOP SDK Usage Examples');
  console.log('======================');
  console.log('Running all 8 contract examples...\n');

  try {
    await exampleP2PKH();
    await exampleEscrow();
    await exampleCounter();
    await exampleFungibleToken();
    await exampleNFT();
    await exampleAuction();
    await exampleOraclePriceFeed();
    await exampleCovenantVault();

    // Educational sections
    opPushTxExplainer();
    advancedBsvSdkIntegration();

    console.log('\n' + '='.repeat(72));
    console.log('  All examples completed successfully.');
    console.log('='.repeat(72));
  } catch (error) {
    console.error('\nExample failed:', error);
    process.exit(1);
  }
}

main();
