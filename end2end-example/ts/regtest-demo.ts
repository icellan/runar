/**
 * PriceBet Regtest Interactive Demo
 *
 * Walks through the complete lifecycle of a Rúnar smart contract on a real
 * BSV regtest node: key generation, funding, compilation, deployment, and
 * spending (cancel path with 2-of-2 ECDSA signatures).
 *
 * Prerequisites:
 *   - BSV regtest node running on localhost:18332
 *   - Node wallet loaded and funded (mine some blocks first)
 *   - pnpm install && pnpm run build
 *
 * Run:
 *   npx tsx end2end-example/ts/regtest-demo.ts
 *
 * Environment variables:
 *   RPC_URL   - JSON-RPC endpoint (default: http://localhost:18332)
 *   RPC_USER  - RPC username (default: rpc)
 *   RPC_PASS  - RPC password (default: rpc)
 */

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { randomBytes, createHash } from 'node:crypto';
import { execSync } from 'node:child_process';
import { compile } from '../../packages/runar-compiler/src/index.js';
import { LocalSigner } from '../../packages/runar-sdk/src/signers/local.js';

// ═══════════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════════

const RPC_URL  = process.env.RPC_URL  ?? 'http://localhost:18332';
const RPC_USER = process.env.RPC_USER ?? 'bitcoin';
const RPC_PASS = process.env.RPC_PASS ?? 'bitcoin';

// ═══════════════════════════════════════════════════════════════════════════════
// ANSI colors
// ═══════════════════════════════════════════════════════════════════════════════

const C = {
  reset:   '\x1b[0m',
  bold:    '\x1b[1m',
  dim:     '\x1b[2m',
  cyan:    '\x1b[36m',
  green:   '\x1b[32m',
  yellow:  '\x1b[33m',
  red:     '\x1b[31m',
};

// ═══════════════════════════════════════════════════════════════════════════════
// Display helpers
// ═══════════════════════════════════════════════════════════════════════════════

function banner(step: number, title: string): void {
  console.log();
  console.log(`${C.cyan}${'═'.repeat(72)}${C.reset}`);
  console.log(`${C.cyan}${C.bold}  Step ${step}: ${title}${C.reset}`);
  console.log(`${C.cyan}${'═'.repeat(72)}${C.reset}`);
  console.log();
}

function label(name: string, value: string): void {
  console.log(`  ${C.dim}${name.padEnd(22)}${C.reset} ${value}`);
}

function ok(msg: string): void {
  console.log(`  ${C.green}✓${C.reset} ${msg}`);
}

function heading(msg: string): void {
  console.log(`\n  ${C.bold}${msg}${C.reset}`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Interactive pause (readline)
// ═══════════════════════════════════════════════════════════════════════════════

const rl = createInterface({ input: process.stdin, output: process.stdout });

function pause(prompt = 'Press Enter to continue...'): Promise<void> {
  return new Promise(resolve => {
    rl.question(`\n  ${C.dim}${prompt}${C.reset}`, () => resolve());
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Crypto helpers (Node.js native — no @bsv/sdk dependency)
// ═══════════════════════════════════════════════════════════════════════════════

function sha256(data: Buffer): Buffer {
  return createHash('sha256').update(data).digest();
}

function hash256(data: Buffer): Buffer {
  return sha256(sha256(data));
}

function hash160(data: Buffer): Buffer {
  return createHash('ripemd160').update(sha256(data)).digest();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Base58Check encoding (for testnet/regtest addresses)
// ═══════════════════════════════════════════════════════════════════════════════

const BASE58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(data: Buffer): string {
  let zeros = 0;
  for (const b of data) {
    if (b === 0) zeros++;
    else break;
  }

  let n = BigInt('0x' + data.toString('hex'));
  let result = '';
  while (n > 0n) {
    result = BASE58_CHARS[Number(n % 58n)] + result;
    n /= 58n;
  }

  return '1'.repeat(zeros) + result;
}

function toBase58Check(payload: Buffer, version: number): string {
  const versioned = Buffer.concat([Buffer.from([version]), payload]);
  const checksum = hash256(versioned).subarray(0, 4);
  return base58Encode(Buffer.concat([versioned, checksum]));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Hex / byte utilities
// ═══════════════════════════════════════════════════════════════════════════════

function hexToBytes(hex: string): Buffer {
  return Buffer.from(hex, 'hex');
}

function bytesToHex(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString('hex');
}

function reverseHex(hex: string): string {
  const pairs: string[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    pairs.push(hex.slice(i, i + 2));
  }
  return pairs.reverse().join('');
}

// ═══════════════════════════════════════════════════════════════════════════════
// Bitcoin wire format helpers
// ═══════════════════════════════════════════════════════════════════════════════

function toLittleEndian32(n: number): string {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(n >>> 0);
  return buf.toString('hex');
}

function toLittleEndian64(n: number): string {
  const lo = n & 0xffffffff;
  const hi = Math.floor(n / 0x100000000) & 0xffffffff;
  return toLittleEndian32(lo) + toLittleEndian32(hi);
}

function encodeVarInt(n: number): string {
  if (n < 0xfd) return n.toString(16).padStart(2, '0');
  if (n <= 0xffff) {
    const buf = Buffer.alloc(2);
    buf.writeUInt16LE(n);
    return 'fd' + buf.toString('hex');
  }
  if (n <= 0xffffffff) return 'fe' + toLittleEndian32(n);
  return 'ff' + toLittleEndian64(n);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Raw transaction builder
// ═══════════════════════════════════════════════════════════════════════════════

interface TxInput {
  prevTxid: string;     // hex, normal byte order
  prevVout: number;
  scriptSig: string;    // hex, empty string for unsigned
  sequence: number;
}

interface TxOutput {
  satoshis: number;
  script: string;       // hex locking script
}

function buildRawTx(inputs: TxInput[], outputs: TxOutput[]): string {
  let tx = '';

  tx += toLittleEndian32(1);                        // version
  tx += encodeVarInt(inputs.length);

  for (const inp of inputs) {
    tx += reverseHex(inp.prevTxid);                 // txid in internal byte order
    tx += toLittleEndian32(inp.prevVout);
    tx += encodeVarInt(inp.scriptSig.length / 2);
    if (inp.scriptSig.length > 0) tx += inp.scriptSig;
    tx += toLittleEndian32(inp.sequence);
  }

  tx += encodeVarInt(outputs.length);

  for (const out of outputs) {
    tx += toLittleEndian64(out.satoshis);
    tx += encodeVarInt(out.script.length / 2);
    tx += out.script;
  }

  tx += toLittleEndian32(0);                        // locktime

  return tx;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Script encoding (for building unlocking scripts)
// Replicated from packages/runar-sdk/src/contract.ts for self-containment.
// ═══════════════════════════════════════════════════════════════════════════════

function encodeScriptNumber(n: bigint): string {
  if (n === 0n) return '00';
  if (n >= 1n && n <= 16n) return (0x50 + Number(n)).toString(16);
  if (n === -1n) return '4f';

  const negative = n < 0n;
  let absVal = negative ? -n : n;
  const bytes: number[] = [];

  while (absVal > 0n) {
    bytes.push(Number(absVal & 0xffn));
    absVal >>= 8n;
  }

  if ((bytes[bytes.length - 1]! & 0x80) !== 0) {
    bytes.push(negative ? 0x80 : 0x00);
  } else if (negative) {
    bytes[bytes.length - 1]! |= 0x80;
  }

  const hex = bytes.map(b => b.toString(16).padStart(2, '0')).join('');
  return encodePushDataHex(hex);
}

function encodePushDataHex(dataHex: string): string {
  if (dataHex.length === 0) return '00';
  const len = dataHex.length / 2;

  if (len <= 75) return len.toString(16).padStart(2, '0') + dataHex;
  if (len <= 0xff) return '4c' + len.toString(16).padStart(2, '0') + dataHex;
  if (len <= 0xffff) {
    const lo = (len & 0xff).toString(16).padStart(2, '0');
    const hi = ((len >> 8) & 0xff).toString(16).padStart(2, '0');
    return '4d' + lo + hi + dataHex;
  }
  const b0 = (len & 0xff).toString(16).padStart(2, '0');
  const b1 = ((len >> 8) & 0xff).toString(16).padStart(2, '0');
  const b2 = ((len >> 16) & 0xff).toString(16).padStart(2, '0');
  const b3 = ((len >> 24) & 0xff).toString(16).padStart(2, '0');
  return '4e' + b0 + b1 + b2 + b3 + dataHex;
}

// ═══════════════════════════════════════════════════════════════════════════════
// P2PKH helpers
// ═══════════════════════════════════════════════════════════════════════════════

function pubKeyHashFrom(compressedPubKeyHex: string): Buffer {
  return hash160(hexToBytes(compressedPubKeyHex));
}

function buildP2PKHScript(pubKeyHash: Buffer): string {
  return '76a914' + bytesToHex(pubKeyHash) + '88ac';
}

function toTestnetAddress(pubKeyHash: Buffer): string {
  return toBase58Check(pubKeyHash, 0x6f);   // 0x6f = testnet/regtest
}

// ═══════════════════════════════════════════════════════════════════════════════
// JSON-RPC helper
// ═══════════════════════════════════════════════════════════════════════════════

let rpcId = 1;

async function rpc(method: string, params: unknown[] = []): Promise<unknown> {
  const body = JSON.stringify({ jsonrpc: '1.0', id: rpcId++, method, params });
  const auth = Buffer.from(`${RPC_USER}:${RPC_PASS}`).toString('base64');

  const res = await fetch(RPC_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Basic ${auth}`,
    },
    body,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`RPC ${method} failed (HTTP ${res.status}): ${text}`);
  }

  const json = await res.json() as { result: unknown; error: { message: string } | null };
  if (json.error) throw new Error(`RPC ${method}: ${json.error.message}`);
  return json.result;
}

async function mine(nBlocks = 1): Promise<void> {
  try {
    await rpc('generate', [nBlocks]);
  } catch {
    const addr = await rpc('getnewaddress') as string;
    await rpc('generatetoaddress', [nBlocks, addr]);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTXO lookup: find the output matching a known P2PKH script in a TX
// ═══════════════════════════════════════════════════════════════════════════════

interface FoundUtxo {
  txid: string;
  vout: number;
  satoshis: number;
  script: string;
}

async function findUtxo(txid: string, expectedScript: string): Promise<FoundUtxo> {
  const tx = await rpc('getrawtransaction', [txid, true]) as {
    vout: Array<{ value: number; n: number; scriptPubKey: { hex: string } }>;
  };

  for (const v of tx.vout) {
    if (v.scriptPubKey.hex === expectedScript) {
      return {
        txid,
        vout: v.n,
        satoshis: Math.round(v.value * 1e8),
        script: v.scriptPubKey.hex,
      };
    }
  }

  throw new Error(`No output matching expected script in TX ${txid}`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main demo
// ═══════════════════════════════════════════════════════════════════════════════

async function main(): Promise<void> {
  console.log(`\n${C.cyan}${C.bold}`);
  console.log('  ┌────────────────────────────────────────────────────────────────┐');
  console.log('  │           PriceBet Regtest Interactive Demo                    │');
  console.log('  │                                                                │');
  console.log('  │  Deploys a Rúnar smart contract to a real BSV regtest node     │');
  console.log('  │  and spends it using the cancel path (2-of-2 ECDSA).          │');
  console.log('  └────────────────────────────────────────────────────────────────┘');
  console.log(`${C.reset}`);

  label('RPC endpoint', RPC_URL);
  label('RPC user', RPC_USER);

  try {
    const info = await rpc('getblockchaininfo') as { chain: string; blocks: number };
    label('Network', info.chain);
    label('Block height', String(info.blocks));

    if (info.chain !== 'regtest') {
      console.log(`\n  ${C.red}Not connected to regtest (chain=${info.chain}). Aborting.${C.reset}`);
      process.exit(1);
    }
    ok('Connected to regtest node');
  } catch (e) {
    console.log(`\n  ${C.red}Cannot connect to BSV regtest node at ${RPC_URL}${C.reset}`);
    console.log(`  ${C.dim}Make sure the node is running and RPC credentials are correct.${C.reset}`);
    console.log(`  ${C.dim}Set RPC_URL, RPC_USER, RPC_PASS environment variables if needed.${C.reset}`);
    if (e instanceof Error) console.log(`  ${C.dim}${e.message}${C.reset}`);
    process.exit(1);
  }

  await pause();

  // ─────────────────────────────────────────────────────────────────────────
  // Step 1: Generate Key Pairs
  // ─────────────────────────────────────────────────────────────────────────

  banner(1, 'Generate Key Pairs');
  console.log('  Creating fresh secp256k1 key pairs for Alice and Bob.');
  console.log('  These will sign real on-chain transactions.\n');

  const alicePrivHex = randomBytes(32).toString('hex');
  const bobPrivHex   = randomBytes(32).toString('hex');

  const aliceSigner = new LocalSigner(alicePrivHex);
  const bobSigner   = new LocalSigner(bobPrivHex);

  const alicePubKey = await aliceSigner.getPublicKey();
  const bobPubKey   = await bobSigner.getPublicKey();

  const alicePKH    = pubKeyHashFrom(alicePubKey);
  const bobPKH      = pubKeyHashFrom(bobPubKey);
  const aliceAddr   = toTestnetAddress(alicePKH);
  const bobAddr     = toTestnetAddress(bobPKH);
  const aliceP2PKH  = buildP2PKHScript(alicePKH);
  const bobP2PKH    = buildP2PKHScript(bobPKH);

  heading('Alice');
  label('Private key', alicePrivHex);
  label('Public key', alicePubKey);
  label('Address (regtest)', aliceAddr);

  heading('Bob');
  label('Private key', bobPrivHex);
  label('Public key', bobPubKey);
  label('Address (regtest)', bobAddr);

  await pause();

  // ─────────────────────────────────────────────────────────────────────────
  // Step 2: Fund Wallets
  // ─────────────────────────────────────────────────────────────────────────

  banner(2, 'Fund Wallets');
  console.log('  Sending 1 BSV to each party from the regtest node wallet.\n');

  const aliceFundTxid = await rpc('sendtoaddress', [aliceAddr, 1.0]) as string;
  ok(`Sent 1 BSV to Alice  txid: ${aliceFundTxid}`);

  const bobFundTxid = await rpc('sendtoaddress', [bobAddr, 1.0]) as string;
  ok(`Sent 1 BSV to Bob    txid: ${bobFundTxid}`);

  heading('Mining a block to confirm');
  await mine(1);
  ok('Block mined');

  heading('Locating UTXOs');
  const aliceUtxo = await findUtxo(aliceFundTxid, aliceP2PKH);
  const bobUtxo   = await findUtxo(bobFundTxid, bobP2PKH);

  label('Alice UTXO', `${aliceUtxo.txid}:${aliceUtxo.vout}  ${aliceUtxo.satoshis} sats`);
  label('Bob UTXO',   `${bobUtxo.txid}:${bobUtxo.vout}  ${bobUtxo.satoshis} sats`);

  await pause();

  // ─────────────────────────────────────────────────────────────────────────
  // Step 3: Compile the PriceBet Contract
  // ─────────────────────────────────────────────────────────────────────────

  banner(3, 'Compile PriceBet Contract');
  console.log('  Compiling with real public keys baked into the locking script.');
  console.log('  Oracle key and strike price are arbitrary (we use the cancel path).\n');

  const __dirname = dirname(fileURLToPath(import.meta.url));
  const source = readFileSync(join(__dirname, 'PriceBet.runar.ts'), 'utf8');

  const ORACLE_PK = 12345n;
  const STRIKE    = 50000n;

  const result = compile(source, {
    fileName: 'PriceBet.runar.ts',
    constructorArgs: {
      alicePubKey:  alicePubKey,
      bobPubKey:    bobPubKey,
      oraclePubKey: ORACLE_PK,
      strikePrice:  STRIKE,
    },
  });

  if (!result.success || !result.scriptHex) {
    console.log(`\n  ${C.red}Compilation failed:${C.reset}`);
    for (const d of result.diagnostics) console.log(`    [${d.severity}] ${d.message}`);
    process.exit(1);
  }

  const lockingScript = result.scriptHex;
  const scriptAsm     = result.scriptAsm!;

  ok('Compilation successful');
  label('Script size', `${lockingScript.length / 2} bytes`);
  label('Methods', 'settle (index 0), cancel (index 1)');

  heading('ASM preview (first 10 opcodes)');
  const asmParts = scriptAsm.split(' ');
  for (let i = 0; i < Math.min(10, asmParts.length); i++) {
    console.log(`    ${String(i + 1).padStart(3)}: ${asmParts[i]}`);
  }
  if (asmParts.length > 10) console.log(`    ... (${asmParts.length - 10} more)`);

  heading('Locking script hex');
  console.log(`    ${lockingScript}`);

  await pause();

  // ─────────────────────────────────────────────────────────────────────────
  // Step 4: Deploy Contract (Funding TX)
  // ─────────────────────────────────────────────────────────────────────────

  banner(4, 'Deploy Contract (Funding TX)');
  console.log('  Building a TX that creates the PriceBet UTXO on-chain.');
  console.log('  Alice and Bob each contribute 1 BSV — the full 2 BSV goes to the bet.\n');

  const CONTRACT_SATS = 200_000_000;  // 2 BSV (1 BSV from each party)

  heading('Transaction layout');
  label('Input  0', `Alice UTXO (${aliceUtxo.satoshis} sats)`);
  label('Input  1', `Bob UTXO (${bobUtxo.satoshis} sats)`);
  label('Output 0', `PriceBet locking script (${CONTRACT_SATS} sats)`);
  label('Fee', '0 sats');

  const fundOutputs: TxOutput[] = [
    { satoshis: CONTRACT_SATS, script: lockingScript },
  ];

  // Build unsigned TX (empty scriptSigs)
  const unsignedFundTx = buildRawTx(
    [
      { prevTxid: aliceUtxo.txid, prevVout: aliceUtxo.vout, scriptSig: '', sequence: 0xffffffff },
      { prevTxid: bobUtxo.txid,   prevVout: bobUtxo.vout,   scriptSig: '', sequence: 0xffffffff },
    ],
    fundOutputs,
  );

  heading('Signing (BIP-143 / SIGHASH_ALL|FORKID)');

  // Alice signs input 0 (her P2PKH UTXO)
  const aliceFundSig = await aliceSigner.sign(
    unsignedFundTx, 0, aliceUtxo.script, aliceUtxo.satoshis,
  );
  ok(`Alice signed input 0 (${aliceFundSig.length / 2} bytes)`);

  // Bob signs input 1 (his P2PKH UTXO)
  const bobFundSig = await bobSigner.sign(
    unsignedFundTx, 1, bobUtxo.script, bobUtxo.satoshis,
  );
  ok(`Bob signed input 1 (${bobFundSig.length / 2} bytes)`);

  // Build P2PKH unlocking scripts: <sig> <pubkey>
  const aliceUnlock = encodePushDataHex(aliceFundSig) + encodePushDataHex(alicePubKey);
  const bobUnlock   = encodePushDataHex(bobFundSig)   + encodePushDataHex(bobPubKey);

  // Rebuild TX with real scriptSigs
  const signedFundTx = buildRawTx(
    [
      { prevTxid: aliceUtxo.txid, prevVout: aliceUtxo.vout, scriptSig: aliceUnlock, sequence: 0xffffffff },
      { prevTxid: bobUtxo.txid,   prevVout: bobUtxo.vout,   scriptSig: bobUnlock,   sequence: 0xffffffff },
    ],
    fundOutputs,
  );

  heading('Broadcasting');
  label('Signed TX size', `${signedFundTx.length / 2} bytes`);

  heading('Complete transaction hex');
  console.log(`    ${signedFundTx}`);

  const contractTxid = await rpc('sendrawtransaction', [signedFundTx]) as string;
  ok(`Funding TX accepted: ${contractTxid}`);

  await mine(1);
  ok('Block mined — contract UTXO confirmed');

  const contractTxInfo = await rpc('getrawtransaction', [contractTxid, true]) as {
    confirmations: number; size: number;
  };
  label('Confirmations', String(contractTxInfo.confirmations));
  label('Contract UTXO', `${contractTxid}:0  ${CONTRACT_SATS} sats`);

  await pause();

  // ─────────────────────────────────────────────────────────────────────────
  // Step 5: Spend Contract (Cancel TX)
  // ─────────────────────────────────────────────────────────────────────────

  banner(5, 'Spend Contract (Cancel TX)');
  console.log('  Both Alice and Bob agree to cancel. They each sign the spending TX.');
  console.log('  The unlocking script pushes: <aliceSig> <bobSig> <1>');
  console.log('  where 1 is the method selector for cancel().\n');

  const aliceRefund = 100_000_000;  // 1 BSV back to Alice
  const bobRefund   = 100_000_000;  // 1 BSV back to Bob

  heading('Transaction layout');
  label('Input  0', `PriceBet UTXO (${CONTRACT_SATS} sats)`);
  label('Output 0', `Alice P2PKH (${aliceRefund} sats)`);
  label('Output 1', `Bob P2PKH (${bobRefund} sats)`);
  label('Fee', '0 sats');

  const cancelOutputs: TxOutput[] = [
    { satoshis: aliceRefund, script: aliceP2PKH },
    { satoshis: bobRefund,   script: bobP2PKH },
  ];

  // Build unsigned TX (empty scriptSig — BIP-143 doesn't include it)
  const unsignedCancelTx = buildRawTx(
    [{ prevTxid: contractTxid, prevVout: 0, scriptSig: '', sequence: 0xffffffff }],
    cancelOutputs,
  );

  heading('Signing (both parties sign the same sighash for input 0)');
  console.log(`  ${C.dim}subscript = PriceBet locking script (${lockingScript.length / 2} bytes)${C.reset}`);
  console.log(`  ${C.dim}value     = ${CONTRACT_SATS} satoshis${C.reset}\n`);

  const aliceCancelSig = await aliceSigner.sign(
    unsignedCancelTx, 0, lockingScript, CONTRACT_SATS,
  );
  ok(`Alice signed (${aliceCancelSig.length / 2} bytes DER+hashtype)`);

  const bobCancelSig = await bobSigner.sign(
    unsignedCancelTx, 0, lockingScript, CONTRACT_SATS,
  );
  ok(`Bob signed (${bobCancelSig.length / 2} bytes DER+hashtype)`);

  // Build unlocking script: <aliceSig> <bobSig> <1>
  // Parameter order matches cancel(aliceSig, bobSig); selector 1 on top.
  const cancelUnlock =
    encodePushDataHex(aliceCancelSig) +
    encodePushDataHex(bobCancelSig) +
    encodeScriptNumber(1n);           // OP_1 (method selector for cancel)

  label('Unlocking script', `${cancelUnlock.length / 2} bytes`);

  heading('Script execution trace (cancel path)');
  console.log('    Stack after scriptSig:       [ aliceSig, bobSig, 1 ]');
  console.log('    OP_DUP OP_0 OP_NUMEQUAL:     [ ..., false ]  (1 != 0)');
  console.log('    OP_IF → OP_ELSE (cancel):    [ aliceSig, bobSig, 1 ]');
  console.log('    OP_DROP:                      [ aliceSig, bobSig ]');
  console.log('    OP_SWAP:                      [ bobSig, aliceSig ]');
  console.log(`    push <alicePK> CHECKSIGVERIFY [ bobSig ]              ${C.green}✓${C.reset}`);
  console.log(`    push <bobPK>   CHECKSIG       [ true ]               ${C.green}✓${C.reset}`);

  // Rebuild TX with the real unlocking script
  const signedCancelTx = buildRawTx(
    [{ prevTxid: contractTxid, prevVout: 0, scriptSig: cancelUnlock, sequence: 0xffffffff }],
    cancelOutputs,
  );

  heading('Broadcasting');
  label('Signed TX size', `${signedCancelTx.length / 2} bytes`);

  const cancelTxid = await rpc('sendrawtransaction', [signedCancelTx]) as string;
  ok(`Cancel TX accepted: ${cancelTxid}`);

  await mine(1);
  ok('Block mined — refunds confirmed');

  const cancelTxInfo = await rpc('getrawtransaction', [cancelTxid, true]) as {
    confirmations: number; size: number;
  };
  label('Confirmations', String(cancelTxInfo.confirmations));

  await pause();

  // ─────────────────────────────────────────────────────────────────────────
  // Step 6: Verify On-Chain State
  // ─────────────────────────────────────────────────────────────────────────

  banner(6, 'Verify On-Chain State');

  heading('Transaction chain');
  console.log();
  console.log('    Faucet');
  console.log('      ├─ 1 BSV → Alice    txid: ' + aliceFundTxid);
  console.log('      └─ 1 BSV → Bob      txid: ' + bobFundTxid);
  console.log('              ↓');
  console.log(`    ${C.cyan}Funding TX${C.reset}  (Alice + Bob → PriceBet UTXO)`);
  console.log('      txid: ' + contractTxid);
  console.log('      output 0: PriceBet locking script  ' + CONTRACT_SATS + ' sats');
  console.log('              ↓');
  console.log(`    ${C.green}Cancel TX${C.reset}   (PriceBet → Alice + Bob refunds)`);
  console.log('      txid: ' + cancelTxid);

  const verifyTx = await rpc('getrawtransaction', [cancelTxid, true]) as {
    vout: Array<{ value: number; n: number; scriptPubKey: { hex: string } }>;
  };

  for (const v of verifyTx.vout) {
    const who = v.scriptPubKey.hex === aliceP2PKH ? 'Alice' :
                v.scriptPubKey.hex === bobP2PKH   ? 'Bob' : 'Unknown';
    const sats = Math.round(v.value * 1e8);
    console.log(`      output ${v.n}: ${who.padEnd(6)} P2PKH            ${sats} sats`);
  }

  console.log();
  console.log(`  ${C.green}${C.bold}${'─'.repeat(62)}${C.reset}`);
  console.log(`  ${C.green}${C.bold}  Demo complete!${C.reset}`);
  console.log(`  ${C.green}${C.bold}  PriceBet was deployed and spent on a real BSV regtest node.${C.reset}`);
  console.log(`  ${C.green}${C.bold}  Cancel path: 2-of-2 ECDSA signatures verified by Bitcoin Script.${C.reset}`);
  console.log(`  ${C.green}${C.bold}${'─'.repeat(62)}${C.reset}`);
  console.log();

  rl.close();
  try { execSync('afplay /System/Library/Sounds/Submarine.aiff', { stdio: 'ignore' }); } catch {}
}

main().catch(err => {
  console.error(`\n${C.red}Fatal: ${err.message ?? err}${C.reset}`);
  rl.close();
  process.exit(1);
});
