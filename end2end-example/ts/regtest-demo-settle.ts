/**
 * PriceBet Regtest Interactive Demo
 *
 * Walks through the complete lifecycle of a Rúnar smart contract on a real
 * BSV regtest node: key generation, funding, compilation, deployment, and
 * spending via the SETTLE or CANCEL path.
 *
 * The user chooses the oracle price (or cancels), determining the winner:
 *   price > strike  → Alice wins (settle path)
 *   price <= strike → Bob wins (settle path)
 *   -1              → Both cancel (cancel path, refund split)
 *
 * Prerequisites:
 *   - BSV regtest node running on localhost:18332
 *   - Node wallet loaded and funded (mine some blocks first)
 *   - pnpm install && pnpm run build
 *
 * Run:
 *   npx tsx end2end-example/ts/regtest-demo-settle.ts
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
import { randomBytes, createHash, generatePrimeSync } from 'node:crypto';
import { execSync } from 'node:child_process';
import { compile } from '../../packages/runar-compiler/src/index.js';
import { LocalSigner } from '../../packages/runar-sdk/src/signers/local.js';

// ═══════════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════════

const RPC_URL  = process.env.RPC_URL  ?? 'http://localhost:18332';
const RPC_USER = process.env.RPC_USER ?? 'bitcoin';
const RPC_PASS = process.env.RPC_PASS ?? 'bitcoin';

const STRIKE = 50000n;

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
  magenta: '\x1b[35m',
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

function askForPrice(): Promise<bigint> {
  return new Promise(resolve => {
    const ask = (): void => {
      rl.question(
        `\n  ${C.yellow}Enter the price between 0 and 100000, or -1 to cancel the bet: ${C.reset}`,
        (answer) => {
          const n = Number(answer.trim());
          if (!Number.isInteger(n) || n < -1 || n > 100000) {
            console.log(`  ${C.red}Invalid input. Enter a whole number between 0 and 100000, or -1.${C.reset}`);
            ask();
            return;
          }
          resolve(BigInt(n));
        },
      );
    };
    ask();
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Crypto helpers (Node.js native)
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
  prevTxid: string;
  prevVout: number;
  scriptSig: string;
  sequence: number;
}

interface TxOutput {
  satoshis: number;
  script: string;
}

function buildRawTx(inputs: TxInput[], outputs: TxOutput[]): string {
  let tx = '';

  tx += toLittleEndian32(1);
  tx += encodeVarInt(inputs.length);

  for (const inp of inputs) {
    tx += reverseHex(inp.prevTxid);
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

  tx += toLittleEndian32(0);

  return tx;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Script encoding (for building unlocking scripts)
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
  return toBase58Check(pubKeyHash, 0x6f);
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
// UTXO lookup
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
// Rabin signature oracle
// ═══════════════════════════════════════════════════════════════════════════════

interface RabinKeyPair {
  p: bigint;
  q: bigint;
  n: bigint;
}

interface RabinSignature {
  sig: bigint;
  padding: bigint;
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

function extGcd(a: bigint, b: bigint): { g: bigint; x: bigint; y: bigint } {
  if (a === 0n) return { g: b, x: 0n, y: 1n };
  const { g, x, y } = extGcd(b % a, a);
  return { g, x: y - (b / a) * x, y: x };
}

function crt(sp: bigint, sq: bigint, p: bigint, q: bigint): bigint {
  const n = p * q;
  const { x: xp } = extGcd(p, q);
  const { x: xq } = extGcd(q, p);
  return (((sp * xq % n) * q % n + (sq * xp % n) * p % n) % n + n) % n;
}

function generateRabinKeyPair(): RabinKeyPair {
  let p: bigint;
  let q: bigint;

  do {
    p = BigInt('0x' + Buffer.from(generatePrimeSync(130)).toString('hex'));
  } while (p % 4n !== 3n);

  do {
    q = BigInt('0x' + Buffer.from(generatePrimeSync(130)).toString('hex'));
  } while (q % 4n !== 3n || q === p);

  return { p, q, n: p * q };
}

function num2binLE(value: bigint, byteLen: number): Buffer {
  const buf = Buffer.alloc(byteLen, 0);
  let v = value;
  for (let i = 0; i < byteLen && v > 0n; i++) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

function bufferToUnsignedLE(buf: Buffer): bigint {
  let result = 0n;
  for (let i = 0; i < buf.length; i++) {
    result += BigInt(buf[i]!) << BigInt(i * 8);
  }
  return result;
}

function isQR(x: bigint, p: bigint): boolean {
  if (x % p === 0n) return true;
  return modPow(x % p, (p - 1n) / 2n, p) === 1n;
}

function rabinSign(msgBytes: Buffer, keypair: RabinKeyPair): RabinSignature {
  const { p, q, n } = keypair;
  const h = sha256(msgBytes);
  const hInt = bufferToUnsignedLE(h);

  for (let pad = 0n; pad < 1000n; pad++) {
    const target = ((hInt - pad) % n + n) % n;

    if (!isQR(target, p) || !isQR(target, q)) continue;

    const sp = modPow(target % p, (p + 1n) / 4n, p);
    const sq = modPow(target % q, (q + 1n) / 4n, q);
    const sig = crt(sp, sq, p, q);

    if ((sig * sig + pad) % n === hInt) {
      return { sig, padding: pad };
    }

    const sigAlt = n - sig;
    if ((sigAlt * sigAlt + pad) % n === hInt) {
      return { sig: sigAlt, padding: pad };
    }
  }

  throw new Error('Failed to generate Rabin signature (no QR found within 1000 padding values)');
}

function findValidPriceNear(
  target: bigint,
  minPrice: bigint,
  maxPrice: bigint,
  keypair: RabinKeyPair,
): { price: bigint; rabinSig: RabinSignature } {
  for (let offset = 0n; offset <= 10000n; offset++) {
    const candidates = offset === 0n ? [target] : [target + offset, target - offset];

    for (const price of candidates) {
      if (price < minPrice || price > maxPrice) continue;

      const msgBytes = num2binLE(price, 8);
      const h = sha256(msgBytes);
      const lastByte = h[h.length - 1]!;

      if (lastByte === 0 || lastByte >= 0x80) continue;

      try {
        const rabinSig = rabinSign(msgBytes, keypair);
        return { price, rabinSig };
      } catch {
        continue;
      }
    }
  }

  throw new Error('Could not find a valid price in range');
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main demo
// ═══════════════════════════════════════════════════════════════════════════════

async function main(): Promise<void> {
  console.log(`\n${C.cyan}${C.bold}`);
  console.log('  ┌────────────────────────────────────────────────────────────────┐');
  console.log('  │            PriceBet Regtest Interactive Demo                   │');
  console.log('  │                                                                │');
  console.log('  │  Deploys a Rúnar smart contract to a real BSV regtest node     │');
  console.log('  │  and spends it via settle or cancel based on your chosen       │');
  console.log('  │  price. Price > strike → Alice wins, else → Bob wins.          │');
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
    if (e instanceof Error) console.log(`  ${C.dim}${e.message}${C.reset}`);
    process.exit(1);
  }

  await pause();

  // ─────────────────────────────────────────────────────────────────────────
  // Step 1: Generate Key Pairs (ECDSA + Rabin Oracle)
  // ─────────────────────────────────────────────────────────────────────────

  banner(1, 'Generate Key Pairs');
  console.log('  Creating secp256k1 key pairs for Alice and Bob,');
  console.log('  plus a Rabin keypair for the price oracle.\n');

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

  heading('Alice (ECDSA)');
  label('Public key', alicePubKey);
  label('Address (regtest)', aliceAddr);

  heading('Bob (ECDSA)');
  label('Public key', bobPubKey);
  label('Address (regtest)', bobAddr);

  heading('Oracle (Rabin)');
  console.log('  Generating two 130-bit primes (p ≡ q ≡ 3 mod 4)...');
  const oracleKeys = generateRabinKeyPair();
  label('p', oracleKeys.p.toString().slice(0, 30) + '...');
  label('q', oracleKeys.q.toString().slice(0, 30) + '...');
  label('n = p × q', oracleKeys.n.toString().slice(0, 40) + '...');
  label('n bit length', `~${oracleKeys.n.toString(2).length} bits`);
  ok('Oracle Rabin keypair generated');

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
  // Step 3: Compile Contract
  // ─────────────────────────────────────────────────────────────────────────

  banner(3, 'Compile Contract');
  console.log(`  Strike price: ${STRIKE}\n`);

  const __dirname = dirname(fileURLToPath(import.meta.url));
  const source = readFileSync(join(__dirname, 'PriceBet.runar.ts'), 'utf8');

  const result = compile(source, {
    fileName: 'PriceBet.runar.ts',
    constructorArgs: {
      alicePubKey:  alicePubKey,
      bobPubKey:    bobPubKey,
      oraclePubKey: oracleKeys.n,
      strikePrice:  STRIKE,
    },
  });

  if (!result.success || !result.scriptHex) {
    console.log(`\n  ${C.red}Compilation failed:${C.reset}`);
    for (const d of result.diagnostics) console.log(`    [${d.severity}] ${d.message}`);
    process.exit(1);
  }

  const lockingScript = result.scriptHex;

  ok('Compilation successful');
  label('Script size', `${lockingScript.length / 2} bytes`);
  label('Methods', 'settle (index 0), cancel (index 1)');

  await pause();

  // ─────────────────────────────────────────────────────────────────────────
  // Step 4: Deploy Contract (Funding TX)
  // ─────────────────────────────────────────────────────────────────────────

  banner(4, 'Deploy Contract (Funding TX)');
  console.log('  Building a TX that creates the PriceBet UTXO on-chain.');
  console.log('  Alice and Bob each contribute 1 BSV — the full 2 BSV goes to the bet.\n');

  const CONTRACT_SATS = 200_000_000;

  heading('Transaction layout');
  label('Input  0', `Alice UTXO (${aliceUtxo.satoshis} sats)`);
  label('Input  1', `Bob UTXO (${bobUtxo.satoshis} sats)`);
  label('Output 0', `PriceBet locking script (${CONTRACT_SATS} sats)`);
  label('Fee', '0 sats');

  const fundOutputs: TxOutput[] = [
    { satoshis: CONTRACT_SATS, script: lockingScript },
  ];

  const unsignedFundTx = buildRawTx(
    [
      { prevTxid: aliceUtxo.txid, prevVout: aliceUtxo.vout, scriptSig: '', sequence: 0xffffffff },
      { prevTxid: bobUtxo.txid,   prevVout: bobUtxo.vout,   scriptSig: '', sequence: 0xffffffff },
    ],
    fundOutputs,
  );

  heading('Signing (BIP-143 / SIGHASH_ALL|FORKID)');

  const aliceFundSig = await aliceSigner.sign(
    unsignedFundTx, 0, aliceUtxo.script, aliceUtxo.satoshis,
  );
  ok(`Alice signed input 0 (${aliceFundSig.length / 2} bytes)`);

  const bobFundSig = await bobSigner.sign(
    unsignedFundTx, 1, bobUtxo.script, bobUtxo.satoshis,
  );
  ok(`Bob signed input 1 (${bobFundSig.length / 2} bytes)`);

  const aliceUnlock = encodePushDataHex(aliceFundSig) + encodePushDataHex(alicePubKey);
  const bobUnlock   = encodePushDataHex(bobFundSig)   + encodePushDataHex(bobPubKey);

  const signedFundTx = buildRawTx(
    [
      { prevTxid: aliceUtxo.txid, prevVout: aliceUtxo.vout, scriptSig: aliceUnlock, sequence: 0xffffffff },
      { prevTxid: bobUtxo.txid,   prevVout: bobUtxo.vout,   scriptSig: bobUnlock,   sequence: 0xffffffff },
    ],
    fundOutputs,
  );

  heading('Broadcasting');
  label('Signed TX size', `${signedFundTx.length / 2} bytes`);

  const contractTxid = await rpc('sendrawtransaction', [signedFundTx]) as string;
  ok(`Funding TX accepted: ${contractTxid}`);

  await mine(1);
  ok('Block mined — contract UTXO confirmed');

  const contractTxInfo = await rpc('getrawtransaction', [contractTxid, true]) as {
    confirmations: number;
  };
  label('Confirmations', String(contractTxInfo.confirmations));
  label('Contract UTXO', `${contractTxid}:0  ${CONTRACT_SATS} sats`);

  await pause();

  // ─────────────────────────────────────────────────────────────────────────
  // Step 5: Choose Price (Oracle Signs)
  // ─────────────────────────────────────────────────────────────────────────

  banner(5, 'Choose Price (or Cancel)');
  console.log(`  The contract is now live on-chain. Strike price: ${STRIKE}`);
  console.log('  If price > strike → Alice wins via settle.');
  console.log('  If price <= strike → Bob wins via settle.');
  console.log('  If -1 → both parties cancel the bet.\n');

  const userPrice = await askForPrice();
  const isCancelPath = userPrice === -1n;

  let price = 0n;
  let oracleRabinSig: RabinSignature | null = null;

  if (!isCancelPath) {
    heading('Oracle signs the price');
    const isAliceWins = userPrice > STRIKE;
    const minPrice = isAliceWins ? STRIKE + 1n : 1n;
    const maxPrice = isAliceWins ? 100000n : STRIKE;
    console.log(`  Finding a valid price near ${userPrice} (${isAliceWins ? 'above' : 'at or below'} strike)...\n`);

    const found = findValidPriceNear(userPrice, minPrice, maxPrice, oracleKeys);
    price = found.price;
    oracleRabinSig = found.rabinSig;

    ok(`Found valid price: ${price}`);
    label('Rabin sig', oracleRabinSig.sig.toString().slice(0, 40) + '...');
    label('Rabin padding', oracleRabinSig.padding.toString());

    heading('Verifying Rabin signature offline');
    const priceMsgBytes = num2binLE(price, 8);
    const priceHash     = sha256(priceMsgBytes);
    const hashInt       = bufferToUnsignedLE(priceHash);
    const computed      = (oracleRabinSig.sig * oracleRabinSig.sig + oracleRabinSig.padding) % oracleKeys.n;
    label('num2bin(price, 8)', bytesToHex(priceMsgBytes));
    label('SHA256(msg)', bytesToHex(priceHash));
    label('(sig² + pad) mod n', computed === hashInt ? `${C.green}matches hash${C.reset}` : `${C.red}MISMATCH${C.reset}`);
    label('Hash byte[31]', `0x${priceHash[31]!.toString(16).padStart(2, '0')} (must be 0x01–0x7f)`);
  } else {
    ok('Cancel path selected — no oracle signature needed');
  }

  const aliceWins = !isCancelPath && price > STRIKE;

  await pause();

  // ─────────────────────────────────────────────────────────────────────────
  // Step 6: Spend Contract
  // ─────────────────────────────────────────────────────────────────────────

  let spendOutputs: TxOutput[];

  if (isCancelPath) {
    banner(6, 'Spend Contract (Cancel TX — Mutual Refund)');
    console.log('  Both parties agreed to cancel. Refunding 50/50.\n');
    const halfSats = CONTRACT_SATS / 2;
    spendOutputs = [
      { satoshis: halfSats, script: aliceP2PKH },
      { satoshis: halfSats, script: bobP2PKH },
    ];
    heading('Transaction layout');
    label('Input  0', `PriceBet UTXO (${CONTRACT_SATS} sats)`);
    label('Output 0', `Alice P2PKH (${halfSats} sats)`);
    label('Output 1', `Bob P2PKH (${halfSats} sats)`);
    label('Fee', '0 sats');
  } else if (aliceWins) {
    banner(6, 'Spend Contract (Settle TX — Alice Wins)');
    console.log(`  Oracle price ${price} > strike ${STRIKE}, so Alice wins!\n`);
    spendOutputs = [{ satoshis: CONTRACT_SATS, script: aliceP2PKH }];
    heading('Transaction layout');
    label('Input  0', `PriceBet UTXO (${CONTRACT_SATS} sats)`);
    label('Output 0', `Alice P2PKH (${CONTRACT_SATS} sats)`);
    label('Fee', '0 sats');
  } else {
    banner(6, 'Spend Contract (Settle TX — Bob Wins)');
    console.log(`  Oracle price ${price} <= strike ${STRIKE}, so Bob wins!\n`);
    spendOutputs = [{ satoshis: CONTRACT_SATS, script: bobP2PKH }];
    heading('Transaction layout');
    label('Input  0', `PriceBet UTXO (${CONTRACT_SATS} sats)`);
    label('Output 0', `Bob P2PKH (${CONTRACT_SATS} sats)`);
    label('Fee', '0 sats');
  }

  const unsignedSpendTx = buildRawTx(
    [{ prevTxid: contractTxid, prevVout: 0, scriptSig: '', sequence: 0xffffffff }],
    spendOutputs,
  );

  let unlockScript: string;

  if (isCancelPath) {
    heading('Signing (both Alice and Bob sign the cancel TX)');
    console.log(`  ${C.dim}subscript = PriceBet locking script (${lockingScript.length / 2} bytes)${C.reset}`);
    console.log(`  ${C.dim}value     = ${CONTRACT_SATS} satoshis${C.reset}\n`);

    const aliceCancelSig = await aliceSigner.sign(unsignedSpendTx, 0, lockingScript, CONTRACT_SATS);
    ok(`Alice signed (${aliceCancelSig.length / 2} bytes DER+hashtype)`);

    const bobCancelSig = await bobSigner.sign(unsignedSpendTx, 0, lockingScript, CONTRACT_SATS);
    ok(`Bob signed (${bobCancelSig.length / 2} bytes DER+hashtype)`);

    heading('Building unlocking script');
    unlockScript =
      encodePushDataHex(aliceCancelSig) +
      encodePushDataHex(bobCancelSig) +
      encodeScriptNumber(1n);

    heading('Script execution trace (cancel path)');
    console.log('    Stack after scriptSig:       [ aliceSig, bobSig, 1 ]');
    console.log('    OP_DUP OP_1 OP_NUMEQUAL:     [ ..., true ]  (1 == 1)');
    console.log('    OP_IF (cancel):               enters cancel branch');
    console.log(`    checkSig(aliceSig, alicePK):  ECDSA verify  ${C.green}✓${C.reset}`);
    console.log(`    checkSig(bobSig, bobPK):      ECDSA verify  ${C.green}✓${C.reset}`);
  } else {
    const winner = aliceWins ? 'Alice' : 'Bob';
    heading(`Signing (${winner} signs the settle TX)`);
    console.log(`  ${C.dim}subscript = PriceBet locking script (${lockingScript.length / 2} bytes)${C.reset}`);
    console.log(`  ${C.dim}value     = ${CONTRACT_SATS} satoshis${C.reset}\n`);

    const dummySig = '00';

    if (aliceWins) {
      const aliceSettleSig = await aliceSigner.sign(unsignedSpendTx, 0, lockingScript, CONTRACT_SATS);
      ok(`Alice signed (${aliceSettleSig.length / 2} bytes DER+hashtype)`);

      heading('Building unlocking script');
      unlockScript =
        encodeScriptNumber(price) +
        encodeScriptNumber(oracleRabinSig!.sig) +
        encodeScriptNumber(oracleRabinSig!.padding) +
        encodePushDataHex(aliceSettleSig) +
        encodePushDataHex(dummySig) +
        encodeScriptNumber(0n);
    } else {
      const bobSettleSig = await bobSigner.sign(unsignedSpendTx, 0, lockingScript, CONTRACT_SATS);
      ok(`Bob signed (${bobSettleSig.length / 2} bytes DER+hashtype)`);

      heading('Building unlocking script');
      unlockScript =
        encodeScriptNumber(price) +
        encodeScriptNumber(oracleRabinSig!.sig) +
        encodeScriptNumber(oracleRabinSig!.padding) +
        encodePushDataHex(dummySig) +
        encodePushDataHex(bobSettleSig) +
        encodeScriptNumber(0n);
    }

    heading('Script execution trace (settle path)');
    console.log('    Stack after scriptSig:       [ price, rabinSig, padding, aliceSig, bobSig, 0 ]');
    console.log('    OP_DUP OP_0 OP_NUMEQUAL:     [ ..., true ]  (0 == 0)');
    console.log('    OP_IF (settle):               enters settle branch');
    console.log('    OP_DROP:                      [ price, rabinSig, padding, aliceSig, bobSig ]');
    console.log('    num2bin(price, 8):            msg on stack');
    console.log(`    verifyRabinSig:              sig² + pad mod n == SHA256(msg)  ${C.green}✓${C.reset}`);
    console.log(`    price > 0:                    ${price} > 0  ${C.green}✓${C.reset}`);
    if (aliceWins) {
      console.log(`    price > strike:               ${price} > ${STRIKE}  ${C.green}✓${C.reset}`);
      console.log(`    checkSig(aliceSig, alicePK):  ECDSA verify  ${C.green}✓${C.reset}`);
    } else {
      console.log(`    price <= strike:              ${price} <= ${STRIKE}  ${C.green}✓${C.reset}`);
      console.log(`    checkSig(bobSig, bobPK):      ECDSA verify  ${C.green}✓${C.reset}`);
    }
  }

  label('Unlocking script', `${unlockScript.length / 2} bytes`);

  const signedSpendTx = buildRawTx(
    [{ prevTxid: contractTxid, prevVout: 0, scriptSig: unlockScript, sequence: 0xffffffff }],
    spendOutputs,
  );

  heading('Broadcasting');
  label('Signed TX size', `${signedSpendTx.length / 2} bytes`);

  const spendTxid = await rpc('sendrawtransaction', [signedSpendTx]) as string;
  ok(`${isCancelPath ? 'Cancel' : 'Settle'} TX accepted: ${spendTxid}`);

  await mine(1);
  const winnerLabel = isCancelPath ? 'Refund' : (aliceWins ? 'Alice payout' : 'Bob payout');
  ok(`Block mined — ${winnerLabel} confirmed`);

  const spendTxInfo = await rpc('getrawtransaction', [spendTxid, true]) as {
    confirmations: number;
  };
  label('Confirmations', String(spendTxInfo.confirmations));

  await pause();

  // ─────────────────────────────────────────────────────────────────────────
  // Step 6: Verify On-Chain State
  // ─────────────────────────────────────────────────────────────────────────

  banner(7, 'Verify On-Chain State');

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

  if (isCancelPath) {
    console.log(`    ${C.yellow}Cancel TX${C.reset}   (Mutual cancel → 50/50 refund)`);
  } else if (aliceWins) {
    console.log(`    ${C.green}Settle TX${C.reset}   (Oracle: price=${price} > strike=${STRIKE} → Alice wins!)`);
  } else {
    console.log(`    ${C.green}Settle TX${C.reset}   (Oracle: price=${price} <= strike=${STRIKE} → Bob wins!)`);
  }

  console.log('      txid: ' + spendTxid);

  const verifyTx = await rpc('getrawtransaction', [spendTxid, true]) as {
    vout: Array<{ value: number; n: number; scriptPubKey: { hex: string } }>;
  };

  for (const v of verifyTx.vout) {
    const who = v.scriptPubKey.hex === aliceP2PKH ? 'Alice' : v.scriptPubKey.hex === bobP2PKH ? 'Bob' : 'Unknown';
    const sats = Math.round(v.value * 1e8);
    console.log(`      output ${v.n}: ${who.padEnd(6)} P2PKH            ${sats} sats`);
  }

  const outcomeMsg = isCancelPath
    ? 'Cancel path: Both ECDSA signatures verified. Bet refunded 50/50.'
    : aliceWins
      ? `Settle path: Rabin oracle signature + Alice's ECDSA signature.`
      : `Settle path: Rabin oracle signature + Bob's ECDSA signature.`;
  const potMsg = isCancelPath
    ? 'Each party received their 1 BSV back.'
    : aliceWins
      ? `Alice won the full ${CONTRACT_SATS / 1e8} BSV pot!`
      : `Bob won the full ${CONTRACT_SATS / 1e8} BSV pot!`;

  console.log();
  console.log(`  ${C.green}${C.bold}${'─'.repeat(62)}${C.reset}`);
  console.log(`  ${C.green}${C.bold}  Demo complete!${C.reset}`);
  console.log(`  ${C.green}${C.bold}  PriceBet was deployed and ${isCancelPath ? 'cancelled' : 'settled'} on a real BSV regtest node.${C.reset}`);
  console.log(`  ${C.green}${C.bold}  ${outcomeMsg}${C.reset}`);
  console.log(`  ${C.green}${C.bold}  ${potMsg}${C.reset}`);
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
