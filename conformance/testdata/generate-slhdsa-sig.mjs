/**
 * Generate the SLH-DSA test signature for conformance/integration tests.
 *
 * Test vector parameters (matching script_execution_test.go):
 *   - Parameter set: SLH_SHA2_128s (n=16)
 *   - Seed: 0x42 || 0x00*47  (48 bytes = 3*n)
 *   - Message: "slh-dsa test vector" (UTF-8)
 *   - Expected public key: 00000000000000000000000000000000b618cb38f7f785488c9768f3a2972baf
 *   - Expected signature size: 7856 bytes
 *
 * Usage: node generate-slhdsa-sig.mjs
 */

import { slhKeygen, slhSign, slhVerify, SLH_SHA2_128s } from '../../packages/runar-testing/dist/crypto/slh-dsa.js';
import { writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const params = SLH_SHA2_128s;

// Seed: 0x42 followed by 47 zero bytes (48 = 3*16)
const seed = new Uint8Array(3 * params.n);
seed[0] = 0x42;

console.log('Generating SLH-DSA keypair with SLH_SHA2_128s...');
const { sk, pk } = slhKeygen(params, seed);

const pkHex = Buffer.from(pk).toString('hex');
console.log(`Public key (${pk.length} bytes): ${pkHex}`);

const expectedPK = '00000000000000000000000000000000b618cb38f7f785488c9768f3a2972baf';
if (pkHex !== expectedPK) {
  console.error(`ERROR: Public key mismatch!`);
  console.error(`  Expected: ${expectedPK}`);
  console.error(`  Got:      ${pkHex}`);
  process.exit(1);
}
console.log('Public key matches expected value.');

// Message: "slh-dsa test vector"
const msg = new TextEncoder().encode('slh-dsa test vector');
const msgHex = Buffer.from(msg).toString('hex');
console.log(`Message (${msg.length} bytes): ${msgHex}`);

console.log('Signing message (this may take a minute)...');
const sig = slhSign(params, msg, sk);
console.log(`Signature size: ${sig.length} bytes`);

if (sig.length !== 7856) {
  console.error(`ERROR: Unexpected signature size! Expected 7856, got ${sig.length}`);
  process.exit(1);
}

// Verify the signature before saving
console.log('Verifying signature...');
const valid = slhVerify(params, msg, sig, pk);
if (!valid) {
  console.error('ERROR: Signature verification failed!');
  process.exit(1);
}
console.log('Signature verified successfully.');

// Write the hex-encoded signature
const sigHex = Buffer.from(sig).toString('hex');
const outPath = join(__dirname, 'slhdsa-test-sig.hex');
writeFileSync(outPath, sigHex + '\n');
console.log(`Wrote signature to ${outPath}`);
console.log(`Signature hex length: ${sigHex.length} characters (${sigHex.length / 2} bytes)`);
