#!/usr/bin/env npx tsx
/**
 * Generate the cross-tier BIP-143 sighash fixture (GAP-003).
 *
 * Audit blocker GAP-003: prove the seven SDKs agree on BIP-143 transaction
 * sighash *preimage* construction across tiers — not just that each agrees
 * with a node. Before this fixture the only cross-tier ECDSA gate was the
 * signed-envelope protocol (`conformance/sdk-envelope/`); BIP-143 deploy/call
 * sighash was tested per-tier in isolation against a regtest node, so a
 * preimage-byte divergence between two tiers that happened to both round-trip
 * a node (e.g. both wrong in the same consensus-irrelevant byte, or one tier
 * never exercising a scenario) could ship green.
 *
 * Design (TypeScript = reference signer):
 *   - TS owns the de-facto golden BIP-143 path (`@bsv/sdk`
 *     `TransactionSignature.format`, the exact code `runar-sdk` LocalSigner /
 *     oppushtx use).
 *   - This generator hand-builds an unsigned raw tx per scenario (NO node
 *     required), computes the full BIP-143 preimage via that same code path,
 *     and signs `sha256d(preimage)` with a fixed test key (priv=1) using
 *     RFC-6979 + low-S — the identical signing convention as
 *     `conformance/sdk-envelope` signing_vectors, so signatures are
 *     byte-reproducible by every tier.
 *   - Each scenario records everything a consumer needs to INDEPENDENTLY
 *     recompute the preimage: { unsignedTxHex, inputIndex, prevScriptHex,
 *     prevValueSats, sighashFlags } plus the expected { preimageHex, sigHex,
 *     pubkeyHex }.
 *
 * Consuming tiers (Go/Rust/Python/Ruby/Zig/Java) load the fixture, recompute
 * the preimage from (unsignedTxHex, inputIndex, prevScriptHex, prevValueSats,
 * sighashFlags), assert byte-equality with `preimageHex` (the core node-free
 * correctness check), and verify `sigHex` against `pubkeyHex` over their own
 * computed sha256d(preimage) digest. Where a regtest node is available the
 * final tx is assembled from `sigHex` and broadcast to prove consensus
 * validity.
 *
 * Run: `cd conformance && npx tsx sdk-bip143/generate-fixtures.ts`
 *   (or with --check to validate the committed fixture without rewriting it.)
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  BigNumber,
  Hash,
  PrivateKey,
  PublicKey,
  Script,
  Signature,
  TransactionSignature,
  Utils,
} from '@bsv/sdk';
import { sign as ecdsaSign, verify as ecdsaVerify } from '@bsv/sdk/primitives/ECDSA';
// The compiler (used only to build the Counter scenario's locking script when
// REGENERATING the fixture) is imported dynamically inside compileCounterScript
// so the build-free `--check` drift guard never pulls in runar-compiler /
// runar-ir-schema/dist (which a lightweight CI lint job does not build).

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '..', '..');

/** SIGHASH_ALL | SIGHASH_FORKID — the default every stateful call uses. */
const SIGHASH_ALL_FORKID = 0x41;

/**
 * R-206: the other sighash modes the compiler accepts.
 *
 * `passes/sighash-directive.ts` parses `@sighash NONE|FORKID`,
 * `SINGLE|FORKID`, `ALL|ANYONECANPAY|FORKID` and so on, and
 * `passes/sighash-validate.ts` carries a table of which BIP-143 digest fields
 * each mode zeroes. All seven SDKs already take a sighash-flag parameter —
 * `ComputeOpPushTxWithSigHash`, `compute_op_push_tx_with_code_sep_sighash`,
 * `sig_hash_type`, `computeOpPushTxWithSigHash`, `OpPushTx.preimage(..., flag)`
 * — so seven independent implementations of the zeroing rules existed and
 * NOTHING compared them. Every scenario in this fixture was 0x41, and every
 * consuming tier asserted `sighashFlags == 0x41` and would have failed loudly
 * rather than skip, which is why the gap stayed invisible instead of rotting
 * quietly.
 *
 * The zeroing rules these exercise (BIP-143, as the validator's table states):
 *   hashPrevouts  zeroed under ANYONECANPAY
 *   hashSequence  zeroed unless the mode is exactly ALL
 *   hashOutputs   zeroed under NONE; under SINGLE it covers ONLY the output at
 *                 the signing index (and is zeroed if there is no such output)
 */
const SIGHASH_NONE_FORKID = 0x42;
const SIGHASH_SINGLE_FORKID = 0x43;
const SIGHASH_ALL_ACP_FORKID = 0xc1;
const SIGHASH_NONE_ACP_FORKID = 0xc2;
const SIGHASH_SINGLE_ACP_FORKID = 0xc3;

const ALICE_PRIV = new PrivateKey(1);
const ALICE_PUB_HEX = ALICE_PRIV.toPublicKey().toDER('hex') as string;

// ---------------------------------------------------------------------------
// Tiny hand-rolled raw-tx serializer. We build the unsigned tx ourselves (no
// node, no SDK tx-builder) so the fixture's unsignedTxHex is a frozen,
// minimal artifact that every tier parses identically. Inputs carry EMPTY
// scriptSigs (unsigned form) — the consuming tier supplies the prevout
// script+value out of band, exactly as a real signer does.
// ---------------------------------------------------------------------------

interface TxIn {
  /** Big-endian display txid (64 hex chars), as users see it. */
  prevTxid: string;
  prevVout: number;
  sequence: number;
}

interface TxOut {
  satoshis: number;
  scriptHex: string;
}

function u32le(n: number): string {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b.toString('hex');
}

function u64le(n: number): string {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n), 0);
  return b.toString('hex');
}

function varint(n: number): string {
  if (n < 0xfd) return Buffer.from([n]).toString('hex');
  if (n <= 0xffff) {
    const b = Buffer.alloc(3);
    b[0] = 0xfd;
    b.writeUInt16LE(n, 1);
    return b.toString('hex');
  }
  const b = Buffer.alloc(5);
  b[0] = 0xfe;
  b.writeUInt32LE(n, 1);
  return b.toString('hex');
}

/** Build an unsigned raw tx (version 1, empty scriptSigs). */
function buildUnsignedTx(inputs: TxIn[], outputs: TxOut[], lockTime = 0): string {
  let hex = u32le(1); // version
  hex += varint(inputs.length);
  for (const inp of inputs) {
    // txid is little-endian (internal) in the wire format
    const leTxid = Buffer.from(inp.prevTxid, 'hex').reverse().toString('hex');
    hex += leTxid;
    hex += u32le(inp.prevVout);
    hex += varint(0); // empty scriptSig (unsigned)
    hex += u32le(inp.sequence);
  }
  hex += varint(outputs.length);
  for (const out of outputs) {
    hex += u64le(out.satoshis);
    const scriptBytes = out.scriptHex.length / 2;
    hex += varint(scriptBytes);
    hex += out.scriptHex;
  }
  hex += u32le(lockTime);
  return hex;
}

// ---------------------------------------------------------------------------
// BIP-143 preimage via the exact @bsv/sdk path runar-sdk uses.
// ---------------------------------------------------------------------------

interface PreimageArgs {
  unsignedTxHex: string;
  inputIndex: number;
  prevScriptHex: string;
  prevValueSats: number;
  inputs: TxIn[];
  outputs: TxOut[];
  lockTime: number;
  /** R-206: BIP-143 sighash flags. Drives which digest fields are zeroed. */
  scope: number;
}

function computePreimageHex(a: PreimageArgs): string {
  const input = a.inputs[a.inputIndex]!;
  const otherInputs = a.inputs
    .map((inp, i) => ({ inp, i }))
    .filter(({ i }) => i !== a.inputIndex)
    .map(({ inp }) => ({
      sourceTXID: inp.prevTxid,
      sourceOutputIndex: inp.prevVout,
      sequence: inp.sequence,
    }));
  const outputs = a.outputs.map((out) => ({
    satoshis: out.satoshis,
    lockingScript: Script.fromHex(out.scriptHex),
  }));

  const preimage = TransactionSignature.format({
    sourceTXID: input.prevTxid,
    sourceOutputIndex: input.prevVout,
    sourceSatoshis: a.prevValueSats,
    transactionVersion: 1,
    otherInputs: otherInputs as Parameters<typeof TransactionSignature.format>[0]['otherInputs'],
    outputs: outputs as unknown as Parameters<typeof TransactionSignature.format>[0]['outputs'],
    inputIndex: a.inputIndex,
    subscript: Script.fromHex(a.prevScriptHex) as unknown as Parameters<typeof TransactionSignature.format>[0]['subscript'],
    inputSequence: input.sequence,
    lockTime: a.lockTime,
    scope: a.scope,
  });
  return Buffer.from(preimage).toString('hex');
}

/** Deterministic RFC-6979 + low-S DER signature over sha256d(preimage), + sighash byte. */
function signPreimage(preimageHex: string, scope: number): { sigHex: string; digestHex: string } {
  const preimage = Utils.toArray(preimageHex, 'hex');
  // BIP-143 sighash digest = sha256d(preimage) — this is THE message the
  // signature commits to and the value every consuming tier verifies the
  // signature against. @bsv/sdk's ECDSA.sign treats its BigNumber argument as
  // the message representative directly (no internal hashing — same convention
  // as conformance/sdk-envelope), so we compute sha256d here and sign it as the
  // prehash. RFC-6979 deterministic nonce + forceLowS makes this byte-stable.
  const digest = Hash.sha256(Hash.sha256(preimage)); // sha256d
  const sig = ecdsaSign(new BigNumber(digest), ALICE_PRIV, true); // forceLowS
  const der = Utils.toHex(sig.toDER() as number[]);
  const sigHex = der + scope.toString(16).padStart(2, '0');
  const digestHex = Utils.toHex(digest);
  return { sigHex, digestHex };
}

// ---------------------------------------------------------------------------
// Scenario construction
// ---------------------------------------------------------------------------

interface Scenario {
  scenario: string;
  description: string;
  unsignedTxHex: string;
  inputIndex: number;
  prevScriptHex: string;
  prevValueSats: number;
  sighashFlags: number;
  preimageHex: string;
  digestHex: string;
  sigHex: string;
  pubkeyHex: string;
}

function p2pkhScript(pkhHex: string): string {
  // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
  return `76a914${pkhHex}88ac`;
}

function buildScenario(
  name: string,
  description: string,
  inputs: TxIn[],
  outputs: TxOut[],
  inputIndex: number,
  prevScriptHex: string,
  prevValueSats: number,
  scope: number = SIGHASH_ALL_FORKID,
  lockTime = 0,
): Scenario {
  const unsignedTxHex = buildUnsignedTx(inputs, outputs, lockTime);
  const preimageHex = computePreimageHex({
    unsignedTxHex,
    inputIndex,
    prevScriptHex,
    prevValueSats,
    inputs,
    outputs,
    lockTime,
    scope,
  });
  const { sigHex, digestHex } = signPreimage(preimageHex, scope);
  return {
    scenario: name,
    description,
    unsignedTxHex,
    inputIndex,
    prevScriptHex,
    prevValueSats,
    sighashFlags: scope,
    preimageHex,
    digestHex,
    sigHex,
    pubkeyHex: ALICE_PUB_HEX,
  };
}

async function compileCounterScript(): Promise<string> {
  const { compile } = await import('../../packages/runar-compiler/src/index.js');
  const src = readFileSync(
    resolve(PROJECT_ROOT, 'examples/ts/stateful-counter/Counter.runar.ts'),
    'utf8',
  );
  const result = compile(src, { fileName: 'Counter.runar.ts' });
  if (!result.artifact) {
    throw new Error(`Counter compile failed: ${JSON.stringify(result.diagnostics)}`);
  }
  // codePart is the locking script template (hex). For a stateful contract
  // this is exactly the prev locking script a `call` spends.
  const hex = (result.artifact as { codePart?: string; script?: string }).codePart
    ?? (result.artifact as { script?: string }).script;
  if (!hex || typeof hex !== 'string') {
    throw new Error('Counter artifact has no codePart/script hex');
  }
  return hex;
}

async function buildScenarios(): Promise<Scenario[]> {
  const scenarios: Scenario[] = [];

  // ---- Scenario 1: P2PKH spend — SIGHASH_ALL|FORKID, stateless ----
  // Spend a P2PKH UTXO (locked to HASH160(pub1)) into a new P2PKH output.
  const pkh = Utils.toHex(Hash.hash160(Utils.toArray(ALICE_PUB_HEX, 'hex')));
  const p2pkhPrevScript = p2pkhScript(pkh);
  const s1Inputs: TxIn[] = [
    {
      prevTxid: 'a'.repeat(64), // deterministic synthetic prevout
      prevVout: 0,
      sequence: 0xffffffff,
    },
  ];
  const s1Outputs: TxOut[] = [
    { satoshis: 4500, scriptHex: p2pkhScript(pkh) },
  ];
  scenarios.push(
    buildScenario(
      'p2pkh_spend',
      'P2PKH spend: single input, single P2PKH output, SIGHASH_ALL|FORKID (stateless).',
      s1Inputs,
      s1Outputs,
      0,
      p2pkhPrevScript,
      5000,
    ),
  );

  // ---- Scenario 2: Counter call — stateful OP_PUSH_TX path ----
  // The prev locking script is the compiled Counter contract; the spending tx
  // carries a stateful continuation output (the same shape buildCallTransaction
  // produces). Distinct tx shape + a large scriptCode exercises a different
  // preimage than scenario 1.
  const counterScript = await compileCounterScript();
  const s2Inputs: TxIn[] = [
    {
      prevTxid: 'b'.repeat(64),
      prevVout: 1,
      sequence: 0xfffffffe, // distinct sequence -> distinct hashSequence
    },
  ];
  // Continuation output: reuse the (same) counter script as a stand-in
  // locking script for the next state, plus an OP_RETURN data output.
  const s2Outputs: TxOut[] = [
    { satoshis: 1, scriptHex: counterScript },
    { satoshis: 0, scriptHex: '006a0454657374' }, // OP_FALSE OP_RETURN "Test"
  ];
  scenarios.push(
    buildScenario(
      'counter_call',
      'Counter call (stateful): OP_PUSH_TX path, compiled Counter scriptCode as subscript, continuation + OP_RETURN outputs, sequence 0xfffffffe.',
      s2Inputs,
      s2Outputs,
      0,
      counterScript,
      2,
    ),
  );

  // ---- Scenario 3: multi-input spend — signing input 1 of 2 ----
  // Both prior scenarios sign input 0 of a SINGLE-input transaction, so
  // nothing pinned the two things a second input changes:
  //   * hashPrevouts / hashSequence become digests over MORE than one
  //     outpoint / sequence, and
  //   * the signing index is non-zero, so a tier that assumed index 0 (or
  //     that indexed the wrong input's value / scriptCode) still passed.
  // That gap is not hypothetical: bsv-sdk 2.4.0 began requiring a
  // locking_script on EVERY input, and packages/runar-py only populated the
  // one it was signing — a break that only a multi-input spend can surface.
  // The funding input deliberately carries a DIFFERENT sequence so a tier that
  // hashed one sequence twice diverges here.
  const s3Inputs: TxIn[] = [
    {
      prevTxid: 'c'.repeat(64), // funding input, NOT the one being signed
      prevVout: 0,
      sequence: 0xfffffffd,
    },
    {
      prevTxid: 'd'.repeat(64), // contract input — the signing input
      prevVout: 2,
      sequence: 0xffffffff,
    },
  ];
  const s3Outputs: TxOut[] = [
    { satoshis: 3000, scriptHex: p2pkhScript(pkh) },
  ];
  scenarios.push(
    buildScenario(
      'multi_input_spend',
      'Multi-input spend: 2 inputs with distinct sequences, signing input INDEX 1 ' +
        '(not 0), SIGHASH_ALL|FORKID. Pins hashPrevouts/hashSequence over more ' +
        'than one input and a non-zero signing index.',
      s3Inputs,
      s3Outputs,
      1,
      p2pkhPrevScript,
      7000,
    ),
  );

  // ---- Scenarios 4-8: one per sighash mode (R-206) ----
  //
  // Every scenario above is SIGHASH_ALL|FORKID, which exercises exactly one
  // row of the BIP-143 zeroing table. The compiler accepts NONE, SINGLE and
  // ANYONECANPAY via `@sighash`, `sighash-validate.ts` reasons about what each
  // one zeroes, and all seven SDKs take a flag parameter — so seven
  // independent implementations of those rules shipped with nothing comparing
  // them against each other.
  //
  // The tx shape is deliberately shared across all five so the ONLY difference
  // between their preimages is the flag: two inputs with distinct sequences
  // and two outputs, signing input 1. Two outputs matter for SINGLE, which
  // commits to the output at the signing index alone — with one output,
  // signing index 1 would hit the "no corresponding output" case and zero
  // hashOutputs, making SINGLE indistinguishable from NONE and the fixture
  // worthless for telling them apart.
  const modeInputs: TxIn[] = [
    { prevTxid: 'e'.repeat(64), prevVout: 0, sequence: 0xfffffffd },
    { prevTxid: 'f'.repeat(64), prevVout: 1, sequence: 0xfffffffe },
  ];
  const modeOutputs: TxOut[] = [
    { satoshis: 2200, scriptHex: p2pkhScript(pkh) },
    { satoshis: 3300, scriptHex: p2pkhScript(pkh) },
  ];
  const modes: Array<{ name: string; scope: number; zeroes: string }> = [
    {
      name: 'sighash_none_forkid',
      scope: SIGHASH_NONE_FORKID,
      zeroes: 'hashSequence and hashOutputs zeroed; the signer commits to no output at all',
    },
    {
      name: 'sighash_single_forkid',
      scope: SIGHASH_SINGLE_FORKID,
      zeroes: 'hashSequence zeroed; hashOutputs covers ONLY output 1 (the signing index)',
    },
    {
      name: 'sighash_all_anyonecanpay_forkid',
      scope: SIGHASH_ALL_ACP_FORKID,
      zeroes: 'hashPrevouts and hashSequence zeroed; hashOutputs covers every output',
    },
    {
      name: 'sighash_none_anyonecanpay_forkid',
      scope: SIGHASH_NONE_ACP_FORKID,
      zeroes: 'hashPrevouts, hashSequence and hashOutputs all zeroed — the weakest commitment',
    },
    {
      name: 'sighash_single_anyonecanpay_forkid',
      scope: SIGHASH_SINGLE_ACP_FORKID,
      zeroes: 'hashPrevouts and hashSequence zeroed; hashOutputs covers ONLY output 1',
    },
  ];
  for (const mode of modes) {
    scenarios.push(
      buildScenario(
        mode.name,
        `Sighash mode 0x${mode.scope.toString(16)}: ${mode.zeroes}. ` +
          'Same 2-in/2-out tx and signing index as its siblings, so the preimage ' +
          'difference is attributable to the flag alone.',
        modeInputs,
        modeOutputs,
        1,
        p2pkhPrevScript,
        9000,
        mode.scope,
      ),
    );
  }

  return scenarios;
}

// ---------------------------------------------------------------------------
// Self-validation: re-derive + verify everything before writing / on --check.
// ---------------------------------------------------------------------------

function selfValidate(scenarios: Scenario[]): void {
  for (const s of scenarios) {
    // 1. pubkey matches the documented signer.
    if (s.pubkeyHex !== ALICE_PUB_HEX) {
      throw new Error(`${s.scenario}: pubkey ${s.pubkeyHex} != ${ALICE_PUB_HEX}`);
    }
    // 2. preimage recomputes byte-identically from the published tx + prevout.
    //    (Reparse unsignedTxHex back into inputs/outputs so we exercise the
    //    same recompute path a consumer must implement.)
    const reInputs = parseInputs(s.unsignedTxHex);
    const reOutputs = parseOutputs(s.unsignedTxHex);
    const re = computePreimageHex({
      unsignedTxHex: s.unsignedTxHex,
      inputIndex: s.inputIndex,
      prevScriptHex: s.prevScriptHex,
      prevValueSats: s.prevValueSats,
      inputs: reInputs,
      outputs: reOutputs,
      lockTime: 0,
      scope: s.sighashFlags,
    });
    if (re !== s.preimageHex) {
      throw new Error(
        `${s.scenario}: preimage drift\n  committed:  ${s.preimageHex}\n  recomputed: ${re}`,
      );
    }
    // 3. sighash digest = sha256d(preimage).
    const digestBytes = Hash.sha256(Hash.sha256(Utils.toArray(s.preimageHex, 'hex')));
    const digest = Utils.toHex(digestBytes);
    if (digest !== s.digestHex) {
      throw new Error(`${s.scenario}: digest drift ${digest} != ${s.digestHex}`);
    }
    // 4. signature verifies for the digest under the pubkey (sig commits to
    //    sha256d(preimage), exactly what every consuming tier checks).
    const derHex = s.sigHex.slice(0, -2); // strip sighash byte
    const ok = ecdsaVerify(
      new BigNumber(digestBytes),
      Signature.fromDER(Utils.toArray(derHex, 'hex')),
      PublicKey.fromDER(Utils.toArray(s.pubkeyHex, 'hex')),
    );
    if (!ok) throw new Error(`${s.scenario}: signature does not verify`);
  }
}

// Minimal reparse helpers used only by self-validation (mirror of the tier
// recompute path).
function parseInputs(txHex: string): TxIn[] {
  const buf = Buffer.from(txHex, 'hex');
  let o = 4; // skip version
  const [nIn, no] = readVarint(buf, o);
  o = no;
  const inputs: TxIn[] = [];
  for (let i = 0; i < nIn; i++) {
    const leTxid = buf.subarray(o, o + 32);
    o += 32;
    const vout = buf.readUInt32LE(o);
    o += 4;
    const [slen, so] = readVarint(buf, o);
    o = so + slen; // skip scriptSig
    const sequence = buf.readUInt32LE(o);
    o += 4;
    inputs.push({
      prevTxid: Buffer.from(leTxid).reverse().toString('hex'),
      prevVout: vout,
      sequence,
    });
  }
  return inputs;
}

function parseOutputs(txHex: string): TxOut[] {
  const buf = Buffer.from(txHex, 'hex');
  let o = 4;
  const [nIn, no] = readVarint(buf, o);
  o = no;
  for (let i = 0; i < nIn; i++) {
    o += 36;
    const [slen, so] = readVarint(buf, o);
    o = so + slen + 4;
  }
  const [nOut, oo] = readVarint(buf, o);
  o = oo;
  const outputs: TxOut[] = [];
  for (let i = 0; i < nOut; i++) {
    const sats = Number(buf.readBigUInt64LE(o));
    o += 8;
    const [slen, so] = readVarint(buf, o);
    o = so;
    const scriptHex = buf.subarray(o, o + slen).toString('hex');
    o += slen;
    outputs.push({ satoshis: sats, scriptHex });
  }
  return outputs;
}

function readVarint(buf: Buffer, o: number): [number, number] {
  const first = buf[o]!;
  if (first < 0xfd) return [first, o + 1];
  if (first === 0xfd) return [buf.readUInt16LE(o + 1), o + 3];
  if (first === 0xfe) return [buf.readUInt32LE(o + 1), o + 5];
  return [Number(buf.readBigUInt64LE(o + 1)), o + 9];
}

// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const checkOnly = process.argv.includes('--check');
  const fixturePath = join(__dirname, 'fixtures.json');

  if (checkOnly) {
    // Build-free drift guard: re-derive the signing-sensitive bytes (preimage,
    // digest, deterministic signature) from the committed tx + prevout using
    // the live TS reference, and re-verify the signature. This catches any
    // drift in the BIP-143 preimage-assembly or RFC-6979/low-S signing path
    // WITHOUT recompiling the Counter contract — the prevScriptHex is a frozen
    // test vector (compiled-script drift is covered by the conformance suite),
    // so `--check` stays install-only and needs no `pnpm build`.
    const committed = JSON.parse(readFileSync(fixturePath, 'utf8'));
    const scenarios = committed.scenarios as Scenario[];
    selfValidate(scenarios); // preimage recomputes + digest matches + sig verifies
    for (const s of scenarios) {
      const { sigHex, digestHex } = signPreimage(s.preimageHex, s.sighashFlags);
      if (sigHex !== s.sigHex) {
        console.error(`FAIL: ${s.scenario}.sigHex drifted from the TS reference`);
        console.error(`  committed:  ${s.sigHex}`);
        console.error(`  recomputed: ${sigHex}`);
        process.exit(1);
      }
      if (digestHex !== s.digestHex) {
        console.error(`FAIL: ${s.scenario}.digestHex drifted ${digestHex} != ${s.digestHex}`);
        process.exit(1);
      }
    }
    console.log(`OK: committed BIP-143 fixture matches the TS reference (${scenarios.length} scenarios).`);
    return;
  }

  const scenarios = await buildScenarios();
  selfValidate(scenarios);

  const fixture = {
    fixture_version: 1,
    notes:
      'Cross-tier BIP-143 sighash fixture (GAP-003). TS (@bsv/sdk TransactionSignature.format) is the reference. Every SDK tier must INDEPENDENTLY recompute preimageHex from (unsignedTxHex, inputIndex, prevScriptHex, prevValueSats, sighashFlags) and assert byte-equality, then verify sigHex against pubkeyHex over sha256d(preimage). sigHex is deterministic RFC-6979 + low-S DER over sha256d(preimage) with priv=1 and the scenario\'s own sighash byte appended. See conformance/sdk-bip143/generate-fixtures.ts.',
    provenance_note:
      'R-206 asked whether these vectors are self-graded. Partly: they are produced by the TS tier, but they are CHECKED by seven independent implementations, two of which are upstream third-party libraries rather than repo code — @bsv/sdk (TS) and bsv-blockchain/go-sdk (Go, via CalcInputPreimage). Rust, Python, Zig, Ruby and Java hand-roll the preimage. Two independent upstream BIP-143 implementations agreeing is category (b), not (c). What is still missing is a category-(a) vector published by the BIP itself; adding one requires fetching it from the spec, and transcribing digests from memory would be fabricating test data.',
    coverage_note:
      'Sighash modes covered: ALL|FORKID (0x41, three tx shapes), NONE|FORKID (0x42), SINGLE|FORKID (0x43), ALL|ANYONECANPAY|FORKID (0xc1), NONE|ANYONECANPAY|FORKID (0xc2), SINGLE|ANYONECANPAY|FORKID (0xc3). The five mode scenarios share one 2-in/2-out transaction signing input 1, so the only difference between their preimages is the flag. Two outputs are required: under SINGLE the digest covers the output at the SIGNING index, and with a single output index 1 would hit the no-corresponding-output case, zero hashOutputs, and make SINGLE indistinguishable from NONE.',
    signer_priv_hex: '0000000000000000000000000000000000000000000000000000000000000001',
    signer_pub_hex: ALICE_PUB_HEX,
    sighash_note: '0x41 = SIGHASH_ALL | SIGHASH_FORKID. digestHex = sha256d(preimage) = the value ECDSA actually signs. Each scenario carries its own sighashFlags; consumers must recompute under THAT value, not a hardcoded one.',
    scenarios,
  };

  writeFileSync(fixturePath, JSON.stringify(fixture, null, 2) + '\n');
  console.log(`Wrote ${fixturePath} (${scenarios.length} scenarios).`);
  for (const s of scenarios) {
    console.log(`  - ${s.scenario}: preimage ${s.preimageHex.length / 2} bytes, subscript ${s.prevScriptHex.length / 2} bytes`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
