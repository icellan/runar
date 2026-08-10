/**
 * Idiom registry for the general (semantic) lifter — milestone 1.
 *
 * Each idiom is a pure matcher over the disassembled op stream that recognizes
 * a macro-pattern emitted by foreign compilers (here: the sCrypt OP_PUSH_TX /
 * fungible-token family). A match reports the op-index span it covers and any
 * recovered data (state fields, pubkey hash). The general lifter uses matches
 * to set segment boundaries and label spans; unmatched regions become asm
 * islands.
 *
 * Recognition keys are stable on-chain constants, so these matchers identify
 * the *construction* even though the byte layout is not Rúnar's.
 */

import { bytesToHex } from 'runar-testing';
import type { Op } from './types.js';

export interface IdiomMatch {
  name: string;
  /** op index where the span starts (inclusive). */
  startIndex: number;
  /** op index where the span ends (exclusive). */
  endIndex: number;
  /** Idiom-specific recovered data. */
  data?: Record<string, unknown>;
}

export interface Idiom {
  name: string;
  /** Higher wins when multiple idioms match at the same index. */
  priority: number;
  match(ops: Op[], i: number): IdiomMatch | null;
}

// secp256k1 generator X coordinate (Gx), curve order N little-endian (+sign
// byte), and the canonical sCrypt optimal-OP_PUSH_TX public key. Together
// these fingerprint the pushtx construction.
const GX_HEX = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const N_LE_HEX = '414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00';
const PUSHTX_PUBKEY_HEX = '038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218';

function dataHex(op: Op | undefined): string | null {
  return op && op.data ? bytesToHex(op.data) : null;
}

/** Trailing `OP_RETURN <push>...` carrying serialized contract state. */
export const opReturnState: Idiom = {
  name: 'op_return_state',
  priority: 100,
  match(ops, i) {
    if (ops[i]?.name !== 'OP_RETURN') return null;
    const fields: string[] = [];
    for (let j = i + 1; j < ops.length; j++) {
      const d = dataHex(ops[j]);
      if (d === null) return null; // a non-push after OP_RETURN -> not pure state
      fields.push(d);
    }
    return { name: 'op_return_state', startIndex: i, endIndex: ops.length, data: { fields } };
  },
};

/** Optimal OP_PUSH_TX: preimage `DUP HASH256` … constructed-sig `CHECKSIG(VERIFY)`. */
export const opPushTx: Idiom = {
  name: 'op_push_tx',
  priority: 95,
  match(ops, i) {
    if (ops[i]?.name !== 'OP_DUP') return null;
    if (ops[i + 1]?.name !== 'OP_HASH256') return null;
    let end = -1;
    let sawGx = false;
    let sawN = false;
    for (let j = i + 2; j < ops.length; j++) {
      const d = dataHex(ops[j]);
      if (d === null) continue;
      if (d.includes(GX_HEX)) sawGx = true;
      if (d === N_LE_HEX) sawN = true;
      if (d === PUSHTX_PUBKEY_HEX) {
        const next = ops[j + 1]?.name;
        if (next === 'OP_CHECKSIGVERIFY' || next === 'OP_CHECKSIG') {
          end = j + 2;
          break;
        }
      }
    }
    if (end === -1 || !sawGx || !sawN) return null;
    return { name: 'op_push_tx', startIndex: i, endIndex: end, data: { pubKey: PUSHTX_PUBKEY_HEX } };
  },
};

/**
 * BIP-143 preimage field-carving prologue (right after OP_PUSH_TX):
 * `OP_4 SPLIT NIP <push 0x20> SPLIT <push 0x20> SPLIT NIP <push 0x24> SPLIT`
 * — drop nVersion(4), take hashPrevouts(32), drop hashSequence(32), take
 * outpoint(36), leaving scriptCode||value||… for further parsing.
 */
export const preimageExtract: Idiom = {
  name: 'preimage_extract',
  priority: 80,
  match(ops, i) {
    const checks: Array<(o: Op | undefined) => boolean> = [
      (o) => o?.name === 'OP_4',
      (o) => o?.name === 'OP_SPLIT',
      (o) => o?.name === 'OP_NIP',
      (o) => dataHex(o) === '20',
      (o) => o?.name === 'OP_SPLIT',
      (o) => dataHex(o) === '20',
      (o) => o?.name === 'OP_SPLIT',
      (o) => o?.name === 'OP_NIP',
      (o) => dataHex(o) === '24',
      (o) => o?.name === 'OP_SPLIT',
    ];
    for (let k = 0; k < checks.length; k++) {
      if (!checks[k]!(ops[i + k])) return null;
    }
    return { name: 'preimage_extract', startIndex: i, endIndex: i + checks.length };
  },
};

/**
 * Final outputs-hash enforcement: `HASH256 EQUAL 2SWAP 2DROP NIP NIP`
 * immediately before `OP_RETURN`. Forces the spending tx's outputs to match
 * the contract-built outputs (the BIP-143 hashOutputs check). The trailing
 * OP_RETURN anchor makes this unambiguous (only one OP_RETURN in the script).
 */
export const outputsEnforce: Idiom = {
  name: 'outputs_enforce',
  priority: 85,
  match(ops, i) {
    const seq = ['OP_HASH256', 'OP_EQUAL', 'OP_2SWAP', 'OP_2DROP', 'OP_NIP', 'OP_NIP'];
    for (let k = 0; k < seq.length; k++) {
      if (ops[i + k]?.name !== seq[k]) return null;
    }
    if (ops[i + seq.length]?.name !== 'OP_RETURN') return null;
    return { name: 'outputs_enforce', startIndex: i, endIndex: i + seq.length };
  },
};

/**
 * A P2PKH locking-script template pushed verbatim to build (or compare) an
 * output script: `1976a914` (length-prefixed full script) or its `76a914`
 * prefix. Wherever these exact bytes are pushed, a P2PKH output is being
 * assembled or matched.
 */
export const buildP2pkhOutput: Idiom = {
  name: 'build_p2pkh_output',
  priority: 70,
  match(ops, i) {
    const d = dataHex(ops[i]);
    if (d === '1976a914' || d === '76a914') {
      return { name: 'build_p2pkh_output', startIndex: i, endIndex: i + 1, data: { template: d } };
    }
    return null;
  },
};

/** Owner gate: `DUP HASH160 <20> EQUALVERIFY CHECKSIG [VERIFY]`. */
export const p2pkhSigGate: Idiom = {
  name: 'p2pkh_sig_gate',
  priority: 90,
  match(ops, i) {
    if (ops[i]?.name !== 'OP_DUP') return null;
    if (ops[i + 1]?.name !== 'OP_HASH160') return null;
    const pkh = dataHex(ops[i + 2]);
    if (pkh === null || ops[i + 2]!.data!.length !== 20) return null;
    if (ops[i + 3]?.name !== 'OP_EQUALVERIFY') return null;
    if (ops[i + 4]?.name !== 'OP_CHECKSIG') return null;
    let end = i + 5;
    if (ops[end]?.name === 'OP_VERIFY') end++;
    return { name: 'p2pkh_sig_gate', startIndex: i, endIndex: end, data: { pubKeyHash: pkh } };
  },
};

/** Registry, consulted highest-priority-first. */
export const IDIOMS: Idiom[] = [
  opReturnState,
  opPushTx,
  p2pkhSigGate,
  outputsEnforce,
  preimageExtract,
  buildP2pkhOutput,
];

/** Try every idiom at op index `i`, highest priority first. */
export function matchIdiomAt(ops: Op[], i: number): IdiomMatch | null {
  for (const idiom of [...IDIOMS].sort((a, b) => b.priority - a.priority)) {
    const m = idiom.match(ops, i);
    if (m) return m;
  }
  return null;
}
