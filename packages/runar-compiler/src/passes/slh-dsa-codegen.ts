/**
 * SLH-DSA (FIPS 205) Bitcoin Script codegen for the Rúnar stack lowerer.
 *
 * Splice into LoweringContext in 05-stack-lower.ts. All helpers self-contained.
 * Entry: lowerVerifySLHDSA() → calls emitVerifySLHDSA().
 *
 * Main-stack convention: pkSeedPad (64 bytes) tracked as '_pkSeedPad' on the
 * main stack, accessed via PICK at known depth. Never placed on alt.
 *
 * Runtime ADRS: treeAddr (8-byte BE) and keypair (4-byte BE) are tracked on
 * the main stack as 'treeAddr8' and 'keypair4', threaded into rawBlocks.
 * ADRS is built at runtime using emitBuildADRS / emitBuildADRS18 helpers.
 */

import type { StackOp } from '../ir/index.js';

// ===========================================================================
// 1. Parameter Sets (FIPS 205 Table 1, SHA2)
// ===========================================================================

interface SLHCodegenParams {
  n: number;    // Security parameter (hash bytes): 16, 24, 32
  h: number;    // Total tree height
  d: number;    // Hypertree layers
  hp: number;   // Subtree height (h/d)
  a: number;    // FORS tree height
  k: number;    // FORS tree count
  w: number;    // Winternitz parameter (16)
  len: number;  // WOTS+ chain count
  len1: number; // Message chains (2*n)
  len2: number; // Checksum chains (3 for all SHA2 sets)
}

function slhMk(n: number, h: number, d: number, a: number, k: number): SLHCodegenParams {
  const len1 = 2 * n;
  const len2 = Math.floor(Math.log2(len1 * 15) / Math.log2(16)) + 1;
  return { n, h, d, hp: h / d, a, k, w: 16, len: len1 + len2, len1, len2 };
}

const SLH_PARAMS: Record<string, SLHCodegenParams> = {
  'SHA2_128s': slhMk(16, 63, 7, 12, 14),
  'SHA2_128f': slhMk(16, 66, 22, 6, 33),
  'SHA2_192s': slhMk(24, 63, 7, 14, 17),
  'SHA2_192f': slhMk(24, 66, 22, 8, 33),
  'SHA2_256s': slhMk(32, 64, 8, 14, 22),
  'SHA2_256f': slhMk(32, 68, 17, 8, 35),
};

// ===========================================================================
// 1b. Fixed-length byte reversal helper
// ===========================================================================

/**
 * Emit an unrolled fixed-length byte reversal for N bytes.
 * Uses (N-1) split-swap-cat operations. Only valid when N is known at compile time.
 */
function emitReverseN(n: number): StackOp[] {
  if (n <= 1) return [];
  const ops: StackOp[] = [];
  // Phase 1: split into N individual bytes
  for (let i = 0; i < n - 1; i++) {
    ops.push({ op: 'push', value: 1n });
    ops.push({ op: 'opcode', code: 'OP_SPLIT' });
  }
  // Phase 2: concatenate in reverse order
  for (let i = 0; i < n - 1; i++) {
    ops.push({ op: 'swap' });
    ops.push({ op: 'opcode', code: 'OP_CAT' });
  }
  return ops;
}

// ===========================================================================
// 1c. Collect ops into array helper
// ===========================================================================

function collectOps(fn: (emit: (op: StackOp) => void) => void): StackOp[] {
  const ops: StackOp[] = [];
  fn(op => ops.push(op));
  return ops;
}

// ===========================================================================
// 2. Compressed ADRS (22 bytes)
// ===========================================================================
// [0] layer  [1..8] tree  [9] type  [10..13] keypair
// [14..17] chain/treeHeight  [18..21] hash/treeIndex

const SLH_WOTS_HASH  = 0;
const SLH_WOTS_PK    = 1;
const SLH_TREE       = 2;
const SLH_FORS_TREE  = 3;
const SLH_FORS_ROOTS = 4;

function slhADRS(opts: {
  layer?: number; tree?: bigint; type: number;
  keypair?: number; chain?: number; hash?: number;
}): Uint8Array {
  const c = new Uint8Array(22);
  c[0] = (opts.layer ?? 0) & 0xff;
  const tr = opts.tree ?? 0n;
  for (let i = 0; i < 8; i++) c[1 + 7 - i] = Number((tr >> BigInt(8 * i)) & 0xffn);
  c[9] = opts.type & 0xff;
  const kp = opts.keypair ?? 0;
  c[10] = (kp >>> 24) & 0xff; c[11] = (kp >>> 16) & 0xff;
  c[12] = (kp >>> 8) & 0xff;  c[13] = kp & 0xff;
  const ch = opts.chain ?? 0;
  c[14] = (ch >>> 24) & 0xff; c[15] = (ch >>> 16) & 0xff;
  c[16] = (ch >>> 8) & 0xff;  c[17] = ch & 0xff;
  const ha = opts.hash ?? 0;
  c[18] = (ha >>> 24) & 0xff; c[19] = (ha >>> 16) & 0xff;
  c[20] = (ha >>> 8) & 0xff;  c[21] = ha & 0xff;
  return c;
}

/** 18-byte prefix (bytes 0..17): everything before hashAddress. */
function slhADRS18(opts: {
  layer?: number; tree?: bigint; type: number;
  keypair?: number; chain?: number;
}): Uint8Array {
  return slhADRS({ ...opts, hash: 0 }).slice(0, 18);
}

// ===========================================================================
// 2b. Runtime ADRS builders
// ===========================================================================

/**
 * Convert a compile-time integer to a 4-byte big-endian Uint8Array.
 */
function int4BE(v: number): Uint8Array {
  const b = new Uint8Array(4);
  b[0] = (v >>> 24) & 0xff;
  b[1] = (v >>> 16) & 0xff;
  b[2] = (v >>> 8) & 0xff;
  b[3] = v & 0xff;
  return b;
}

/**
 * Emit runtime 18-byte ADRS prefix: layer(1B) || PICK(treeAddr8)(8B) ||
 * type(1B) || PICK(keypair4)(4B) || chain(4B).
 *
 * Net stack effect: +1 (the 18-byte result on TOS).
 *
 * ta8Depth and kp4Depth are from TOS *before* this function pushes anything.
 */
function emitBuildADRS18(
  emit: (op: StackOp) => void,
  layer: number, type_: number, chain: number,
  ta8Depth: number, kp4Depth: number | 'zero',
): void {
  // Push layer byte (1B)
  emit({ op: 'push', value: new Uint8Array([layer & 0xff]) });
  // After push: ta8 at ta8Depth+1, kp4 at kp4Depth+1

  // PICK ta8: depth = ta8Depth + 1 (one extra item on stack)
  emit({ op: 'push', value: BigInt(ta8Depth + 1) });
  emit({ op: 'pick', depth: ta8Depth + 1 });
  // Stack: ... layerByte ta8Copy (2 items above original TOS)
  emit({ op: 'opcode', code: 'OP_CAT' });
  // Stack: ... (layer||ta8)(9B) — net +1 from start

  // Push type byte (1B)
  emit({ op: 'push', value: new Uint8Array([type_ & 0xff]) });
  emit({ op: 'opcode', code: 'OP_CAT' });
  // Stack: ... partial10B — net +1

  // Keypair (4B): either PICK from stack or push zeros
  if (kp4Depth === 'zero') {
    emit({ op: 'push', value: new Uint8Array(4) });
  } else {
    emit({ op: 'push', value: BigInt(kp4Depth + 1) });
    emit({ op: 'pick', depth: kp4Depth + 1 });
  }
  emit({ op: 'opcode', code: 'OP_CAT' });
  // Stack: ... partial14B — net +1

  // Push chain (4B BE)
  emit({ op: 'push', value: int4BE(chain) });
  emit({ op: 'opcode', code: 'OP_CAT' });
  // Stack: ... prefix18B — net +1
}

/**
 * Emit runtime 22-byte ADRS.
 *
 * hash mode:
 *   'zero'  — append 4 zero bytes (hash=0)
 *   'stack' — TOS has a 4-byte BE hash value; consumed and appended
 *
 * For 'zero': net stack effect = +1 (22B ADRS on TOS).
 * For 'stack': net stack effect = 0 (TOS hash4 replaced by 22B ADRS).
 *
 * ta8Depth/kp4Depth measured from TOS before this function pushes anything.
 */
function emitBuildADRS(
  emit: (op: StackOp) => void,
  layer: number, type_: number, chain: number,
  ta8Depth: number, kp4Depth: number | 'zero',
  hash: 'zero' | 'stack',
): void {
  if (hash === 'stack') {
    // Save hash4 from TOS to alt
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
    // Depths shift by -1 (one item removed from main)
    const adjKp = kp4Depth === 'zero' ? 'zero' as const : kp4Depth - 1;
    emitBuildADRS18(emit, layer, type_, chain, ta8Depth - 1, adjKp);
    // 18-byte prefix on TOS
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });
    emit({ op: 'opcode', code: 'OP_CAT' });
    // 22-byte ADRS on TOS. Net: replaced hash4 with adrs22.
  } else {
    // 'zero'
    emitBuildADRS18(emit, layer, type_, chain, ta8Depth, kp4Depth);
    emit({ op: 'push', value: new Uint8Array(4) });
    emit({ op: 'opcode', code: 'OP_CAT' });
    // 22-byte ADRS on TOS. Net: +1.
  }
}

// ===========================================================================
// 3. SLH Stack Tracker
// ===========================================================================

class SLHTracker {
  private nm: (string | null)[];
  private _e: (op: StackOp) => void;

  constructor(init: (string | null)[], emit: (op: StackOp) => void) {
    this.nm = [...init];
    this._e = emit;
  }

  get depth(): number { return this.nm.length; }

  findDepth(name: string): number {
    for (let i = this.nm.length - 1; i >= 0; i--)
      if (this.nm[i] === name) return this.nm.length - 1 - i;
    throw new Error(`SLHTracker: '${name}' not on stack [${this.nm.join(',')}]`);
  }

  has(n: string): boolean { return this.nm.includes(n); }

  pushBytes(n: string | null, v: Uint8Array): void { this._e({ op: 'push', value: v }); this.nm.push(n); }
  pushInt(n: string | null, v: bigint): void { this._e({ op: 'push', value: v }); this.nm.push(n); }
  pushEmpty(n: string | null): void { this._e({ op: 'opcode', code: 'OP_0' }); this.nm.push(n); }
  dup(n: string | null): void { this._e({ op: 'dup' }); this.nm.push(n); }
  drop(): void { this._e({ op: 'drop' }); this.nm.pop(); }
  nip(): void { this._e({ op: 'nip' }); const L = this.nm.length; if (L >= 2) this.nm.splice(L - 2, 1); }
  over(n: string | null): void { this._e({ op: 'over' }); this.nm.push(n); }

  swap(): void {
    this._e({ op: 'swap' });
    const L = this.nm.length;
    if (L >= 2) { const t = this.nm[L-1]!; this.nm[L-1] = this.nm[L-2]!; this.nm[L-2] = t; }
  }

  rot(): void {
    this._e({ op: 'rot' });
    const L = this.nm.length;
    if (L >= 3) { const r = this.nm.splice(L - 3, 1)[0]!; this.nm.push(r); }
  }

  op(code: string): void { this._e({ op: 'opcode', code }); }

  roll(d: number): void {
    if (d === 0) return;
    if (d === 1) { this.swap(); return; }
    if (d === 2) { this.rot(); return; }
    this._e({ op: 'push', value: BigInt(d) }); this.nm.push(null);
    this._e({ op: 'roll', depth: d }); this.nm.pop();
    const idx = this.nm.length - 1 - d;
    const r = this.nm.splice(idx, 1)[0] ?? null;
    this.nm.push(r);
  }

  pick(d: number, n: string | null): void {
    if (d === 0) { this.dup(n); return; }
    if (d === 1) { this.over(n); return; }
    this._e({ op: 'push', value: BigInt(d) }); this.nm.push(null);
    this._e({ op: 'pick', depth: d }); this.nm.pop();
    this.nm.push(n);
  }

  toTop(name: string): void { this.roll(this.findDepth(name)); }
  copyToTop(name: string, n?: string | null): void { this.pick(this.findDepth(name), n ?? name); }
  toAlt(): void { this.op('OP_TOALTSTACK'); this.nm.pop(); }
  fromAlt(n: string | null): void { this.op('OP_FROMALTSTACK'); this.nm.push(n); }

  split(left: string | null, right: string | null): void {
    this.op('OP_SPLIT'); this.nm.pop(); this.nm.pop();
    this.nm.push(left); this.nm.push(right);
  }

  cat(n: string | null): void {
    this.op('OP_CAT'); this.nm.pop(); this.nm.pop(); this.nm.push(n);
  }

  sha256(n: string | null): void {
    this.op('OP_SHA256'); this.nm.pop(); this.nm.push(n);
  }

  equal(n: string | null): void {
    this.op('OP_EQUAL'); this.nm.pop(); this.nm.pop(); this.nm.push(n);
  }

  rename(n: string | null): void {
    if (this.nm.length > 0) this.nm[this.nm.length - 1] = n;
  }

  /**
   * rawBlock: emit raw opcodes; tracker only records net stack effect.
   * @param consume Names consumed (top is last element).
   * @param produce Name for single result, or null.
   * @param fn      Raw emitter function.
   */
  rawBlock(
    consume: string[],
    produce: string | null,
    fn: (emit: (op: StackOp) => void) => void,
  ): void {
    for (let i = consume.length - 1; i >= 0; i--) this.nm.pop();
    fn(this._e);
    if (produce !== null) this.nm.push(produce);
  }
}

// ===========================================================================
// 4. Tweakable Hash T(pkSeed, ADRS, M)
// ===========================================================================
// trunc_n(SHA-256(pkSeedPad(64) || ADRSc(22) || M))
// pkSeedPad on main stack, accessed via PICK.

/**
 * Tracked tweakable hash. Accesses _pkSeedPad via copyToTop.
 */
function emitSLHT(
  t: SLHTracker, n: number,
  adrs: string, msg: string, result: string,
): void {
  t.toTop(adrs);
  t.toTop(msg);
  t.cat('_am');
  // Access pkSeedPad via PICK on main stack
  t.copyToTop('_pkSeedPad', '_psp');
  t.swap();
  t.cat('_pre');
  t.sha256('_h32');
  if (n < 32) {
    t.pushInt(null, BigInt(n));
    t.split(result, '_tr');
    t.drop();
  } else {
    t.rename(result);
  }
}

/**
 * Raw tweakable hash with pkSeedPad on main stack via PICK.
 *
 * Stack in:  adrsC(1) msg(0), pkSeedPad at depth pkSeedPadDepth from TOS
 * After CAT: (adrsC||msg)(0), pkSeedPad at depth pkSeedPadDepth-1
 * PICK pkSeedPad, SWAP, CAT, SHA256, truncate
 * Stack out: result(0)
 */
function emitSLHT_raw(e: (op: StackOp) => void, n: number, pkSeedPadDepth: number): void {
  e({ op: 'opcode', code: 'OP_CAT' });
  // After CAT: 2 consumed, 1 produced. pkSeedPad depth = pkSeedPadDepth - 1.
  const pickDepth = pkSeedPadDepth - 1;
  e({ op: 'push', value: BigInt(pickDepth) });
  e({ op: 'pick', depth: pickDepth });
  // pkSeedPad copy on TOS, original still in place
  e({ op: 'swap' });
  e({ op: 'opcode', code: 'OP_CAT' });
  e({ op: 'opcode', code: 'OP_SHA256' });
  if (n < 32) {
    e({ op: 'push', value: BigInt(n) });
    e({ op: 'opcode', code: 'OP_SPLIT' });
    e({ op: 'drop' });
  }
}

// ===========================================================================
// 5. WOTS+ One Chain (tweakable hash, dynamic hashAddress)
// ===========================================================================

/**
 * One conditional hash step (if-then body).
 *
 * Entry: sigElem(2) steps(1) hashAddr(0)
 *        with ADRS prefix (18B) on alt (FROMALT/DUP/TOALT pattern)
 *        and pkSeedPad at pkSeedPadDepth from TOS.
 *
 * Exit:  newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
 */
function slhChainStepThen(n: number, pkSeedPadDepth: number): StackOp[] {
  const ops: StackOp[] = [];
  // DUP hashAddr before consuming it in ADRS construction
  ops.push({ op: 'dup' });
  // sigElem(3) steps(2) hashAddr(1) hashAddr_copy(0)
  // Convert copy to 4-byte big-endian
  ops.push({ op: 'push', value: 4n });
  ops.push({ op: 'opcode', code: 'OP_NUM2BIN' });
  ops.push(...emitReverseN(4));
  // sigElem(3) steps(2) hashAddr(1) hashAddrBE4(0) — 4 items above base

  // Get prefix from alt: FROMALT; DUP; TOALT
  ops.push({ op: 'opcode', code: 'OP_FROMALTSTACK' });
  ops.push({ op: 'opcode', code: 'OP_DUP' });
  ops.push({ op: 'opcode', code: 'OP_TOALTSTACK' });
  // sigElem(4) steps(3) hashAddr(2) hashAddrBE4(1) prefix18(0) — 5 items
  ops.push({ op: 'swap' });
  ops.push({ op: 'opcode', code: 'OP_CAT' });
  // sigElem(3) steps(2) hashAddr(1) adrsC22(0) — 4 items

  // Move sigElem to top: ROLL 3
  ops.push({ op: 'push', value: 3n });
  ops.push({ op: 'roll', depth: 3 });
  // steps(2) hashAddr(1) adrsC22(0) sigElem(top) — 4 items
  // CAT: adrsC(1) || sigElem(0) -> adrsC||sigElem
  ops.push({ op: 'opcode', code: 'OP_CAT' });
  // steps(1) hashAddr(0) (adrsC||sigElem)(top) — 3 items

  // pkSeedPad via PICK (3 items on main above base, same as entry)
  ops.push({ op: 'push', value: BigInt(pkSeedPadDepth) });
  ops.push({ op: 'pick', depth: pkSeedPadDepth });
  // steps(2) hashAddr(1) (adrsC||sigElem)(0) pkSeedPad(top) — 4 items
  ops.push({ op: 'swap' });
  // steps(2) hashAddr(1) pkSeedPad(0) (adrsC||sigElem)(top)
  ops.push({ op: 'opcode', code: 'OP_CAT' });
  ops.push({ op: 'opcode', code: 'OP_SHA256' });
  if (n < 32) {
    ops.push({ op: 'push', value: BigInt(n) });
    ops.push({ op: 'opcode', code: 'OP_SPLIT' });
    ops.push({ op: 'drop' });
  }
  // steps(2) hashAddr(1) newSigElem(0) — 3 items
  // Rearrange -> newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
  ops.push({ op: 'rot' });
  ops.push({ op: 'opcode', code: 'OP_1SUB' });
  ops.push({ op: 'rot' });
  ops.push({ op: 'opcode', code: 'OP_1ADD' });
  // newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
  return ops;
}

/**
 * One WOTS+ chain with tweakable hashing (raw opcodes).
 *
 * Input:  sig(3) csum(2) endptAcc(1) digit(0)
 *         pkSeedPad at pkSeedPadDepth from TOS (digit)
 *         treeAddr8 at ta8Depth from TOS
 *         keypair4 at kp4Depth from TOS
 *
 * Output: sigRest(2) newCsum(1) newEndptAcc(0)
 *         (3 items replaces 4 input items, so depths shift by -1)
 *
 * Alt: not used for pkSeedPad. Uses alt internally (balanced).
 */
function emitSLHOneChainClean(
  emit: (op: StackOp) => void,
  n: number, layer: number, chainIdx: number,
  pkSeedPadDepth: number, ta8Depth: number, kp4Depth: number,
): void {
  // Input: sig(3) csum(2) endptAcc(1) digit(0)

  // steps = 15 - digit
  emit({ op: 'push', value: 15n });
  emit({ op: 'swap' });
  emit({ op: 'opcode', code: 'OP_SUB' });
  // sig(3) csum(2) endptAcc(1) steps(0)

  // Save steps_copy, endptAcc, csum to alt
  emit({ op: 'opcode', code: 'OP_DUP' });
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });   // alt: steps_copy
  emit({ op: 'swap' });
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });   // alt: steps_copy, endptAcc
  emit({ op: 'swap' });
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });   // alt: steps_copy, endptAcc, csum(top)
  // main: sig(1) steps(0)
  // pspD = pkSeedPadDepth - 2 (4 items removed, 2 remain = -2)
  // ta8D = ta8Depth - 2, kp4D = kp4Depth - 2

  // Split n-byte sig element
  emit({ op: 'swap' });
  emit({ op: 'push', value: BigInt(n) });
  emit({ op: 'opcode', code: 'OP_SPLIT' });         // steps sigElem sigRest
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });   // alt: ..., csum, sigRest(top)
  emit({ op: 'swap' });
  // main: sigElem(1) steps(0)
  // pspD = pkSeedPadDepth - 2 (since we went from 2 to 2 items via split+toalt+swap)

  // Compute hashAddr = 15 - steps (= digit) on main stack
  emit({ op: 'opcode', code: 'OP_DUP' });
  emit({ op: 'push', value: 15n });
  emit({ op: 'swap' });
  emit({ op: 'opcode', code: 'OP_SUB' });
  // main: sigElem(2) steps(1) hashAddr(0) — 3 items
  // pspD = pkSeedPadDepth - 1 (was pspD_base - 2, now 3 items instead of 2 = +1 => -1 total)
  const pspDChain = pkSeedPadDepth - 1;
  const ta8DChain = ta8Depth - 1;
  const kp4DChain = kp4Depth - 1;

  // Build 18-byte ADRS prefix using runtime treeAddr8 and keypair4
  // After emitBuildADRS18: +1 item on stack => 4 items: sigElem steps hashAddr prefix18
  emitBuildADRS18(emit, layer, SLH_WOTS_HASH, chainIdx, ta8DChain, kp4DChain);
  // pspD = pspDChain + 1 = pkSeedPadDepth
  // Save prefix18 to alt for loop reuse
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
  // main: sigElem(2) steps(1) hashAddr(0) — back to 3 items
  // pspD = pspDChain = pkSeedPadDepth - 1

  // Build then-ops for chain step
  // At step entry: sigElem(2) steps(1) hashAddr(0), 3 items above base
  // pspD at step entry = pkSeedPadDepth - 1
  const thenOps = slhChainStepThen(n, pspDChain);

  // 15 unrolled conditional hash iterations
  for (let j = 0; j < 15; j++) {
    emit({ op: 'over' });
    emit({ op: 'opcode', code: 'OP_0NOTEQUAL' });
    emit({ op: 'if', then: thenOps });
  }

  // endpoint(2) 0(1) finalHashAddr(0)
  emit({ op: 'drop' });
  emit({ op: 'drop' });
  // main: endpoint

  // Drop prefix from alt
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });
  emit({ op: 'drop' });

  // Restore from alt (LIFO): sigRest, csum, endptAcc, steps_copy
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // sigRest
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // csum
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // endptAcc
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // steps_copy
  // bottom->top: endpoint sigRest csum endptAcc steps_copy

  // csum += steps_copy: ROT top-3 to bring csum up
  emit({ op: 'rot' });
  emit({ op: 'opcode', code: 'OP_ADD' });

  // Cat endpoint to endptAcc
  emit({ op: 'swap' });
  emit({ op: 'push', value: 3n });
  emit({ op: 'roll', depth: 3 });
  emit({ op: 'opcode', code: 'OP_CAT' });
  // sigRest(2) newCsum(1) newEndptAcc(0)
}

// ===========================================================================
// Full WOTS+ Processing (all len chains)
// ===========================================================================
// Input:  psp(4) ta8(3) kp4(2) wotsSig(1) msg(0)
// Output: psp(3) ta8(2) kp4(1) wotsPk(0)

function emitSLHWotsAll(
  emit: (op: StackOp) => void,
  p: SLHCodegenParams, layer: number,
): void {
  const { n, len1, len2 } = p;

  // Input: psp(4) ta8(3) kp4(2) wotsSig(1) msg(0)
  // Rearrange: psp(6) ta8(5) kp4(4) sigRem(3) csum=0(2) endptAcc=empty(1) msgRem(0)
  emit({ op: 'swap' });
  emit({ op: 'push', value: 0n });
  emit({ op: 'opcode', code: 'OP_0' });
  emit({ op: 'push', value: 3n });
  emit({ op: 'roll', depth: 3 });
  // psp(6) ta8(5) kp4(4) sigRem(3) csum(2) endptAcc(1) msgRem(0)
  // pspD=6, ta8D=5, kp4D=4

  // Process n bytes -> 2*n message chains
  for (let byteIdx = 0; byteIdx < n; byteIdx++) {
    // State: psp(6) ta8(5) kp4(4) sigRem(3) csum(2) endptAcc(1) msgRem(0)
    if (byteIdx < n - 1) {
      emit({ op: 'push', value: 1n });
      emit({ op: 'opcode', code: 'OP_SPLIT' });
      emit({ op: 'swap' });
    }
    // Unsigned byte conversion
    emit({ op: 'push', value: 0n });
    emit({ op: 'push', value: 1n });
    emit({ op: 'opcode', code: 'OP_NUM2BIN' });
    emit({ op: 'opcode', code: 'OP_CAT' });
    emit({ op: 'opcode', code: 'OP_BIN2NUM' });
    // High/low nibbles
    emit({ op: 'opcode', code: 'OP_DUP' });
    emit({ op: 'push', value: 16n });
    emit({ op: 'opcode', code: 'OP_DIV' });
    emit({ op: 'swap' });
    emit({ op: 'push', value: 16n });
    emit({ op: 'opcode', code: 'OP_MOD' });
    // Stack: ..kp4 sig csum endptAcc [msgRest if non-last] hiNib loNib

    if (byteIdx < n - 1) {
      // Stack: psp ta8 kp4 sig csum endptAcc msgRest hiNib loNib
      emit({ op: 'opcode', code: 'OP_TOALTSTACK' }); // loNib -> alt
      emit({ op: 'swap' });                            // msgRest hiNib -> hiNib msgRest
      emit({ op: 'opcode', code: 'OP_TOALTSTACK' }); // msgRest -> alt
      // Stack: psp(6) ta8(5) kp4(4) sig(3) csum(2) endptAcc(1) hiNib(0)
      // pspD=6, ta8D=5, kp4D=4
    } else {
      // Stack: psp ta8 kp4 sig csum endptAcc hiNib loNib
      emit({ op: 'opcode', code: 'OP_TOALTSTACK' }); // loNib -> alt
      // Stack: psp(6) ta8(5) kp4(4) sig(3) csum(2) endptAcc(1) hiNib(0)
    }

    // First chain call (hiNib)
    // sig(3) csum(2) endptAcc(1) digit=hiNib(0), pspD=6, ta8D=5, kp4D=4
    emitSLHOneChainClean(emit, n, layer, byteIdx * 2, 6, 5, 4);
    // Output: sigRest(2) newCsum(1) newEndptAcc(0)
    // pspD=5, ta8D=4, kp4D=3

    if (byteIdx < n - 1) {
      // Restore loNib and msgRest from alt
      emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // msgRest
      emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // loNib
      emit({ op: 'swap' });
      emit({ op: 'opcode', code: 'OP_TOALTSTACK' }); // msgRest -> alt
      // Stack: psp(6) ta8(5) kp4(4) sigRest(3) newCsum(2) newEndptAcc(1) loNib(0)
    } else {
      emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // loNib
      // Stack: psp(6) ta8(5) kp4(4) sigRest(3) newCsum(2) newEndptAcc(1) loNib(0)
    }

    // Second chain call (loNib)
    emitSLHOneChainClean(emit, n, layer, byteIdx * 2 + 1, 6, 5, 4);
    // Output: sigRest(2) newCsum(1) newEndptAcc(0)
    // pspD=5, ta8D=4, kp4D=3

    if (byteIdx < n - 1) {
      // Restore msgRest from alt
      emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // msgRest
      // Stack: psp(6) ta8(5) kp4(4) sigRest(3) csum(2) endptAcc(1) msgRest(0)
    }
    // Back to shape: psp(6) ta8(5) kp4(4) sigRest(3) csum(2) endptAcc(1) msgRem(0)
  }

  // After all message chains: psp(5) ta8(4) kp4(3) sigRest(2) totalCsum(1) endptAcc(0)
  // Checksum digits (len2=3)
  emit({ op: 'swap' });
  // psp(5) ta8(4) kp4(3) sigRest(2) endptAcc(1) totalCsum(0)

  emit({ op: 'opcode', code: 'OP_DUP' });
  emit({ op: 'push', value: 16n });
  emit({ op: 'opcode', code: 'OP_MOD' });
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });

  emit({ op: 'opcode', code: 'OP_DUP' });
  emit({ op: 'push', value: 16n });
  emit({ op: 'opcode', code: 'OP_DIV' });
  emit({ op: 'push', value: 16n });
  emit({ op: 'opcode', code: 'OP_MOD' });
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });

  emit({ op: 'push', value: 256n });
  emit({ op: 'opcode', code: 'OP_DIV' });
  emit({ op: 'push', value: 16n });
  emit({ op: 'opcode', code: 'OP_MOD' });
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
  // psp(4) ta8(3) kp4(2) sigRest(1) endptAcc(0) | alt: d2, d1, d0(top)

  for (let ci = 0; ci < len2; ci++) {
    // psp(4) ta8(3) kp4(2) sigRest(1) endptAcc(0)
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' }); // endptAcc -> alt
    emit({ op: 'push', value: 0n });
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // endptAcc
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // digit
    // psp(6) ta8(5) kp4(4) sigRest(3) 0(2) endptAcc(1) digit(0)

    emitSLHOneChainClean(emit, n, layer, len1 + ci, 6, 5, 4);
    // sigRest(2) newCsum(1) newEndptAcc(0) — pspD=5, ta8D=4, kp4D=3

    emit({ op: 'swap' });
    emit({ op: 'drop' });
    // psp(4) ta8(3) kp4(2) sigRest(1) newEndptAcc(0)
  }

  // psp(4) ta8(3) kp4(2) empty(1) endptAcc(0)
  emit({ op: 'swap' });
  emit({ op: 'drop' });
  // psp(3) ta8(2) kp4(1) endptAcc(0)

  // Compress -> wotsPk via T(pkSeed, ADRS_WOTS_PK, endptAcc)
  // Build ADRS: ta8 at depth 2, keypair=0 (setType clears it, not restored per FIPS 205)
  emitBuildADRS(emit, layer, SLH_WOTS_PK, 0, 2, 'zero', 'zero');
  // psp(4) ta8(3) kp4(2) endptAcc(1) adrs22(0)
  emit({ op: 'swap' });
  // psp(4) ta8(3) kp4(2) adrs22(1) endptAcc(0)
  emitSLHT_raw(emit, n, 4);
  // psp(3) ta8(2) kp4(1) wotsPk(0)
}

// ===========================================================================
// 6. Merkle Auth Path Verification
// ===========================================================================
// Input:  psp(5) ta8(4) kp4(3) leafIdx(2) authPath(hp*n)(1) node(n)(0)
// Output: psp(2) ta8(1) kp4(0) root(top)... wait, Merkle consumes
//         leafIdx+authPath+node and produces root. psp/ta8/kp4 are below.
// Output: psp(3) ta8(2) kp4(1) root(0)

function emitSLHMerkle(
  emit: (op: StackOp) => void,
  p: SLHCodegenParams, layer: number,
): void {
  const { n, hp } = p;

  // Input: psp(5) ta8(4) kp4(3) leafIdx(2) authPath(1) node(0)
  // Move leafIdx to alt
  emit({ op: 'push', value: 2n });
  emit({ op: 'roll', depth: 2 });
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
  // psp(4) ta8(3) kp4(2) authPath(1) node(0) | alt: leafIdx

  for (let j = 0; j < hp; j++) {
    // psp(4) ta8(3) kp4(2) authPath(1) node(0)
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' });    // node -> alt

    emit({ op: 'push', value: BigInt(n) });
    emit({ op: 'opcode', code: 'OP_SPLIT' });
    emit({ op: 'swap' });                               // authPathRest authJ

    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });  // node
    // psp(4) ta8(3) kp4(2) authPathRest(2) authJ(1) node(0)

    // Get leafIdx
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });
    emit({ op: 'opcode', code: 'OP_DUP' });
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
    // psp(5) ta8(4) kp4(3) authPathRest(3) authJ(2) node(1) leafIdx(0)

    // bit = (leafIdx >> j) % 2
    if (j > 0) {
      emit({ op: 'push', value: BigInt(1 << j) });
      emit({ op: 'opcode', code: 'OP_DIV' });
    }
    emit({ op: 'push', value: 2n });
    emit({ op: 'opcode', code: 'OP_MOD' });

    // Build the tweakable hash ops for both branches.
    // After CAT in branch: authPathRest(1) children(0)
    // psp(4) ta8(3) kp4(2) authPathRest(1) children(0)
    // pspD=4, ta8D=3, kp4D=2

    // Need ADRS with hash = leafIdx >> (j+1) as 4-byte BE
    // Build hash: get leafIdx from alt, shift, convert to 4B BE
    const mkTweakHash: StackOp[] = collectOps(e => {
      // Stack in: authPathRest(1) children(0)
      // pspD=4, ta8D=3, kp4D=2

      // Get leafIdx from alt to compute hash
      e({ op: 'opcode', code: 'OP_FROMALTSTACK' });
      e({ op: 'opcode', code: 'OP_DUP' });
      e({ op: 'opcode', code: 'OP_TOALTSTACK' });
      // authPathRest(2) children(1) leafIdx(0); pspD=5, ta8D=4, kp4D=3
      if (j + 1 > 0) {
        e({ op: 'push', value: BigInt(1 << (j + 1)) });
        e({ op: 'opcode', code: 'OP_DIV' });
      }
      // Convert to 4-byte BE
      e({ op: 'push', value: 4n });
      e({ op: 'opcode', code: 'OP_NUM2BIN' });
      for (const op of emitReverseN(4)) e(op);
      // authPathRest(2) children(1) hash4BE(0); pspD=5, ta8D=4, kp4D=3

      // Build ADRS (22B) with hash='stack', keypair=0 (setType clears it per FIPS 205)
      emitBuildADRS(e, layer, SLH_TREE, j + 1, 4, 'zero', 'stack');
      // Net 0 (hash4 replaced by adrs22). pspD=5, ta8D=4, kp4D=3
      // authPathRest(2) children(1) adrs22(0)
      e({ op: 'swap' });
      // authPathRest(2) adrs22(1) children(0)
      // Now tweakable hash: adrs(1) msg(0) -> result. pspD=5
      emitSLHT_raw(e, n, 5);
      // authPathRest(1) result(0); pspD=4
    });

    emit({
      op: 'if',
      then: [
        // bit==1: authJ||node. Stack: authJ(1) node(0). CAT -> authJ||node.
        { op: 'opcode', code: 'OP_CAT' },
        ...mkTweakHash,
      ],
      else: [
        // bit==0: node||authJ. Stack: authJ(1) node(0). SWAP -> node(1) authJ(0). CAT -> node||authJ.
        { op: 'swap' },
        { op: 'opcode', code: 'OP_CAT' },
        ...mkTweakHash,
      ],
    });
    // psp(3) ta8(2) kp4(1) authPathRest(1) result(0) | alt: leafIdx
  }

  // Drop leafIdx from alt
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });
  emit({ op: 'drop' });

  // psp(3) ta8(2) kp4(1) authPathRest(empty)(1) root(0)
  emit({ op: 'swap' });
  emit({ op: 'drop' });
  // psp(3) ta8(2) kp4(1) root(0)... wait, 4 items total
  // After swap+drop: psp(2) ta8(1) kp4(0) root... no.
  // Let me recount. Before drop of leafIdx:
  // psp ta8 kp4 authPathRest root leafIdx(from alt) — after FROMALT, 6 items
  // DROP leafIdx: psp ta8 kp4 authPathRest root — 5 items
  // SWAP: psp ta8 kp4 root authPathRest
  // DROP: psp ta8 kp4 root — 4 items
  // psp(3) ta8(2) kp4(1) root(0)
}

// ===========================================================================
// 7. FORS Verification
// ===========================================================================
// Input:  psp(4) ta8(3) kp4(2) forsSig(1) md(0)
// Output: psp(2) ta8(1) kp4(0) forsPk(top)... let me recount.
// FORS consumes forsSig+md and produces forsPk.
// Output: psp(3) ta8(2) kp4(1) forsPk(0)

function emitSLHFors(
  emit: (op: StackOp) => void,
  p: SLHCodegenParams,
): void {
  const { n, a, k } = p;

  // Input: psp(4) ta8(3) kp4(2) forsSig(1) md(0)
  // Save md to alt, push empty rootAcc to alt
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });      // md -> alt
  emit({ op: 'opcode', code: 'OP_0' });
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });      // rootAcc(empty) -> alt
  // psp(3) ta8(2) kp4(1) forsSig(0) | alt: md, rootAcc(top)
  // pspD=3, ta8D=2, kp4D=1

  for (let i = 0; i < k; i++) {
    // psp(3) ta8(2) kp4(1) forsSigRem(0) | alt: md, rootAcc

    // Get md: pop rootAcc, pop md, dup md, push md back, push rootAcc back
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });  // rootAcc
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });  // md
    emit({ op: 'opcode', code: 'OP_DUP' });
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' });    // md back
    emit({ op: 'swap' });
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' });    // rootAcc back
    // psp(4) ta8(3) kp4(2) forsSigRem(1) md_copy(0)

    // Extract idx: `a` bits at position i*a from md_copy
    const bitStart = i * a;
    const byteStart = Math.floor(bitStart / 8);
    const bitOffset = bitStart % 8;
    const bitsInFirst = Math.min(8 - bitOffset, a);
    const take = a > bitsInFirst ? 2 : 1;

    if (byteStart > 0) {
      emit({ op: 'push', value: BigInt(byteStart) });
      emit({ op: 'opcode', code: 'OP_SPLIT' });
      emit({ op: 'opcode', code: 'OP_NIP' });
    }
    emit({ op: 'push', value: BigInt(take) });
    emit({ op: 'opcode', code: 'OP_SPLIT' });
    emit({ op: 'drop' });
    if (take > 1) { for (const op of emitReverseN(take)) emit(op); }
    emit({ op: 'push', value: 0n });
    emit({ op: 'push', value: 1n });
    emit({ op: 'opcode', code: 'OP_NUM2BIN' });
    emit({ op: 'opcode', code: 'OP_CAT' });
    emit({ op: 'opcode', code: 'OP_BIN2NUM' });
    const totalBits = take * 8;
    const rightShift = totalBits - bitOffset - a;
    if (rightShift > 0) {
      emit({ op: 'push', value: BigInt(1 << rightShift) });
      emit({ op: 'opcode', code: 'OP_DIV' });
    }
    // Use OP_MOD instead of OP_AND to avoid byte-length mismatch
    emit({ op: 'push', value: BigInt(1 << a) });
    emit({ op: 'opcode', code: 'OP_MOD' });
    // psp(4) ta8(3) kp4(2) forsSigRem(1) idx(0)

    // Save idx to alt (above rootAcc)
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
    // psp(3) ta8(2) kp4(1) forsSigRem(0) | alt: md, rootAcc, idx(top)

    // Split sk(n) from sigRem
    emit({ op: 'push', value: BigInt(n) });
    emit({ op: 'opcode', code: 'OP_SPLIT' });
    emit({ op: 'swap' });
    // psp(4) ta8(3) kp4(2) sigRest(1) sk(0)

    // Leaf = T(pkSeed, ADRS_FORS_TREE{chain=0, hash=runtime}, sk)
    // The FORS leaf hash index is: i * (1<<a) + idx
    // Need to get idx from alt, compute, convert to 4B BE, build ADRS
    // Get idx from alt (above rootAcc)
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // idx
    emit({ op: 'opcode', code: 'OP_DUP' });
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' }); // idx back
    // psp(5) ta8(4) kp4(3) sigRest(2) sk(1) idx(0)

    // Compute hash = i*(1<<a) + idx
    if (i > 0) {
      emit({ op: 'push', value: BigInt(i * (1 << a)) });
      emit({ op: 'opcode', code: 'OP_ADD' });
    }
    // Convert to 4B BE
    emit({ op: 'push', value: 4n });
    emit({ op: 'opcode', code: 'OP_NUM2BIN' });
    for (const op of emitReverseN(4)) emit(op);
    // psp(5) ta8(4) kp4(3) sigRest(2) sk(1) hash4BE(0)

    // Build ADRS with hash='stack': ta8D=4, kp4D=3
    emitBuildADRS(emit, 0, SLH_FORS_TREE, 0, 4, 3, 'stack');
    // hash4 replaced by adrs22. psp(5) ta8(4) kp4(3) sigRest(2) sk(1) adrs22(0)
    emit({ op: 'swap' });
    // psp(5) ta8(4) kp4(3) sigRest(2) adrs22(1) sk(0)
    emitSLHT_raw(emit, n, 5);
    // psp(4) ta8(3) kp4(2) sigRest(1) node(0)

    // Auth path walk: a levels
    for (let j = 0; j < a; j++) {
      // psp(4) ta8(3) kp4(2) sigRest(1) node(0)
      emit({ op: 'opcode', code: 'OP_TOALTSTACK' });  // node -> alt

      emit({ op: 'push', value: BigInt(n) });
      emit({ op: 'opcode', code: 'OP_SPLIT' });
      emit({ op: 'swap' });
      // sigRest authJ

      emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // node
      // psp(4) ta8(3) kp4(2) sigRest(2) authJ(1) node(0)

      // Get idx: pop from alt (idx is top of alt), dup, push back
      emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });
      emit({ op: 'opcode', code: 'OP_DUP' });
      emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
      // psp(5) ta8(4) kp4(3) sigRest(3) authJ(2) node(1) idx(0)

      // bit = (idx >> j) % 2
      if (j > 0) {
        emit({ op: 'push', value: BigInt(1 << j) });
        emit({ op: 'opcode', code: 'OP_DIV' });
      }
      emit({ op: 'push', value: 2n });
      emit({ op: 'opcode', code: 'OP_MOD' });

      // After if/then branches: CAT children -> children(0)
      // psp(4) ta8(3) kp4(2) sigRest(1) children(0)
      // Need tweakable hash with ADRS. hash = i*(1<<(a-j-1)) + (idx >> (j+1))
      const mkForsAuthHash: StackOp[] = collectOps(e => {
        // Stack: sigRest(1) children(0)
        // pspD=4, ta8D=3, kp4D=2

        // Get idx from alt to compute hash
        e({ op: 'opcode', code: 'OP_FROMALTSTACK' });
        e({ op: 'opcode', code: 'OP_DUP' });
        e({ op: 'opcode', code: 'OP_TOALTSTACK' });
        // sigRest(2) children(1) idx(0); pspD=5, ta8D=4, kp4D=3
        // hash = i*(1<<(a-j-1)) + (idx >> (j+1))
        if (j + 1 > 0) {
          e({ op: 'push', value: BigInt(1 << (j + 1)) });
          e({ op: 'opcode', code: 'OP_DIV' });
        }
        const base = i * (1 << (a - j - 1));
        if (base > 0) {
          e({ op: 'push', value: BigInt(base) });
          e({ op: 'opcode', code: 'OP_ADD' });
        }
        // Convert to 4B BE
        e({ op: 'push', value: 4n });
        e({ op: 'opcode', code: 'OP_NUM2BIN' });
        for (const op of emitReverseN(4)) e(op);
        // sigRest(2) children(1) hash4BE(0); ta8D=4, kp4D=3

        // Build ADRS with hash='stack'
        emitBuildADRS(e, 0, SLH_FORS_TREE, j + 1, 4, 3, 'stack');
        // sigRest(2) children(1) adrs22(0); pspD=5, ta8D=4, kp4D=3
        e({ op: 'swap' });
        emitSLHT_raw(e, n, 5);
        // sigRest(1) result(0); pspD=4
      });

      emit({
        op: 'if',
        then: [
          { op: 'opcode', code: 'OP_CAT' },
          ...mkForsAuthHash,
        ],
        else: [
          { op: 'swap' },
          { op: 'opcode', code: 'OP_CAT' },
          ...mkForsAuthHash,
        ],
      });
      // psp(4) ta8(3) kp4(2) sigRest(1) result(0)
    }

    // psp(4) ta8(3) kp4(2) sigRest(1) treeRoot(0) | alt: md, rootAcc, idx

    // Drop idx from alt
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });
    emit({ op: 'drop' });

    // Append treeRoot to rootAcc
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });  // rootAcc
    emit({ op: 'swap' });
    emit({ op: 'opcode', code: 'OP_CAT' });
    // psp(3) ta8(2) kp4(1) sigRest(1) newRootAcc(0)

    emit({ op: 'opcode', code: 'OP_TOALTSTACK' });    // rootAcc -> alt
    // psp(3) ta8(2) kp4(1) sigRest(0) | alt: md, newRootAcc
  }

  // Drop empty sigRest
  emit({ op: 'drop' });

  // Get rootAcc, drop md
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });    // rootAcc
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });    // md
  emit({ op: 'drop' });
  // psp(2) ta8(1) kp4(0) rootAcc(top)... wait:
  // psp ta8 kp4 rootAcc md -> after drop md: psp ta8 kp4 rootAcc
  // Actually: after FROMALT rootAcc and FROMALT md:
  // main: psp ta8 kp4 rootAcc md — 5 items
  // After DROP: psp ta8 kp4 rootAcc — 4 items
  // psp(3) ta8(2) kp4(1) rootAcc(0)

  // Compress: T(pkSeed, ADRS_FORS_ROOTS, rootAcc)
  // Build ADRS: ta8D=2, kp4D=1
  emitBuildADRS(emit, 0, SLH_FORS_ROOTS, 0, 2, 1, 'zero');
  // psp(4) ta8(3) kp4(2) rootAcc(1) adrs22(0)
  emit({ op: 'swap' });
  emitSLHT_raw(emit, n, 4);
  // psp(3) ta8(2) kp4(1) forsPk(0)
}

// ===========================================================================
// 8. Hmsg — Message Digest (SHA-256 MGF1)
// ===========================================================================
// Input:  R(3) pkSeed(2) pkRoot(1) msg(0)
// Output: digest(outLen bytes)

function emitSLHHmsg(
  emit: (op: StackOp) => void,
  _n: number, outLen: number,
): void {
  // CAT: R || pkSeed || pkRoot || msg
  emit({ op: 'opcode', code: 'OP_CAT' });
  emit({ op: 'opcode', code: 'OP_CAT' });
  emit({ op: 'opcode', code: 'OP_CAT' });
  emit({ op: 'opcode', code: 'OP_SHA256' });          // seed(32B)

  const blocks = Math.ceil(outLen / 32);
  if (blocks === 1) {
    emit({ op: 'push', value: new Uint8Array(4) });
    emit({ op: 'opcode', code: 'OP_CAT' });
    emit({ op: 'opcode', code: 'OP_SHA256' });
    if (outLen < 32) {
      emit({ op: 'push', value: BigInt(outLen) });
      emit({ op: 'opcode', code: 'OP_SPLIT' });
      emit({ op: 'drop' });
    }
  } else {
    emit({ op: 'opcode', code: 'OP_0' });             // seed resultAcc
    emit({ op: 'swap' });                               // resultAcc seed

    for (let ctr = 0; ctr < blocks; ctr++) {
      if (ctr < blocks - 1) {
        emit({ op: 'opcode', code: 'OP_DUP' });
      }
      const ctrBytes = new Uint8Array(4);
      ctrBytes[3] = ctr & 0xff;
      ctrBytes[2] = (ctr >>> 8) & 0xff;
      ctrBytes[1] = (ctr >>> 16) & 0xff;
      ctrBytes[0] = (ctr >>> 24) & 0xff;
      emit({ op: 'push', value: ctrBytes });
      emit({ op: 'opcode', code: 'OP_CAT' });
      emit({ op: 'opcode', code: 'OP_SHA256' });

      if (ctr === blocks - 1) {
        const rem = outLen - ctr * 32;
        if (rem < 32) {
          emit({ op: 'push', value: BigInt(rem) });
          emit({ op: 'opcode', code: 'OP_SPLIT' });
          emit({ op: 'drop' });
        }
      }

      if (ctr < blocks - 1) {
        emit({ op: 'rot' });
        emit({ op: 'swap' });
        emit({ op: 'opcode', code: 'OP_CAT' });
        emit({ op: 'swap' });
      } else {
        emit({ op: 'swap' });
        emit({ op: 'opcode', code: 'OP_CAT' });
      }
    }
  }
}

// ===========================================================================
// 9. Main Entry — emitVerifySLHDSA
// ===========================================================================
// Input:  msg(2) sig(1) pubkey(0)  [pubkey on top]
// Output: boolean

function emitVerifySLHDSA(
  emit: (op: StackOp) => void,
  paramKey: string,
): void {
  const p = SLH_PARAMS[paramKey];
  if (!p) throw new Error(`Unknown SLH-DSA params: ${paramKey}`);

  const { n, d, hp, k, a, len } = p;
  const forsSigLen = k * (1 + a) * n;
  const xmssSigLen = (len + hp) * n;
  const mdLen = Math.ceil((k * a) / 8);
  const treeIdxLen = Math.ceil((p.h - hp) / 8);
  const leafIdxLen = Math.ceil(hp / 8);
  const digestLen = mdLen + treeIdxLen + leafIdxLen;

  const t = new SLHTracker(['msg', 'sig', 'pubkey'], emit);

  // ---- 1. Parse pubkey -> pkSeed, pkRoot ----
  t.toTop('pubkey');
  t.pushInt(null, BigInt(n));
  t.split('pkSeed', 'pkRoot');

  // Build pkSeedPad = pkSeed || zeros(64-n), keep on main stack
  t.copyToTop('pkSeed', '_psp');
  if (64 - n > 0) {
    t.pushBytes(null, new Uint8Array(64 - n));
    t.cat('_pkSeedPad');
  } else {
    t.rename('_pkSeedPad');
  }
  // _pkSeedPad stays on main stack (tracked)

  // ---- 2. Parse R from sig ----
  t.toTop('sig');
  t.pushInt(null, BigInt(n));
  t.split('R', 'sigRest');

  // ---- 3. Compute Hmsg(R, pkSeed, pkRoot, msg) ----
  t.copyToTop('R', '_R');
  t.copyToTop('pkSeed', '_pks');
  t.copyToTop('pkRoot', '_pkr');
  t.copyToTop('msg', '_msg');
  t.rawBlock(['_R', '_pks', '_pkr', '_msg'], 'digest', (e) => {
    emitSLHHmsg(e, n, digestLen);
  });

  // ---- 4. Extract md, treeIdx, leafIdx ----
  t.toTop('digest');
  t.pushInt(null, BigInt(mdLen));
  t.split('md', '_drest');

  t.toTop('_drest');
  t.pushInt(null, BigInt(treeIdxLen));
  t.split('_treeBytes', '_leafBytes');

  // Convert _treeBytes -> treeIdx
  t.toTop('_treeBytes');
  t.rawBlock(['_treeBytes'], 'treeIdx', (e) => {
    if (treeIdxLen > 1) { for (const op of emitReverseN(treeIdxLen)) e(op); }
    e({ op: 'push', value: 0n });
    e({ op: 'push', value: 1n });
    e({ op: 'opcode', code: 'OP_NUM2BIN' });
    e({ op: 'opcode', code: 'OP_CAT' });
    e({ op: 'opcode', code: 'OP_BIN2NUM' });
    // Use OP_MOD instead of OP_AND to avoid byte-length mismatch
    const modulus = 1n << BigInt(p.h - hp);
    e({ op: 'push', value: modulus });
    e({ op: 'opcode', code: 'OP_MOD' });
  });

  // Convert _leafBytes -> leafIdx
  t.toTop('_leafBytes');
  t.rawBlock(['_leafBytes'], 'leafIdx', (e) => {
    if (leafIdxLen > 1) { for (const op of emitReverseN(leafIdxLen)) e(op); }
    e({ op: 'push', value: 0n });
    e({ op: 'push', value: 1n });
    e({ op: 'opcode', code: 'OP_NUM2BIN' });
    e({ op: 'opcode', code: 'OP_CAT' });
    e({ op: 'opcode', code: 'OP_BIN2NUM' });
    e({ op: 'push', value: BigInt(1 << hp) });
    e({ op: 'opcode', code: 'OP_MOD' });
  });

  // ---- 4b. Compute treeAddr8 and keypair4 for ADRS construction ----
  // treeAddr8 = treeIdx as 8-byte big-endian
  t.copyToTop('treeIdx', '_ti8');
  t.rawBlock(['_ti8'], 'treeAddr8', (e) => {
    e({ op: 'push', value: 8n });
    e({ op: 'opcode', code: 'OP_NUM2BIN' });
    for (const op of emitReverseN(8)) e(op);
  });

  // keypair4 = leafIdx as 4-byte big-endian
  t.copyToTop('leafIdx', '_li4');
  t.rawBlock(['_li4'], 'keypair4', (e) => {
    e({ op: 'push', value: 4n });
    e({ op: 'opcode', code: 'OP_NUM2BIN' });
    for (const op of emitReverseN(4)) e(op);
  });

  // ---- 5. Parse FORS sig ----
  t.toTop('sigRest');
  t.pushInt(null, BigInt(forsSigLen));
  t.split('forsSig', 'htSigRest');

  // ---- 6. FORS -> forsPk ----
  // Copy psp/ta8/kp4 to top, then forsSig, md
  t.copyToTop('_pkSeedPad', '_psp');
  t.copyToTop('treeAddr8', '_ta');
  t.copyToTop('keypair4', '_kp');
  t.toTop('forsSig');
  t.toTop('md');
  t.rawBlock(['_psp', '_ta', '_kp', 'forsSig', 'md'], 'forsPk', (e) => {
    // Stack: psp(4) ta8(3) kp4(2) forsSig(1) md(0)
    emitSLHFors(e, p);
    // Stack: psp(3) ta8(2) kp4(1) forsPk(0)
    // Drop psp, ta8, kp4
    e({ op: 'opcode', code: 'OP_TOALTSTACK' }); // forsPk -> alt
    e({ op: 'drop' }); // kp4
    e({ op: 'drop' }); // ta8
    e({ op: 'drop' }); // psp
    e({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // forsPk back
  });

  // ---- 7. Hypertree: d layers ----
  for (let layer = 0; layer < d; layer++) {
    // Split xmssSig from htSigRest
    t.toTop('htSigRest');
    t.pushInt(null, BigInt(xmssSigLen));
    t.split(`xsig${layer}`, 'htSigRest');

    // Split wotsSig and authPath
    t.toTop(`xsig${layer}`);
    t.pushInt(null, BigInt(len * n));
    t.split(`wsig${layer}`, `auth${layer}`);

    // WOTS+: copy psp/ta8/kp4 + wotsSig + currentMsg -> wotsPk
    const curMsg = layer === 0 ? 'forsPk' : `root${layer - 1}`;
    t.copyToTop('_pkSeedPad', '_psp');
    t.copyToTop('treeAddr8', '_ta');
    t.copyToTop('keypair4', '_kp');
    t.toTop(`wsig${layer}`);
    t.toTop(curMsg);
    t.rawBlock(['_psp', '_ta', '_kp', `wsig${layer}`, curMsg], `wpk${layer}`, (e) => {
      // Stack: psp(4) ta8(3) kp4(2) wotsSig(1) msg(0)
      emitSLHWotsAll(e, p, layer);
      // Stack: psp(3) ta8(2) kp4(1) wotsPk(0)
      e({ op: 'opcode', code: 'OP_TOALTSTACK' });
      e({ op: 'drop' }); e({ op: 'drop' }); e({ op: 'drop' });
      e({ op: 'opcode', code: 'OP_FROMALTSTACK' });
    });

    // Merkle: copy psp/ta8/kp4 + leafIdx + authPath + wotsPk -> root
    t.copyToTop('_pkSeedPad', '_psp');
    t.copyToTop('treeAddr8', '_ta');
    t.copyToTop('keypair4', '_kp');
    t.toTop('leafIdx');
    t.toTop(`auth${layer}`);
    t.toTop(`wpk${layer}`);
    t.rawBlock(['_psp', '_ta', '_kp', 'leafIdx', `auth${layer}`, `wpk${layer}`], `root${layer}`, (e) => {
      // Stack: psp(5) ta8(4) kp4(3) leafIdx(2) authPath(1) node(0)
      emitSLHMerkle(e, p, layer);
      // Stack: psp(3) ta8(2) kp4(1) root(0)
      e({ op: 'opcode', code: 'OP_TOALTSTACK' });
      e({ op: 'drop' }); e({ op: 'drop' }); e({ op: 'drop' });
      e({ op: 'opcode', code: 'OP_FROMALTSTACK' });
    });

    // Update leafIdx, treeIdx, treeAddr8, keypair4 for next layer
    if (layer < d - 1) {
      t.toTop('treeIdx');
      t.dup('_tic');
      // leafIdx = _tic % (1 << hp)
      t.rawBlock(['_tic'], 'leafIdx', (e) => {
        e({ op: 'push', value: BigInt(1 << hp) });
        e({ op: 'opcode', code: 'OP_MOD' });
      });
      // treeIdx = treeIdx >> hp
      t.swap();
      t.rawBlock(['treeIdx'], 'treeIdx', (e) => {
        e({ op: 'push', value: BigInt(1 << hp) });
        e({ op: 'opcode', code: 'OP_DIV' });
      });

      // Update treeAddr8 = new treeIdx as 8-byte BE
      // Drop old treeAddr8
      t.toTop('treeAddr8');
      t.drop();
      t.copyToTop('treeIdx', '_ti8');
      t.rawBlock(['_ti8'], 'treeAddr8', (e) => {
        e({ op: 'push', value: 8n });
        e({ op: 'opcode', code: 'OP_NUM2BIN' });
        for (const op of emitReverseN(8)) e(op);
      });

      // Update keypair4 = new leafIdx as 4-byte BE
      // Drop old keypair4
      t.toTop('keypair4');
      t.drop();
      t.copyToTop('leafIdx', '_li4');
      t.rawBlock(['_li4'], 'keypair4', (e) => {
        e({ op: 'push', value: 4n });
        e({ op: 'opcode', code: 'OP_NUM2BIN' });
        for (const op of emitReverseN(4)) e(op);
      });
    }
  }

  // ---- 8. Compare root to pkRoot ----
  t.toTop(`root${d - 1}`);
  t.toTop('pkRoot');
  t.equal('_result');

  // ---- 9. Cleanup ----
  t.toTop('_result');
  t.toAlt();

  // Drop all remaining tracked values
  const leftover = ['msg', 'R', 'pkSeed', 'htSigRest', 'treeIdx', 'leafIdx',
    '_pkSeedPad', 'treeAddr8', 'keypair4'];
  for (const nm of leftover) {
    if (t.has(nm)) { t.toTop(nm); t.drop(); }
  }
  while (t.depth > 0) t.drop();

  t.fromAlt('_result');
}

// ===========================================================================
// Exports
// ===========================================================================

export {
  SLH_PARAMS,
  slhADRS,
  slhADRS18,
  SLHTracker,
  emitSLHT,
  emitSLHT_raw,
  slhChainStepThen,
  emitSLHOneChainClean as emitSLHOneChain,
  emitSLHWotsAll,
  emitSLHMerkle,
  emitSLHFors,
  emitSLHHmsg,
  emitVerifySLHDSA,
  emitBuildADRS,
  emitBuildADRS18,
};

export type { SLHCodegenParams };
