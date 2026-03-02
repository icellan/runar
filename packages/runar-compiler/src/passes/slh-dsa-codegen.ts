/**
 * SLH-DSA (FIPS 205) Bitcoin Script codegen for the Rúnar stack lowerer.
 *
 * Splice into LoweringContext in 05-stack-lower.ts. All helpers self-contained.
 * Entry: lowerVerifySLHDSA() → calls emitVerifySLHDSA().
 *
 * Alt-stack convention: pkSeedPad (64 bytes) on alt permanently.
 * Tweakable hash pops pkSeedPad, DUPs, pushes copy back, uses original.
 *
 * Compile-time ADRS: treeAddr=0, keypair=0 where runtime values needed.
 * WOTS+ chain hashAddress built dynamically from a counter on the stack.
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
// pkSeedPad on alt; pop, DUP, push back, use.

/** Tracked tweakable hash. */
function emitSLHT(
  t: SLHTracker, n: number,
  adrs: string, msg: string, result: string,
): void {
  t.toTop(adrs);
  t.toTop(msg);
  t.cat('_am');
  t.fromAlt('_psp');
  t.dup('_psp2');
  t.toAlt();
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

/** Raw tweakable hash. Stack: adrsC(1) msg(0) -> result(n). pkSeedPad on alt. */
function emitSLHT_raw(e: (op: StackOp) => void, n: number): void {
  e({ op: 'opcode', code: 'OP_CAT' });
  e({ op: 'opcode', code: 'OP_FROMALTSTACK' });
  e({ op: 'opcode', code: 'OP_DUP' });
  e({ op: 'opcode', code: 'OP_TOALTSTACK' });
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
 * Exit:  newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
 */
function slhChainStepThen(adrsPrefix: Uint8Array, n: number): StackOp[] {
  const ops: StackOp[] = [];
  // DUP hashAddr before consuming it in ADRS construction
  ops.push({ op: 'dup' });
  // sigElem(3) steps(2) hashAddr(1) hashAddr_copy(0)
  // Convert copy to 4-byte big-endian
  ops.push({ op: 'push', value: 4n });
  ops.push({ op: 'opcode', code: 'OP_NUM2BIN' });
  ops.push({ op: 'opcode', code: 'OP_REVERSE' });
  // Build ADRS = prefix(18) || hashAddrBE(4)
  ops.push({ op: 'push', value: adrsPrefix });
  ops.push({ op: 'swap' });
  ops.push({ op: 'opcode', code: 'OP_CAT' });
  // sigElem(3) steps(2) hashAddr(1) adrsC(0)
  // Move sigElem to top: ROLL 3
  ops.push({ op: 'push', value: 3n });
  ops.push({ op: 'roll', depth: 3 });
  // steps(2) hashAddr(1) adrsC(0) sigElem(top)
  // CAT: adrsC(1) || sigElem(0) -> adrsC||sigElem
  ops.push({ op: 'opcode', code: 'OP_CAT' });
  // steps(1) hashAddr(0) (adrsC||sigElem)(top)
  // pkSeedPad from alt
  ops.push({ op: 'opcode', code: 'OP_FROMALTSTACK' });
  ops.push({ op: 'opcode', code: 'OP_DUP' });
  ops.push({ op: 'opcode', code: 'OP_TOALTSTACK' });
  // steps(2) hashAddr(1) (adrsC||sigElem)(0) pkSeedPad(top)
  ops.push({ op: 'swap' });
  // steps(2) hashAddr(1) pkSeedPad(0) (adrsC||sigElem)(top)
  // CAT: pkSeedPad || (adrsC||sigElem)
  ops.push({ op: 'opcode', code: 'OP_CAT' });
  ops.push({ op: 'opcode', code: 'OP_SHA256' });
  if (n < 32) {
    ops.push({ op: 'push', value: BigInt(n) });
    ops.push({ op: 'opcode', code: 'OP_SPLIT' });
    ops.push({ op: 'drop' });
  }
  // steps(2) hashAddr(1) newSigElem(0)
  // Rearrange -> newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
  // ROT: brings steps(depth 2) to top
  ops.push({ op: 'rot' });
  // hashAddr(1) newSigElem(0) steps(top)
  ops.push({ op: 'opcode', code: 'OP_1SUB' });
  // hashAddr(1) newSigElem(0) (steps-1)(top)
  // ROT: brings hashAddr(depth 2) to top
  ops.push({ op: 'rot' });
  // newSigElem(1) (steps-1)(0) hashAddr(top)
  ops.push({ op: 'opcode', code: 'OP_1ADD' });
  // newSigElem(1) (steps-1)(0) (hashAddr+1)(top)
  // Need: newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
  // Save (hashAddr+1), swap bottom two, restore
  ops.push({ op: 'opcode', code: 'OP_TOALTSTACK' });
  ops.push({ op: 'swap' });
  ops.push({ op: 'opcode', code: 'OP_FROMALTSTACK' });
  // newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
  return ops;
}

/**
 * One WOTS+ chain with tweakable hashing (raw opcodes).
 *
 * Input:  sig(3) csum(2) endptAcc(1) digit(0)
 * Output: sigRest(2) newCsum(1) newEndptAcc(0)
 * Alt: pkSeedPad persists. 4 internal push/pop balanced.
 */
function emitSLHOneChainClean(
  emit: (op: StackOp) => void,
  n: number, layer: number, chainIdx: number,
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

  // Split n-byte sig element
  emit({ op: 'swap' });
  emit({ op: 'push', value: BigInt(n) });
  emit({ op: 'opcode', code: 'OP_SPLIT' });         // steps sigElem sigRest
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });   // alt: ..., csum, sigRest(top)
  emit({ op: 'swap' });
  // main: sigElem(1) steps(0)

  // Compute hashAddr = 15 - steps (= digit) on main stack
  emit({ op: 'opcode', code: 'OP_DUP' });
  emit({ op: 'push', value: 15n });
  emit({ op: 'swap' });
  emit({ op: 'opcode', code: 'OP_SUB' });
  // main: sigElem(2) steps(1) hashAddr(0)

  // Build ADRS prefix for this chain
  const prefix = slhADRS18({ layer, type: SLH_WOTS_HASH, chain: chainIdx });
  const thenOps = slhChainStepThen(prefix, n);

  // 15 unrolled conditional hash iterations
  for (let j = 0; j < 15; j++) {
    // sigElem(2) steps(1) hashAddr(0)
    // Check steps > 0: OVER copies steps (depth 1) to top
    emit({ op: 'over' });
    emit({ op: 'opcode', code: 'OP_0NOTEQUAL' });
    emit({ op: 'if', then: thenOps });
  }

  // endpoint(2) 0(1) finalHashAddr(0)
  emit({ op: 'drop' });
  emit({ op: 'drop' });
  // main: endpoint

  // Restore from alt (LIFO): sigRest, csum, endptAcc, steps_copy
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // sigRest
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // csum
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // endptAcc
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // steps_copy
  // bottom->top: endpoint sigRest csum endptAcc steps_copy

  // csum += steps_copy: ROT top-3 to bring csum up
  emit({ op: 'rot' });
  // ... endptAcc steps_copy csum -> after rot of top-3: steps_copy csum endptAcc
  // Wait. Top-3 are csum(2) endptAcc(1) steps_copy(0). ROT brings csum to top.
  // No. ROT brings depth-2 of the top-3 to top.
  // The full stack (bottom->top): endpoint, sigRest, csum, endptAcc, steps_copy
  // Top-3: csum(depth 2 in top-3), endptAcc(depth 1), steps_copy(depth 0 = top)
  // ROT brings csum to top: endpoint sigRest endptAcc steps_copy csum
  emit({ op: 'opcode', code: 'OP_ADD' });
  // endpoint sigRest endptAcc newCsum

  // Cat endpoint to endptAcc
  emit({ op: 'swap' });
  // endpoint sigRest newCsum endptAcc
  emit({ op: 'push', value: 3n });
  emit({ op: 'roll', depth: 3 });
  // sigRest newCsum endptAcc endpoint
  emit({ op: 'opcode', code: 'OP_CAT' });
  // sigRest(2) newCsum(1) newEndptAcc(0)
}

// ===========================================================================
// Full WOTS+ Processing (all len chains)
// ===========================================================================
// Input:  wotsSig(len*n)(1) msg(n)(0)
// Output: wotsPk(n)

function emitSLHWotsAll(
  emit: (op: StackOp) => void,
  p: SLHCodegenParams, layer: number,
): void {
  const { n, len1, len2 } = p;

  // Rearrange: sigRem(3) csum=0(2) endptAcc=empty(1) msgRem(0)
  emit({ op: 'swap' });
  emit({ op: 'push', value: 0n });
  emit({ op: 'opcode', code: 'OP_0' });
  emit({ op: 'push', value: 3n });
  emit({ op: 'roll', depth: 3 });

  // Process n bytes -> 2*n message chains
  for (let byteIdx = 0; byteIdx < n; byteIdx++) {
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

    if (byteIdx < n - 1) {
      emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
      emit({ op: 'swap' });
      emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
    } else {
      emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
    }

    emitSLHOneChainClean(emit, n, layer, byteIdx * 2);

    if (byteIdx < n - 1) {
      emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });
      emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });
      emit({ op: 'swap' });
      emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
    } else {
      emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });
    }

    emitSLHOneChainClean(emit, n, layer, byteIdx * 2 + 1);

    if (byteIdx < n - 1) {
      emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });
    }
  }

  // sigRest(2) totalCsum(1) endptAcc(0)
  // Checksum digits (len2=3)
  emit({ op: 'swap' });

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

  // sigRest(1) endptAcc(0) | alt: ..., d2, d1, d0(top)
  for (let ci = 0; ci < len2; ci++) {
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
    emit({ op: 'push', value: 0n });
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });

    emitSLHOneChainClean(emit, n, layer, len1 + ci);

    emit({ op: 'swap' });
    emit({ op: 'drop' });
  }

  // empty(1) endptAcc(0)
  emit({ op: 'swap' });
  emit({ op: 'drop' });

  // Compress -> wotsPk via T(pkSeed, ADRS_WOTS_PK, endptAcc)
  const pkAdrs = slhADRS({ layer, type: SLH_WOTS_PK });
  emit({ op: 'push', value: pkAdrs });
  emit({ op: 'swap' });
  emitSLHT_raw(emit, n);
}

// ===========================================================================
// 6. Merkle Auth Path Verification
// ===========================================================================
// Input:  leafIdx(2) authPath(hp*n)(1) node(n)(0)
// Output: root(n)

function emitSLHMerkle(
  emit: (op: StackOp) => void,
  p: SLHCodegenParams, layer: number,
): void {
  const { n, hp } = p;

  // Move leafIdx to alt
  emit({ op: 'push', value: 2n });
  emit({ op: 'roll', depth: 2 });
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
  // authPath(1) node(0) | alt: ..., leafIdx

  for (let j = 0; j < hp; j++) {
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' });    // node -> alt

    emit({ op: 'push', value: BigInt(n) });
    emit({ op: 'opcode', code: 'OP_SPLIT' });
    emit({ op: 'swap' });                               // authPathRest authJ

    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });  // node
    // authPathRest(2) authJ(1) node(0)

    // Get leafIdx
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });
    emit({ op: 'opcode', code: 'OP_DUP' });
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
    // authPathRest(3) authJ(2) node(1) leafIdx(0)

    // bit = (leafIdx >> j) & 1
    if (j > 0) {
      emit({ op: 'push', value: BigInt(j) });
      emit({ op: 'opcode', code: 'OP_RSHIFT' });
    }
    emit({ op: 'push', value: 1n });
    emit({ op: 'opcode', code: 'OP_AND' });

    const adrs = slhADRS({ layer, type: SLH_TREE, chain: j + 1, hash: 0 });

    const mkTweakHash: StackOp[] = [
      { op: 'push', value: adrs },
      { op: 'swap' },
      { op: 'opcode', code: 'OP_CAT' },
      { op: 'opcode', code: 'OP_FROMALTSTACK' },
      { op: 'opcode', code: 'OP_DUP' },
      { op: 'opcode', code: 'OP_TOALTSTACK' },
      { op: 'swap' },
      { op: 'opcode', code: 'OP_CAT' },
      { op: 'opcode', code: 'OP_SHA256' },
      ...(n < 32 ? [
        { op: 'push', value: BigInt(n) } as StackOp,
        { op: 'opcode', code: 'OP_SPLIT' } as StackOp,
        { op: 'drop' } as StackOp,
      ] : []),
    ];

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
  }

  // Drop leafIdx from alt
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });
  emit({ op: 'drop' });

  // authPathRest(empty)(1) root(0)
  emit({ op: 'swap' });
  emit({ op: 'drop' });
}

// ===========================================================================
// 7. FORS Verification
// ===========================================================================
// Input:  forsSig(k*(1+a)*n)(1) md(ceil(k*a/8))(0)
// Output: forsPk(n)

function emitSLHFors(
  emit: (op: StackOp) => void,
  p: SLHCodegenParams,
): void {
  const { n, a, k } = p;

  // Save md to alt, push empty rootAcc to alt
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });      // md -> alt
  emit({ op: 'opcode', code: 'OP_0' });
  emit({ op: 'opcode', code: 'OP_TOALTSTACK' });      // rootAcc(empty) -> alt
  // main: forsSig | alt: pkSeedPad, md, rootAcc(top)

  for (let i = 0; i < k; i++) {
    // main: forsSigRem | alt: pkSeedPad, md, rootAcc

    // Get md: pop rootAcc, pop md, dup md, push md back, push rootAcc back
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });  // rootAcc
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });  // md
    emit({ op: 'opcode', code: 'OP_DUP' });
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' });    // md back
    emit({ op: 'swap' });
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' });    // rootAcc back
    // main: forsSigRem md_copy

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
    if (take > 1) emit({ op: 'opcode', code: 'OP_REVERSE' });
    emit({ op: 'push', value: 0n });
    emit({ op: 'push', value: 1n });
    emit({ op: 'opcode', code: 'OP_NUM2BIN' });
    emit({ op: 'opcode', code: 'OP_CAT' });
    emit({ op: 'opcode', code: 'OP_BIN2NUM' });
    const totalBits = take * 8;
    const rightShift = totalBits - bitOffset - a;
    if (rightShift > 0) {
      emit({ op: 'push', value: BigInt(rightShift) });
      emit({ op: 'opcode', code: 'OP_RSHIFT' });
    }
    emit({ op: 'push', value: BigInt((1 << a) - 1) });
    emit({ op: 'opcode', code: 'OP_AND' });
    // main: forsSigRem idx

    // Save idx to alt (above rootAcc)
    emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
    // main: forsSigRem | alt: ..., md, rootAcc, idx(top)

    // Split sk(n) from sigRem
    emit({ op: 'push', value: BigInt(n) });
    emit({ op: 'opcode', code: 'OP_SPLIT' });
    emit({ op: 'swap' });
    // main: sigRest sk

    // Leaf = T(pkSeed, ADRS_FORS_TREE{h=0}, sk)
    const leafAdrs = slhADRS({ type: SLH_FORS_TREE, chain: 0, hash: 0 });
    emit({ op: 'push', value: leafAdrs });
    emit({ op: 'swap' });
    emitSLHT_raw(emit, n);
    // main: sigRest(1) node(0)

    // Auth path walk: a levels
    for (let j = 0; j < a; j++) {
      // sigRest(1) node(0)
      emit({ op: 'opcode', code: 'OP_TOALTSTACK' });  // node -> alt

      emit({ op: 'push', value: BigInt(n) });
      emit({ op: 'opcode', code: 'OP_SPLIT' });
      emit({ op: 'swap' });
      // sigRest authJ

      emit({ op: 'opcode', code: 'OP_FROMALTSTACK' }); // node
      // sigRest(2) authJ(1) node(0)

      // Get idx: pop from alt (idx is top of alt), dup, push back
      emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });
      emit({ op: 'opcode', code: 'OP_DUP' });
      emit({ op: 'opcode', code: 'OP_TOALTSTACK' });
      // sigRest(3) authJ(2) node(1) idx(0)

      // bit = (idx >> j) & 1
      if (j > 0) {
        emit({ op: 'push', value: BigInt(j) });
        emit({ op: 'opcode', code: 'OP_RSHIFT' });
      }
      emit({ op: 'push', value: 1n });
      emit({ op: 'opcode', code: 'OP_AND' });

      const levelAdrs = slhADRS({ type: SLH_FORS_TREE, chain: j + 1, hash: 0 });

      const hashTail: StackOp[] = [
        { op: 'push', value: levelAdrs },
        { op: 'swap' },
        { op: 'opcode', code: 'OP_CAT' },
        { op: 'opcode', code: 'OP_FROMALTSTACK' },
        { op: 'opcode', code: 'OP_DUP' },
        { op: 'opcode', code: 'OP_TOALTSTACK' },
        { op: 'swap' },
        { op: 'opcode', code: 'OP_CAT' },
        { op: 'opcode', code: 'OP_SHA256' },
        ...(n < 32 ? [
          { op: 'push', value: BigInt(n) } as StackOp,
          { op: 'opcode', code: 'OP_SPLIT' } as StackOp,
          { op: 'drop' } as StackOp,
        ] : []),
      ];

      emit({
        op: 'if',
        then: [
          { op: 'opcode', code: 'OP_CAT' },
          ...hashTail,
        ],
        else: [
          { op: 'swap' },
          { op: 'opcode', code: 'OP_CAT' },
          ...hashTail,
        ],
      });
    }

    // sigRest(1) treeRoot(0) | alt: ..., md, rootAcc, idx

    // Drop idx from alt
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });
    emit({ op: 'drop' });

    // Append treeRoot to rootAcc
    emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });  // rootAcc
    emit({ op: 'swap' });
    emit({ op: 'opcode', code: 'OP_CAT' });
    // main: sigRest(1) newRootAcc(0)

    emit({ op: 'opcode', code: 'OP_TOALTSTACK' });    // rootAcc -> alt
    // main: sigRest | alt: ..., md, newRootAcc
  }

  // Drop empty sigRest
  emit({ op: 'drop' });

  // Get rootAcc, drop md
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });    // rootAcc
  emit({ op: 'opcode', code: 'OP_FROMALTSTACK' });    // md
  emit({ op: 'drop' });
  // main: rootAcc(k*n)

  // Compress: T(pkSeed, ADRS_FORS_ROOTS, rootAcc)
  const forsAdrs = slhADRS({ type: SLH_FORS_ROOTS });
  emit({ op: 'push', value: forsAdrs });
  emit({ op: 'swap' });
  emitSLHT_raw(emit, n);
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

  // Build pkSeedPad = pkSeed || zeros(64-n), push to alt
  t.copyToTop('pkSeed', '_psp');
  if (64 - n > 0) {
    t.pushBytes(null, new Uint8Array(64 - n));
    t.cat('_pkSeedPad');
  } else {
    t.rename('_pkSeedPad');
  }
  t.toAlt();

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
    if (treeIdxLen > 1) e({ op: 'opcode', code: 'OP_REVERSE' });
    e({ op: 'push', value: 0n });
    e({ op: 'push', value: 1n });
    e({ op: 'opcode', code: 'OP_NUM2BIN' });
    e({ op: 'opcode', code: 'OP_CAT' });
    e({ op: 'opcode', code: 'OP_BIN2NUM' });
    const mask = (1n << BigInt(p.h - hp)) - 1n;
    e({ op: 'push', value: mask });
    e({ op: 'opcode', code: 'OP_AND' });
  });

  // Convert _leafBytes -> leafIdx
  t.toTop('_leafBytes');
  t.rawBlock(['_leafBytes'], 'leafIdx', (e) => {
    if (leafIdxLen > 1) e({ op: 'opcode', code: 'OP_REVERSE' });
    e({ op: 'push', value: 0n });
    e({ op: 'push', value: 1n });
    e({ op: 'opcode', code: 'OP_NUM2BIN' });
    e({ op: 'opcode', code: 'OP_CAT' });
    e({ op: 'opcode', code: 'OP_BIN2NUM' });
    e({ op: 'push', value: BigInt((1 << hp) - 1) });
    e({ op: 'opcode', code: 'OP_AND' });
  });

  // ---- 5. Parse FORS sig ----
  t.toTop('sigRest');
  t.pushInt(null, BigInt(forsSigLen));
  t.split('forsSig', 'htSigRest');

  // ---- 6. FORS -> forsPk ----
  t.toTop('forsSig');
  t.toTop('md');
  t.rawBlock(['forsSig', 'md'], 'forsPk', (e) => {
    emitSLHFors(e, p);
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

    // WOTS+: wotsSig + currentMsg -> wotsPk
    const curMsg = layer === 0 ? 'forsPk' : `root${layer - 1}`;
    t.toTop(`wsig${layer}`);
    t.toTop(curMsg);
    t.rawBlock([`wsig${layer}`, curMsg], `wpk${layer}`, (e) => {
      emitSLHWotsAll(e, p, layer);
    });

    // Merkle: leafIdx + authPath + wotsPk -> root
    t.toTop('leafIdx');
    t.toTop(`auth${layer}`);
    t.toTop(`wpk${layer}`);
    t.rawBlock(['leafIdx', `auth${layer}`, `wpk${layer}`], `root${layer}`, (e) => {
      emitSLHMerkle(e, p, layer);
    });

    // Update leafIdx, treeIdx for next layer
    if (layer < d - 1) {
      t.toTop('treeIdx');
      t.dup('_tic');
      t.pushInt(null, BigInt((1 << hp) - 1));
      t.op('OP_AND');
      t.rename('leafIdx');

      t.toTop('_tic');
      t.pushInt(null, BigInt(hp));
      t.op('OP_RSHIFT');
      t.rename('treeIdx');
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
  const leftover = ['msg', 'R', 'pkSeed', 'htSigRest', 'treeIdx', 'leafIdx'];
  for (const nm of leftover) {
    if (t.has(nm)) { t.toTop(nm); t.drop(); }
  }
  while (t.depth > 0) t.drop();

  t.fromAlt('_result');
  // Pop pkSeedPad from alt
  t.fromAlt(null);
  t.drop();
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
};

export type { SLHCodegenParams };

// ===========================================================================
// Integration with LoweringContext (05-stack-lower.ts)
// ===========================================================================
//
// 1. In lowerCall(), replace the error-throwing stub:
//
//    if (func.startsWith('verifySLHDSA_SHA2_')) {
//      const paramKey = func.replace('verifySLHDSA_', '');
//      this.lowerVerifySLHDSA(bindingName, paramKey, args, bindingIndex, lastUses);
//      return;
//    }
//
// 2. Add method to LoweringContext:
//
//    private lowerVerifySLHDSA(
//      bindingName: string,
//      paramKey: string,
//      args: string[],
//      bindingIndex: number,
//      lastUses: Map<string, number>,
//    ): void {
//      if (args.length < 3) {
//        throw new Error('verifySLHDSA requires 3 arguments: msg, sig, pubkey');
//      }
//      for (const arg of args) {
//        this.bringToTop(arg, this.isLastUse(arg, bindingIndex, lastUses));
//      }
//      for (let i = 0; i < 3; i++) this.stackMap.pop();
//
//      emitVerifySLHDSA((op) => this.emitOp(op), paramKey);
//
//      this.stackMap.push(bindingName);
//      this.trackDepth();
//    }
