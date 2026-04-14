/**
 * Poseidon2 KoalaBear permutation codegen — Bitcoin Script generator for the
 * Poseidon2 hash function over the KoalaBear field.
 *
 * Ports compilers/go/codegen/poseidon2_koalabear.go to TypeScript.
 *
 * Parameters (SP1 v6, StackedBasefold):
 *   - State width: 16 KoalaBear field elements
 *   - External rounds: 8 (4 initial + 4 final)
 *   - Internal rounds: 20
 *   - MDS matrix: 4x4 circulant blocks for external, diagonalised for internal
 *
 * Round constants match SP1 v6.0.2 / Plonky3 koala-bear/src/poseidon2.rs.
 *
 * Stack conventions:
 *   EmitPoseidon2KBPermute: [..., s0..s15] (s15 top) → [..., s0'..s15']
 *   EmitPoseidon2KBCompress: [..., s0..s15] (s15 top) → [..., h0..h7]
 */

import type { StackOp } from '../ir/index.js';
import {
  KBTracker,
  kbFieldAdd,
  kbFieldMul,
  kbFieldSqr,
  kbFieldAddUnreduced,
  kbFieldMulConst,
} from './koalabear-codegen.js';

// ===========================================================================
// Constants
// ===========================================================================

const P2KB_WIDTH = 16;
const P2KB_EXTERNAL_ROUNDS = 8;
const P2KB_INTERNAL_ROUNDS = 20;
const P2KB_TOTAL_ROUNDS = P2KB_EXTERNAL_ROUNDS + P2KB_INTERNAL_ROUNDS;

// Internal diagonal matrix M-1 entries (the diag minus identity, so the
// linear layer is x + diag[i]*sum where sum = sum(x)).
const P2KB_INTERNAL_DIAG_M1: bigint[] = [
  2130706431n, 1n, 2n, 1065353217n, 3n, 4n, 1065353216n, 2130706430n,
  2130706429n, 2122383361n, 1864368129n, 2130706306n, 8323072n, 266338304n, 133169152n, 127n,
];

// Round constants for all 28 rounds (external initial, internal, external final).
// Internal rounds only use element [0] (index 4..23).
const P2KB_ROUND_CONSTANTS: bigint[][] = [
  // External initial rounds (0-3)
  [2128964168n, 288780357n, 316938561n, 2126233899n, 426817493n, 1714118888n, 1045008582n, 1738510837n, 889721787n, 8866516n, 681576474n, 419059826n, 1596305521n, 1583176088n, 1584387047n, 1529751136n],
  [1863858111n, 1072044075n, 517831365n, 1464274176n, 1138001621n, 428001039n, 245709561n, 1641420379n, 1365482496n, 770454828n, 693167409n, 757905735n, 136670447n, 436275702n, 525466355n, 1559174242n],
  [1030087950n, 869864998n, 322787870n, 267688717n, 948964561n, 740478015n, 679816114n, 113662466n, 2066544572n, 1744924186n, 367094720n, 1380455578n, 1842483872n, 416711434n, 1342291586n, 1692058446n],
  [1493348999n, 1113949088n, 210900530n, 1071655077n, 610242121n, 1136339326n, 2020858841n, 1019840479n, 678147278n, 1678413261n, 1361743414n, 61132629n, 1209546658n, 64412292n, 1936878279n, 1980661727n],
  // Internal rounds (4-23) — only element [0] is used
  [1423960925n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [2101391318n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [1915532054n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [275400051n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [1168624859n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [1141248885n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [356546469n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [1165250474n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [1320543726n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [932505663n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [1204226364n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [1452576828n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [1774936729n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [926808140n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [1184948056n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [1186493834n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [843181003n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [185193011n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [452207447n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  [510054082n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
  // External final rounds (24-27)
  [1139268644n, 630873441n, 669538875n, 462500858n, 876500520n, 1214043330n, 383937013n, 375087302n, 636912601n, 307200505n, 390279673n, 1999916485n, 1518476730n, 1606686591n, 1410677749n, 1581191572n],
  [1004269969n, 143426723n, 1747283099n, 1016118214n, 1749423722n, 66331533n, 1177761275n, 1581069649n, 1851371119n, 852520128n, 1499632627n, 1820847538n, 150757557n, 884787840n, 619710451n, 1651711087n],
  [505263814n, 212076987n, 1482432120n, 1458130652n, 382871348n, 417404007n, 2066495280n, 1996518884n, 902934924n, 582892981n, 1337064375n, 1199354861n, 2102596038n, 1533193853n, 1436311464n, 2012303432n],
  [839997195n, 1225781098n, 2011967775n, 575084315n, 1309329169n, 786393545n, 995788880n, 1702925345n, 1444525226n, 908073383n, 1811535085n, 1531002367n, 1635653662n, 1585100155n, 867006515n, 879151050n],
];

// ===========================================================================
// State name helpers
// ===========================================================================

function p2StateName(i: number): string { return `_p2s${i}`; }

function p2StateNames(): string[] {
  const names: string[] = [];
  for (let i = 0; i < P2KB_WIDTH; i++) names.push(p2StateName(i));
  return names;
}

// ===========================================================================
// Internal codegen helpers
// ===========================================================================

/** S-box: x^3 (squaring then multiplying). */
function p2Sbox(t: KBTracker, name: string, round: number, idx: number): void {
  const tmp = `_p2sbox_r${round}_${idx}`;
  t.copyToTop(name, tmp + '_sq_copy');
  kbFieldSqr(t, tmp + '_sq_copy', tmp + '_sq');
  kbFieldMul(t, name, tmp + '_sq', tmp + '_cube');
  t.rename(name);
}

/**
 * External MDS 4x4 layer on one group of 4 elements.
 * Uses the circulant MDS matrix [2,3,1,1] (Plonky3 convention):
 *   out[i] = sum + x[i] + x[(i+1)%4]
 * where sum = a+b+c+d.
 */
function p2ExternalMDS4(t: KBTracker, names: [string, string, string, string], round: number, group: number): void {
  const prefix = `_p2mds_r${round}_g${group}`;

  // Compute sum = a + b + c + d (via unreduced additions)
  t.copyToTop(names[0], prefix + '_ca');
  t.copyToTop(names[1], prefix + '_cb');
  kbFieldAddUnreduced(t, prefix + '_ca', prefix + '_cb', prefix + '_ab');
  t.copyToTop(names[2], prefix + '_cc');
  kbFieldAddUnreduced(t, prefix + '_ab', prefix + '_cc', prefix + '_abc');
  t.copyToTop(names[3], prefix + '_cd');
  kbFieldAddUnreduced(t, prefix + '_abc', prefix + '_cd', prefix + '_sum');

  // out[0] = sum + a + 2*b
  t.copyToTop(prefix + '_sum', prefix + '_s0'); t.copyToTop(names[0], prefix + '_a0');
  kbFieldAddUnreduced(t, prefix + '_s0', prefix + '_a0', prefix + '_sa0');
  t.copyToTop(names[1], prefix + '_b0'); kbFieldMulConst(t, prefix + '_b0', 2n, prefix + '_2b0');
  kbFieldAdd(t, prefix + '_sa0', prefix + '_2b0', prefix + '_out0');

  // out[1] = sum + b + 2*c
  t.copyToTop(prefix + '_sum', prefix + '_s1'); t.copyToTop(names[1], prefix + '_b1');
  kbFieldAddUnreduced(t, prefix + '_s1', prefix + '_b1', prefix + '_sb1');
  t.copyToTop(names[2], prefix + '_c1'); kbFieldMulConst(t, prefix + '_c1', 2n, prefix + '_2c1');
  kbFieldAdd(t, prefix + '_sb1', prefix + '_2c1', prefix + '_out1');

  // out[2] = sum + c + 2*d
  t.copyToTop(prefix + '_sum', prefix + '_s2'); t.copyToTop(names[2], prefix + '_c2');
  kbFieldAddUnreduced(t, prefix + '_s2', prefix + '_c2', prefix + '_sc2');
  t.copyToTop(names[3], prefix + '_d2'); kbFieldMulConst(t, prefix + '_d2', 2n, prefix + '_2d2');
  kbFieldAdd(t, prefix + '_sc2', prefix + '_2d2', prefix + '_out2');

  // out[3] = sum + d + 2*a
  t.copyToTop(prefix + '_sum', prefix + '_s3'); t.copyToTop(names[3], prefix + '_d3');
  kbFieldAddUnreduced(t, prefix + '_s3', prefix + '_d3', prefix + '_sd3');
  t.copyToTop(names[0], prefix + '_a3'); kbFieldMulConst(t, prefix + '_a3', 2n, prefix + '_2a3');
  kbFieldAdd(t, prefix + '_sd3', prefix + '_2a3', prefix + '_out3');

  // Drop old values and sum, bring outputs into place
  for (const n of [names[0], names[1], names[2], names[3], prefix + '_sum']) {
    t.toTop(n); t.drop();
  }
  t.toTop(prefix + '_out0'); t.rename(names[0]);
  t.toTop(prefix + '_out1'); t.rename(names[1]);
  t.toTop(prefix + '_out2'); t.rename(names[2]);
  t.toTop(prefix + '_out3'); t.rename(names[3]);
}

/**
 * Full external MDS layer (4 independent 4x4 groups, then cross-group mixing).
 * The cross-group sum S[k] = sum of out[k], out[k+4], out[k+8], out[k+12]
 * is added to each element: names[i] += S[i%4].
 */
function p2ExternalMDSFull(t: KBTracker, names: string[], round: number): void {
  // Apply 4x4 MDS to each of the 4 groups
  for (let g = 0; g < 4; g++) {
    const group: [string, string, string, string] = [names[g * 4]!, names[g * 4 + 1]!, names[g * 4 + 2]!, names[g * 4 + 3]!];
    p2ExternalMDS4(t, group, round, g);
  }

  // Cross-group mixing: S[k] = sum over j of names[k + j*4]
  const prefix = `_p2xg_r${round}`;
  for (let k = 0; k < 4; k++) {
    const sumName = `${prefix}_s${k}`;
    t.copyToTop(names[k]!, sumName);
    for (let j = 1; j < 4; j++) {
      const idx = k + j * 4;
      const addName = `${prefix}_a${k}_${j}`;
      t.copyToTop(names[idx]!, addName);
      kbFieldAdd(t, sumName, addName, sumName + '_n');
      t.rename(sumName);
    }
  }
  // Add S[i%4] to each element
  for (let i = 0; i < P2KB_WIDTH; i++) {
    const k = i % 4;
    const sumName = `${prefix}_s${k}`;
    const copyName = `${prefix}_sc${i}`;
    t.copyToTop(sumName, copyName);
    kbFieldAdd(t, names[i]!, copyName, names[i]!);
  }
  // Drop the 4 cross-sums
  for (let k = 0; k < 4; k++) {
    t.toTop(`${prefix}_s${k}`); t.drop();
  }
}

/** Internal diffusion layer: accumulate sum, multiply by diag, add sum. */
function p2InternalDiffusion(t: KBTracker, names: string[], round: number): void {
  const prefix = `_p2id_r${round}`;

  // Compute sum of all state elements
  t.copyToTop(names[0]!, prefix + '_acc');
  for (let i = 1; i < P2KB_WIDTH; i++) {
    t.copyToTop(names[i]!, `${prefix}_add${i}`);
    kbFieldAdd(t, prefix + '_acc', `${prefix}_add${i}`, prefix + '_acc_new');
    t.rename(prefix + '_acc');
  }
  t.rename(prefix + '_sum');

  // Compute new element = diag[i] * x[i] + sum
  for (let i = 0; i < P2KB_WIDTH; i++) {
    const diag = P2KB_INTERNAL_DIAG_M1[i]!;
    const prodName = `${prefix}_prod${i}`;
    if (diag === 1n) {
      t.copyToTop(names[i]!, prodName);
    } else {
      t.copyToTop(names[i]!, `${prefix}_si${i}`);
      kbFieldMulConst(t, `${prefix}_si${i}`, diag, prodName);
    }
    t.copyToTop(prefix + '_sum', `${prefix}_sc${i}`);
    kbFieldAdd(t, prodName, `${prefix}_sc${i}`, `${prefix}_out${i}`);
  }

  // Drop old values and sum
  for (let i = 0; i < P2KB_WIDTH; i++) { t.toTop(names[i]!); t.drop(); }
  t.toTop(prefix + '_sum'); t.drop();

  // Rename outputs to state names
  for (let i = 0; i < P2KB_WIDTH; i++) {
    t.toTop(`${prefix}_out${i}`); t.rename(names[i]!);
  }
}

/** Add round constants to all state elements. Skips zeros. */
function p2AddRoundConstants(t: KBTracker, names: string[], round: number): void {
  for (let i = 0; i < P2KB_WIDTH; i++) {
    const rc = P2KB_ROUND_CONSTANTS[round]![i]!;
    if (rc === 0n) continue;
    const prefix = `_p2rc_r${round}_${i}`;
    t.pushInt(prefix + '_c', rc);
    kbFieldAdd(t, names[i]!, prefix + '_c', prefix + '_sum');
    t.rename(names[i]!);
  }
}

/** Add round constant to element 0 only (internal rounds). */
function p2AddRoundConstantElem0(t: KBTracker, names: string[], round: number): void {
  const rc = P2KB_ROUND_CONSTANTS[round]![0]!;
  if (rc === 0n) return;
  const prefix = `_p2rc_r${round}_0`;
  t.pushInt(prefix + '_c', rc);
  kbFieldAdd(t, names[0]!, prefix + '_c', prefix + '_sum');
  t.rename(names[0]!);
}

/** Full Poseidon2 permutation: 4 external + 20 internal + 4 external rounds. */
function p2Permute(t: KBTracker, names: string[]): void {
  // Initial external MDS (no round constants)
  p2ExternalMDSFull(t, names, -1);

  // External initial rounds (0..3): add constants, sbox all, external MDS
  for (let r = 0; r < 4; r++) {
    p2AddRoundConstants(t, names, r);
    for (let i = 0; i < P2KB_WIDTH; i++) p2Sbox(t, names[i]!, r, i); // eslint-disable-line @typescript-eslint/no-non-null-assertion
    p2ExternalMDSFull(t, names, r);
  }

  // Internal rounds (4..23): add constant to elem 0, sbox elem 0, internal diffusion
  for (let r = 4; r < 4 + P2KB_INTERNAL_ROUNDS; r++) {
    p2AddRoundConstantElem0(t, names, r);
    p2Sbox(t, names[0]!, r, 0);
    p2InternalDiffusion(t, names, r);
  }

  // External final rounds (24..27): add constants, sbox all, external MDS
  for (let r = 4 + P2KB_INTERNAL_ROUNDS; r < P2KB_TOTAL_ROUNDS; r++) {
    p2AddRoundConstants(t, names, r);
    for (let i = 0; i < P2KB_WIDTH; i++) p2Sbox(t, names[i]!, r, i);
    p2ExternalMDSFull(t, names, r);
  }
}

// ===========================================================================
// Internal helper for Fiat-Shamir integration
// ===========================================================================

/**
 * p2KBPermuteOnTracker: run the Poseidon2 permutation on an existing KBTracker
 * where the state is already named _p2s0.._p2s15.
 *
 * Used by FiatShamirState.emitPermute to avoid recreating a tracker.
 * The caller is responsible for pushPrimeCache/popPrimeCache around this call.
 */
export function p2KBPermuteOnTracker(t: KBTracker): void {
  const names = p2StateNames();
  p2Permute(t, names);
  // After permute, bring all state elements to top in order
  for (let i = 0; i < P2KB_WIDTH; i++) t.toTop(p2StateName(i));
}

// ===========================================================================
// Public emit functions
// ===========================================================================

/**
 * EmitPoseidon2KBPermute: full 16-element Poseidon2 permutation.
 *
 * Stack in:  [..., s0, s1, ..., s15]  (s15 on top)
 * Stack out: [..., s0', s1', ..., s15']
 */
export function emitPoseidon2KBPermute(emit: (op: StackOp) => void): void {
  const initNames: string[] = [];
  for (let i = 0; i < P2KB_WIDTH; i++) initNames.push(p2StateName(i));
  const t = new KBTracker(initNames, emit);
  t.pushPrimeCache();
  const names = p2StateNames();
  p2Permute(t, names);
  t.popPrimeCache();
  // Bring all state elements to top in order (s0 deepest, s15 top)
  for (let i = 0; i < P2KB_WIDTH; i++) t.toTop(p2StateName(i));
}

/**
 * EmitPoseidon2KBCompress: compress 16 elements to 8 (first half of permuted output).
 *
 * Stack in:  [..., s0, s1, ..., s15]  (s15 on top)
 * Stack out: [..., h0, h1, ..., h7]
 */
export function emitPoseidon2KBCompress(emit: (op: StackOp) => void): void {
  const initNames: string[] = [];
  for (let i = 0; i < P2KB_WIDTH; i++) initNames.push(p2StateName(i));
  const t = new KBTracker(initNames, emit);
  t.pushPrimeCache();
  const names = p2StateNames();
  p2Permute(t, names);
  t.popPrimeCache();
  // Drop elements 8..15, then bring 0..7 to top in order
  for (let i = 8; i < P2KB_WIDTH; i++) { t.toTop(p2StateName(i)); t.drop(); }
  for (let i = 0; i < 8; i++) t.toTop(p2StateName(i));
}
