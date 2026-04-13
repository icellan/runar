// Poseidon2 permutation over KoalaBear field — codegen for Bitcoin Script.
//
// Implements the Poseidon2 hash function used by SP1 v6 for Merkle commitments
// and Fiat-Shamir challenges. All operations use the KoalaBear prime field
// (p = 2^31 - 2^24 + 1 = 2,130,706,433).
//
// Parameters (SP1 v6.0.2):
//   - State width: 16 KoalaBear field elements
//   - Sbox: x^3 (cube)
//   - External rounds: 8 (4 before internal, 4 after)
//   - Internal rounds: 20
//   - Total rounds: 28
//   - Digest: first 8 elements of the output state
//
// The permutation is structured as:
//   Phase 1 — 4 external rounds (rounds 0-3)
//   Phase 2 — 20 internal rounds (rounds 4-23)
//   Phase 3 — 4 external rounds (rounds 24-27)
//
// External rounds apply the full S-box and MDS matrix to all 16 elements.
// Internal rounds apply S-box only to element 0 and use a diagonal diffusion matrix.
//
// This module provides internal codegen functions called by Merkle verification
// and sponge codegen modules. It is NOT registered as a contract-level builtin.
package codegen

import "fmt"

// ===========================================================================
// Poseidon2 KoalaBear constants
// ===========================================================================

// poseidon2KBWidth is the state width (number of field elements).
const poseidon2KBWidth = 16

// poseidon2KBExternalRounds is the number of external (full) rounds.
const poseidon2KBExternalRounds = 8

// poseidon2KBInternalRounds is the number of internal (partial) rounds.
const poseidon2KBInternalRounds = 20

// poseidon2KBTotalRounds is the total number of rounds.
const poseidon2KBTotalRounds = poseidon2KBExternalRounds + poseidon2KBInternalRounds

// poseidon2KBInternalDiagM1 contains the diagonal entries for the internal
// diffusion layer. From Plonky3 p3-koala-bear DiffusionMatrixKoalaBear.
//
// V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/8, 1/2^24, -1/2^8, -1/8, -1/16, -1/2^24]
// Values are computed mod p (fractions via modular inverse).
//
// The internal linear layer computes:
//
//	sum = sum(state[i])
//	state[i] = state[i] * diag_m_1[i] + sum
//
// where diag_m_1[i] are the entries of V above, computed mod p.
var poseidon2KBInternalDiagM1 = [poseidon2KBWidth]int64{
	2130706431, // V[0]  = -2 mod p
	1,          // V[1]  = 1
	2,          // V[2]  = 2
	1065353217, // V[3]  = 1/2 mod p
	3,          // V[4]  = 3
	4,          // V[5]  = 4
	1065353216, // V[6]  = -1/2 mod p
	2130706430, // V[7]  = -3 mod p
	2130706429, // V[8]  = -4 mod p
	2122383361, // V[9]  = 1/2^8 mod p
	1864368129, // V[10] = 1/8 mod p
	2130706306, // V[11] = 1/2^24 mod p
	8323072,    // V[12] = -1/2^8 mod p
	266338304,  // V[13] = -1/8 mod p
	133169152,  // V[14] = -1/16 mod p
	127,        // V[15] = -1/2^24 mod p
}

// poseidon2KBRoundConstants holds the round constants for all 28 rounds.
// Each round has 16 constants. For external rounds, all 16 are used.
// For internal rounds (4-23), only element [0] is used (rest are zero).
//
// Extracted from Plonky3 p3-koala-bear (SP1 v6.0.2):
//   - koala-bear/src/poseidon2.rs: KOALABEAR_RC16_EXTERNAL_INITIAL,
//     KOALABEAR_POSEIDON2_RC_16_INTERNAL, KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL
//
// Source: https://github.com/0xPolygonZero/Plonky3/blob/main/koala-bear/src/poseidon2.rs
var poseidon2KBRoundConstants = [poseidon2KBTotalRounds][poseidon2KBWidth]int64{
	// External initial rounds (0-3)
	{2128964168, 288780357, 316938561, 2126233899, 426817493, 1714118888, 1045008582, 1738510837, 889721787, 8866516, 681576474, 419059826, 1596305521, 1583176088, 1584387047, 1529751136},
	{1863858111, 1072044075, 517831365, 1464274176, 1138001621, 428001039, 245709561, 1641420379, 1365482496, 770454828, 693167409, 757905735, 136670447, 436275702, 525466355, 1559174242},
	{1030087950, 869864998, 322787870, 267688717, 948964561, 740478015, 679816114, 113662466, 2066544572, 1744924186, 367094720, 1380455578, 1842483872, 416711434, 1342291586, 1692058446},
	{1493348999, 1113949088, 210900530, 1071655077, 610242121, 1136339326, 2020858841, 1019840479, 678147278, 1678413261, 1361743414, 61132629, 1209546658, 64412292, 1936878279, 1980661727},

	// Internal rounds (4-23) — only element [0] is used
	{1423960925, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{2101391318, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1915532054, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{275400051, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1168624859, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1141248885, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{356546469, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1165250474, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1320543726, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{932505663, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1204226364, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1452576828, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1774936729, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{926808140, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1184948056, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{1186493834, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{843181003, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{185193011, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{452207447, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	{510054082, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},

	// External final rounds (24-27)
	{1139268644, 630873441, 669538875, 462500858, 876500520, 1214043330, 383937013, 375087302, 636912601, 307200505, 390279673, 1999916485, 1518476730, 1606686591, 1410677749, 1581191572},
	{1004269969, 143426723, 1747283099, 1016118214, 1749423722, 66331533, 1177761275, 1581069649, 1851371119, 852520128, 1499632627, 1820847538, 150757557, 884787840, 619710451, 1651711087},
	{505263814, 212076987, 1482432120, 1458130652, 382871348, 417404007, 2066495280, 1996518884, 902934924, 582892981, 1337064375, 1199354861, 2102596038, 1533193853, 1436311464, 2012303432},
	{839997195, 1225781098, 2011967775, 575084315, 1309329169, 786393545, 995788880, 1702925345, 1444525226, 908073383, 1811535085, 1531002367, 1635653662, 1585100155, 867006515, 879151050},
}

// ===========================================================================
// State naming helpers
// ===========================================================================

// poseidon2KBStateName returns the canonical name for state element i.
func poseidon2KBStateName(i int) string {
	return fmt.Sprintf("_p2s%d", i)
}

// poseidon2KBStateNames returns an array of canonical state element names.
func poseidon2KBStateNames() [poseidon2KBWidth]string {
	var names [poseidon2KBWidth]string
	for i := 0; i < poseidon2KBWidth; i++ {
		names[i] = poseidon2KBStateName(i)
	}
	return names
}

// ===========================================================================
// Sbox: x^3 (cube) over KoalaBear field
// ===========================================================================

// poseidon2KBSbox computes state[idx] = state[idx]^3 mod p.
// Uses: x^3 = x * x^2. Two multiplications, one squaring copy.
func poseidon2KBSbox(t *KBTracker, name string, round, idx int) {
	tmp := fmt.Sprintf("_p2sbox_r%d_%d", round, idx)

	// x^2
	t.copyToTop(name, tmp+"_sq_copy")
	kbFieldSqr(t, tmp+"_sq_copy", tmp+"_sq")
	// x^3 = x * x^2
	kbFieldMul(t, name, tmp+"_sq", tmp+"_cube")
	t.rename(name)
}

// ===========================================================================
// External MDS: circ(2, 3, 1, 1) applied blockwise to 4 groups of 4
// ===========================================================================

// poseidon2KBExternalMDS4 applies the circulant matrix circ(2,3,1,1) to a
// 4-element block [a, b, c, d]:
//
//	sum = a + b + c + d
//	out0 = sum + a + 2*b  (= 2a + 3b + c + d)
//	out1 = sum + b + 2*c  (= a + 2b + 3c + d)
//	out2 = sum + c + 2*d  (= a + b + 2c + 3d)
//	out3 = sum + d + 2*a  (= 3a + b + c + 2d)
func poseidon2KBExternalMDS4(t *KBTracker, names [4]string, round, group int) {
	prefix := fmt.Sprintf("_p2mds_r%d_g%d", round, group)

	// Compute sum = a + b + c + d (unreduced — intermediate, consumed by mul below)
	// Max value: 4p ≈ 8.5e9 (fits in 34 bits, safe for BSV script numbers)
	t.copyToTop(names[0], prefix+"_ca")
	t.copyToTop(names[1], prefix+"_cb")
	kbFieldAddUnreduced(t, prefix+"_ca", prefix+"_cb", prefix+"_ab")
	t.copyToTop(names[2], prefix+"_cc")
	kbFieldAddUnreduced(t, prefix+"_ab", prefix+"_cc", prefix+"_abc")
	t.copyToTop(names[3], prefix+"_cd")
	kbFieldAddUnreduced(t, prefix+"_abc", prefix+"_cd", prefix+"_sum")

	// out0 = sum + a + 2*b (unreduced adds — kbFieldMulConst does final mod)
	t.copyToTop(prefix+"_sum", prefix+"_s0")
	t.copyToTop(names[0], prefix+"_a0")
	kbFieldAddUnreduced(t, prefix+"_s0", prefix+"_a0", prefix+"_sa0")
	t.copyToTop(names[1], prefix+"_b0")
	kbFieldMulConst(t, prefix+"_b0", 2, prefix+"_2b0")
	kbFieldAdd(t, prefix+"_sa0", prefix+"_2b0", prefix+"_out0")

	// out1 = sum + b + 2*c
	t.copyToTop(prefix+"_sum", prefix+"_s1")
	t.copyToTop(names[1], prefix+"_b1")
	kbFieldAddUnreduced(t, prefix+"_s1", prefix+"_b1", prefix+"_sb1")
	t.copyToTop(names[2], prefix+"_c1")
	kbFieldMulConst(t, prefix+"_c1", 2, prefix+"_2c1")
	kbFieldAdd(t, prefix+"_sb1", prefix+"_2c1", prefix+"_out1")

	// out2 = sum + c + 2*d
	t.copyToTop(prefix+"_sum", prefix+"_s2")
	t.copyToTop(names[2], prefix+"_c2")
	kbFieldAddUnreduced(t, prefix+"_s2", prefix+"_c2", prefix+"_sc2")
	t.copyToTop(names[3], prefix+"_d2")
	kbFieldMulConst(t, prefix+"_d2", 2, prefix+"_2d2")
	kbFieldAdd(t, prefix+"_sc2", prefix+"_2d2", prefix+"_out2")

	// out3 = sum + d + 2*a
	t.copyToTop(prefix+"_sum", prefix+"_s3")
	t.copyToTop(names[3], prefix+"_d3")
	kbFieldAddUnreduced(t, prefix+"_s3", prefix+"_d3", prefix+"_sd3")
	t.copyToTop(names[0], prefix+"_a3")
	kbFieldMulConst(t, prefix+"_a3", 2, prefix+"_2a3")
	kbFieldAdd(t, prefix+"_sd3", prefix+"_2a3", prefix+"_out3")

	// Drop old state elements and sum
	t.toTop(names[0])
	t.drop()
	t.toTop(names[1])
	t.drop()
	t.toTop(names[2])
	t.drop()
	t.toTop(names[3])
	t.drop()
	t.toTop(prefix + "_sum")
	t.drop()

	// Rename outputs to the original state names
	t.toTop(prefix + "_out0")
	t.rename(names[0])
	t.toTop(prefix + "_out1")
	t.rename(names[1])
	t.toTop(prefix + "_out2")
	t.rename(names[2])
	t.toTop(prefix + "_out3")
	t.rename(names[3])
}

// poseidon2KBExternalMDSFull applies the external MDS to all 16 state elements:
//  1. Apply circ(2,3,1,1) to each group of 4 (via poseidon2KBExternalMDS4)
//  2. Cross-group mixing: add sum of position-equivalent elements to each element
func poseidon2KBExternalMDSFull(t *KBTracker, names [poseidon2KBWidth]string, round int) {
	// Step 1: Apply 4x4 MDS blockwise (names are modified in-place by MDS4)
	for g := 0; g < 4; g++ {
		group := [4]string{names[g*4], names[g*4+1], names[g*4+2], names[g*4+3]}
		poseidon2KBExternalMDS4(t, group, round, g)
	}

	// Step 2: Cross-group mixing
	// For each position k (0..3), compute sums[k] = state[k] + state[k+4] + state[k+8] + state[k+12]
	// Then add sums[k] to each state[i] where i % 4 == k
	prefix := fmt.Sprintf("_p2xg_r%d", round)
	for k := 0; k < 4; k++ {
		sumName := fmt.Sprintf("%s_s%d", prefix, k)
		t.copyToTop(names[k], sumName)
		for j := 1; j < 4; j++ {
			idx := k + j*4
			addName := fmt.Sprintf("%s_a%d_%d", prefix, k, j)
			t.copyToTop(names[idx], addName)
			kbFieldAdd(t, sumName, addName, sumName+"_n")
			t.rename(sumName)
		}
	}

	// Add sums[i%4] to each element — kbFieldAdd consumes names[i] and produces result
	for i := 0; i < poseidon2KBWidth; i++ {
		k := i % 4
		sumName := fmt.Sprintf("%s_s%d", prefix, k)
		copyName := fmt.Sprintf("%s_sc%d", prefix, i)
		t.copyToTop(sumName, copyName)
		// kbFieldAdd consumes names[i] and copyName, produces names[i] (reuse name)
		kbFieldAdd(t, names[i], copyName, names[i])
	}

	// Clean up: drop the 4 sum accumulators
	for k := 0; k < 4; k++ {
		t.toTop(fmt.Sprintf("%s_s%d", prefix, k))
		t.drop()
	}
}

// ===========================================================================
// Internal diffusion: diagonal matrix + sum
// ===========================================================================

// poseidon2KBInternalDiffusion applies the internal linear layer:
//
//	sum = sum(state[i])
//	state[i] = state[i] * diag_m_1[i] + sum   for each i
//
// For diag_m_1[0] = p-2 (== -2 mod p): state[0] = -2*state[0] + sum
// Other entries include modular inverses (1/2, 1/8, etc.); uses kbFieldMulConst.
func poseidon2KBInternalDiffusion(t *KBTracker, names [poseidon2KBWidth]string, round int) {
	prefix := fmt.Sprintf("_p2id_r%d", round)

	// Step 1: Compute sum of all state elements.
	// Accumulate pairwise: sum = s0 + s1 + ... + s15
	t.copyToTop(names[0], prefix+"_acc")
	for i := 1; i < poseidon2KBWidth; i++ {
		t.copyToTop(names[i], fmt.Sprintf("%s_add%d", prefix, i))
		kbFieldAdd(t, prefix+"_acc", fmt.Sprintf("%s_add%d", prefix, i), prefix+"_acc_new")
		t.rename(prefix + "_acc")
	}
	// prefix+"_acc" now holds the sum
	t.rename(prefix + "_sum")

	// Step 2: For each element, compute state[i] = state[i] * diag_m_1[i] + sum.
	for i := 0; i < poseidon2KBWidth; i++ {
		diag := poseidon2KBInternalDiagM1[i]
		prodName := fmt.Sprintf("%s_prod%d", prefix, i)

		// Multiply state[i] by diag_m_1[i]
		if diag == 1 {
			// Multiplication by 1 is identity — just copy
			t.copyToTop(names[i], prodName)
		} else {
			t.copyToTop(names[i], fmt.Sprintf("%s_si%d", prefix, i))
			kbFieldMulConst(t, fmt.Sprintf("%s_si%d", prefix, i), diag, prodName)
		}

		// Add sum
		t.copyToTop(prefix+"_sum", fmt.Sprintf("%s_sc%d", prefix, i))
		resultName := fmt.Sprintf("%s_out%d", prefix, i)
		kbFieldAdd(t, prodName, fmt.Sprintf("%s_sc%d", prefix, i), resultName)
	}

	// Step 3: Drop old state elements and sum, rename outputs.
	for i := 0; i < poseidon2KBWidth; i++ {
		t.toTop(names[i])
		t.drop()
	}
	t.toTop(prefix + "_sum")
	t.drop()

	for i := 0; i < poseidon2KBWidth; i++ {
		t.toTop(fmt.Sprintf("%s_out%d", prefix, i))
		t.rename(names[i])
	}
}

// ===========================================================================
// Add round constants
// ===========================================================================

// poseidon2KBAddRoundConstants adds round constants to all 16 state elements.
// Used in external rounds.
func poseidon2KBAddRoundConstants(t *KBTracker, names [poseidon2KBWidth]string, round int) {
	for i := 0; i < poseidon2KBWidth; i++ {
		rc := poseidon2KBRoundConstants[round][i]
		if rc == 0 {
			continue // Skip zero round constants (no-op addition)
		}
		prefix := fmt.Sprintf("_p2rc_r%d_%d", round, i)
		t.pushInt(prefix+"_c", rc)
		kbFieldAdd(t, names[i], prefix+"_c", prefix+"_sum")
		t.rename(names[i])
	}
}

// poseidon2KBAddRoundConstantElem0 adds the round constant to element 0 only.
// Used in internal rounds.
func poseidon2KBAddRoundConstantElem0(t *KBTracker, names [poseidon2KBWidth]string, round int) {
	rc := poseidon2KBRoundConstants[round][0]
	if rc == 0 {
		return // Skip zero round constants
	}
	prefix := fmt.Sprintf("_p2rc_r%d_0", round)
	t.pushInt(prefix+"_c", rc)
	kbFieldAdd(t, names[0], prefix+"_c", prefix+"_sum")
	t.rename(names[0])
}

// ===========================================================================
// Full Poseidon2 permutation
// ===========================================================================

// poseidon2KBPermute applies the full Poseidon2 permutation to 16 state elements
// on the KBTracker stack. The state names array is mutated in place as elements
// are renamed through intermediate results.
//
// Algorithm:
//
//	Initial — external MDS (Plonky3's external_initial_permute_state)
//	Phase 1 — 4 external rounds (rounds 0-3):
//	  add round constants, full sbox, external MDS (blockwise + cross-group)
//	Phase 2 — 20 internal rounds (rounds 4-23):
//	  add round constant to elem 0, sbox on elem 0, internal diffusion
//	Phase 3 — 4 external rounds (rounds 24-27):
//	  add round constants, full sbox, external MDS (blockwise + cross-group)
func poseidon2KBPermute(t *KBTracker, names [poseidon2KBWidth]string) {
	// Initial MDS before external rounds (Plonky3's external_initial_permute_state)
	poseidon2KBExternalMDSFull(t, names, -1)

	// Phase 1: 4 external rounds (rounds 0-3)
	for r := 0; r < 4; r++ {
		poseidon2KBAddRoundConstants(t, names, r)
		for i := 0; i < poseidon2KBWidth; i++ {
			poseidon2KBSbox(t, names[i], r, i)
		}
		poseidon2KBExternalMDSFull(t, names, r)
	}

	// Phase 2: 20 internal rounds (rounds 4-23)
	for r := 4; r < 4+poseidon2KBInternalRounds; r++ {
		poseidon2KBAddRoundConstantElem0(t, names, r)
		poseidon2KBSbox(t, names[0], r, 0)
		poseidon2KBInternalDiffusion(t, names, r)
	}

	// Phase 3: 4 external rounds (rounds 24-27)
	for r := 4 + poseidon2KBInternalRounds; r < poseidon2KBTotalRounds; r++ {
		poseidon2KBAddRoundConstants(t, names, r)
		for i := 0; i < poseidon2KBWidth; i++ {
			poseidon2KBSbox(t, names[i], r, i)
		}
		poseidon2KBExternalMDSFull(t, names, r)
	}
}

// ===========================================================================
// Public emit functions
// ===========================================================================

// EmitPoseidon2KBPermute emits the full Poseidon2 permutation over KoalaBear.
//
// Stack in:  [..., s0, s1, ..., s15] (s15 on top)
// Stack out: [..., s0', s1', ..., s15'] (s15' on top)
//
// All 16 state elements are permuted in place. The caller is responsible for
// extracting the elements it needs from the resulting stack.
func EmitPoseidon2KBPermute(emit func(StackOp)) {
	// Initialize tracker with 16 input state elements.
	// Stack order: s0 is deepest, s15 is on top.
	initNames := make([]string, poseidon2KBWidth)
	for i := 0; i < poseidon2KBWidth; i++ {
		initNames[i] = poseidon2KBStateName(i)
	}
	t := NewKBTracker(initNames, emit)
	t.PushPrimeCache() // Cache the KoalaBear prime on alt-stack

	names := poseidon2KBStateNames()
	poseidon2KBPermute(t, names)

	t.PopPrimeCache() // Clean up cached prime

	// State elements are now named _p2s0.._p2s15 on the stack.
	// Reorder so that _p2s0 is deepest and _p2s15 is on top (original order).
	// After the permutation the elements may be in arbitrary positions.
	// Roll each element to its correct position from bottom up.
	for i := 0; i < poseidon2KBWidth; i++ {
		t.toTop(poseidon2KBStateName(i))
	}
	// Now stack is: [_p2s0, _p2s1, ..., _p2s15] with _p2s15 on top.
	// Rename to generic output names.
	// (They already have the right names from poseidon2KBStateName.)
}

// EmitPoseidon2KBCompress emits Poseidon2 compression (permute + truncate to 8 elements).
//
// Stack in:  [..., s0, s1, ..., s15] (s15 on top)
// Stack out: [..., h0, h1, ..., h7] (h7 on top)
//
// The digest is the first 8 elements of the permuted state.
// Elements s8'..s15' are dropped after permutation.
func EmitPoseidon2KBCompress(emit func(StackOp)) {
	// Initialize tracker with 16 input state elements.
	initNames := make([]string, poseidon2KBWidth)
	for i := 0; i < poseidon2KBWidth; i++ {
		initNames[i] = poseidon2KBStateName(i)
	}
	t := NewKBTracker(initNames, emit)
	t.PushPrimeCache() // Cache the KoalaBear prime on alt-stack

	names := poseidon2KBStateNames()
	poseidon2KBPermute(t, names)

	t.PopPrimeCache() // Clean up cached prime

	// Drop elements 8-15 (the non-digest portion)
	for i := 8; i < poseidon2KBWidth; i++ {
		t.toTop(poseidon2KBStateName(i))
		t.drop()
	}

	// Reorder digest elements so _p2s0 is deepest, _p2s7 on top
	for i := 0; i < 8; i++ {
		t.toTop(poseidon2KBStateName(i))
	}
}
