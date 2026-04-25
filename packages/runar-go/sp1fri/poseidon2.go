package sp1fri

// Poseidon2-KoalaBear permutation (width=16, RF=8, RP=20, alpha=3).
//
// Runtime implementation of the codegen scaffold in
// `compilers/go/codegen/poseidon2_koalabear.go`. Constants are byte-identical
// to the codegen tables (KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
// KOALABEAR_POSEIDON2_RC_16_INTERNAL, KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL
// and the optimized diagonal V from
// `koala-bear/src/poseidon2.rs`).
//
// All values are canonical KoalaBear (uint32 in [0, p)).
//
// References:
//   - Plonky3 koala-bear/src/poseidon2.rs
//   - Plonky3 poseidon2/src/external.rs (external linear layer)
//   - Plonky3 monty-31/src/poseidon2.rs (internal linear layer wiring)

const (
	poseidon2Width    = 16
	poseidon2HalfRF   = 4
	poseidon2RP       = 20
	poseidon2TotalRds = 2*poseidon2HalfRF + poseidon2RP // 28
)

// The constants below are the SP1 v6.0.2 published Grain-LFSR tables
// (KOALABEAR_POSEIDON2_RC_16_*). They match `default_koalabear_poseidon2_16()`
// and pass `test_default_koalabear_poseidon2_width_16` (see poseidon2_test.go).
// The minimal-guest fixture at
// `tests/vectors/sp1/fri/minimal-guest/regen/src/main.rs` is built against
// the same `default_koalabear_poseidon2_16()` so the runtime permutation
// matches the prover's permutation byte-for-byte.

// Round constants — initial 4 external rounds (rounds 0..3).
var poseidon2RCExtInitial = [poseidon2HalfRF][poseidon2Width]uint32{
	{2128964168, 288780357, 316938561, 2126233899, 426817493, 1714118888, 1045008582, 1738510837, 889721787, 8866516, 681576474, 419059826, 1596305521, 1583176088, 1584387047, 1529751136},
	{1863858111, 1072044075, 517831365, 1464274176, 1138001621, 428001039, 245709561, 1641420379, 1365482496, 770454828, 693167409, 757905735, 136670447, 436275702, 525466355, 1559174242},
	{1030087950, 869864998, 322787870, 267688717, 948964561, 740478015, 679816114, 113662466, 2066544572, 1744924186, 367094720, 1380455578, 1842483872, 416711434, 1342291586, 1692058446},
	{1493348999, 1113949088, 210900530, 1071655077, 610242121, 1136339326, 2020858841, 1019840479, 678147278, 1678413261, 1361743414, 61132629, 1209546658, 64412292, 1936878279, 1980661727},
}

// Round constants — internal rounds (rounds 4..23). Each is a single scalar
// applied to state[0]; state[1..16] receive zero.
var poseidon2RCInternal = [poseidon2RP]uint32{
	1423960925, 2101391318, 1915532054, 275400051,
	1168624859, 1141248885, 356546469, 1165250474,
	1320543726, 932505663, 1204226364, 1452576828,
	1774936729, 926808140, 1184948056, 1186493834,
	843181003, 185193011, 452207447, 510054082,
}

// Round constants — final 4 external rounds (rounds 24..27).
var poseidon2RCExtFinal = [poseidon2HalfRF][poseidon2Width]uint32{
	{1139268644, 630873441, 669538875, 462500858, 876500520, 1214043330, 383937013, 375087302, 636912601, 307200505, 390279673, 1999916485, 1518476730, 1606686591, 1410677749, 1581191572},
	{1004269969, 143426723, 1747283099, 1016118214, 1749423722, 66331533, 1177761275, 1581069649, 1851371119, 852520128, 1499632627, 1820847538, 150757557, 884787840, 619710451, 1651711087},
	{505263814, 212076987, 1482432120, 1458130652, 382871348, 417404007, 2066495280, 1996518884, 902934924, 582892981, 1337064375, 1199354861, 2102596038, 1533193853, 1436311464, 2012303432},
	{839997195, 1225781098, 2011967775, 575084315, 1309329169, 786393545, 995788880, 1702925345, 1444525226, 908073383, 1811535085, 1531002367, 1635653662, 1585100155, 867006515, 879151050},
}

// Internal diagonal V from `koala-bear/src/poseidon2.rs::KoalaBearInternalLayerParameters`:
//   V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4,
//        1/2^8, 1/8, 1/2^24, -1/2^8, -1/8, -1/16, -1/2^24]
//
// The internal layer is `s[i] -> s[i] * V[i] + sum`. Note the codegen-time
// formulation in `compilers/go/codegen/poseidon2_koalabear.go` uses the same V
// (entries match `poseidon2KBInternalDiagM1`).
var poseidon2InternalDiagV = [poseidon2Width]uint32{
	2130706431, // -2 mod p
	1,
	2,
	1065353217, // 1/2 mod p
	3,
	4,
	1065353216, // -1/2 mod p
	2130706430, // -3 mod p
	2130706429, // -4 mod p
	2122383361, // 1/2^8
	1864368129, // 1/8
	2130706306, // 1/2^24
	8323072,    // -1/2^8
	266338304,  // -1/8
	133169152,  // -1/16
	127,        // -1/2^24
}

// poseidon2Sbox cubes a single field element: x -> x^3.
func poseidon2Sbox(x uint32) uint32 {
	x2 := KbMul(x, x)
	return KbMul(x2, x)
}

// externalMDS4 applies the 4x4 circulant `circ(2, 3, 1, 1)` to a 4-element
// block. Mirrors `poseidon2KBExternalMDS4` in the codegen.
//
//	out0 = sum + a + 2b   = 2a + 3b +  c +  d
//	out1 = sum + b + 2c   =  a + 2b + 3c +  d
//	out2 = sum + c + 2d   =  a +  b + 2c + 3d
//	out3 = sum + d + 2a   = 3a +  b +  c + 2d  (sum = a+b+c+d)
func externalMDS4(blk *[4]uint32) {
	a, b, c, d := blk[0], blk[1], blk[2], blk[3]
	sum := KbAdd(KbAdd(a, b), KbAdd(c, d))
	blk[0] = KbAdd(KbAdd(sum, a), KbAdd(b, b))
	blk[1] = KbAdd(KbAdd(sum, b), KbAdd(c, c))
	blk[2] = KbAdd(KbAdd(sum, c), KbAdd(d, d))
	blk[3] = KbAdd(KbAdd(sum, d), KbAdd(a, a))
}

// externalMDSFull applies the full 16x16 external linear layer:
//   1. Apply circ(2,3,1,1) to each of the 4 blocks of 4.
//   2. Cross-block mixing: for each k in 0..4, sums[k] = sum over j of state[k + 4j];
//      then state[i] += sums[i mod 4].
func externalMDSFull(state *[poseidon2Width]uint32) {
	// Block-wise MDS.
	for g := 0; g < 4; g++ {
		var blk [4]uint32
		copy(blk[:], state[g*4:g*4+4])
		externalMDS4(&blk)
		copy(state[g*4:g*4+4], blk[:])
	}

	// Cross-block sums.
	var sums [4]uint32
	for k := 0; k < 4; k++ {
		s := uint32(0)
		for j := 0; j < 4; j++ {
			s = KbAdd(s, state[k+4*j])
		}
		sums[k] = s
	}

	// Add sums[i mod 4] to each element.
	for i := 0; i < poseidon2Width; i++ {
		state[i] = KbAdd(state[i], sums[i%4])
	}
}

// internalDiffusion applies the internal linear layer `s -> diag(V) s + sum_S`
// where sum_S = sum(s[i]). Exactly matches `internal_layer_mat_mul` for
// KoalaBear width 16 in `koala-bear/src/poseidon2.rs`. Equivalent formulation:
//   sum = sum(s[i])
//   for each i: s[i] = s[i] * V[i] + sum
func internalDiffusion(state *[poseidon2Width]uint32) {
	sum := uint32(0)
	for i := 0; i < poseidon2Width; i++ {
		sum = KbAdd(sum, state[i])
	}
	for i := 0; i < poseidon2Width; i++ {
		state[i] = KbAdd(KbMul(state[i], poseidon2InternalDiagV[i]), sum)
	}
}

// addRCExternal adds external round constants to all 16 elements.
func addRCExternal(state *[poseidon2Width]uint32, rc *[poseidon2Width]uint32) {
	for i := 0; i < poseidon2Width; i++ {
		state[i] = KbAdd(state[i], rc[i])
	}
}

// Poseidon2Permute applies the full Poseidon2-KoalaBear width-16 permutation.
//
// Algorithm:
//   1. Initial external linear layer (no RC, no S-box).
//   2. 4 external rounds: addRC + S-box(all 16) + extMDS.
//   3. 20 internal rounds: state[0] += rc; state[0] = sbox(state[0]); intDiff.
//   4. 4 external rounds: addRC + S-box(all 16) + extMDS.
func Poseidon2Permute(state *[poseidon2Width]uint32) {
	// 1. Initial external layer.
	externalMDSFull(state)

	// 2. External initial rounds (rounds 0..3).
	for r := 0; r < poseidon2HalfRF; r++ {
		addRCExternal(state, &poseidon2RCExtInitial[r])
		for i := 0; i < poseidon2Width; i++ {
			state[i] = poseidon2Sbox(state[i])
		}
		externalMDSFull(state)
	}

	// 3. Internal rounds (rounds 4..23).
	for r := 0; r < poseidon2RP; r++ {
		state[0] = KbAdd(state[0], poseidon2RCInternal[r])
		state[0] = poseidon2Sbox(state[0])
		internalDiffusion(state)
	}

	// 4. External final rounds (rounds 24..27).
	for r := 0; r < poseidon2HalfRF; r++ {
		addRCExternal(state, &poseidon2RCExtFinal[r])
		for i := 0; i < poseidon2Width; i++ {
			state[i] = poseidon2Sbox(state[i])
		}
		externalMDSFull(state)
	}
}

// Poseidon2Compress is `TruncatedPermutation<Perm, 2, 8, 16>::compress(left, right)`:
//   1. concat left || right into a 16-element preimage,
//   2. apply the permutation,
//   3. truncate to the first 8 elements.
func Poseidon2Compress(left, right [8]uint32) [8]uint32 {
	var state [poseidon2Width]uint32
	copy(state[:8], left[:])
	copy(state[8:], right[:])
	Poseidon2Permute(&state)
	var out [8]uint32
	copy(out[:], state[:8])
	return out
}

// Poseidon2HashSlice is `PaddingFreeSponge<Perm, 16, 8, 8>::hash_iter(input)`:
// overwrite-mode sponge with rate 8 and zero padding. Squeezes 8 elements.
//
// Empty input returns the all-zero state (no permutation is performed).
//
// See `symmetric/src/sponge.rs::PaddingFreeSponge::hash_iter`.
func Poseidon2HashSlice(input []uint32) [8]uint32 {
	var state [poseidon2Width]uint32
	rem := input
	for {
		// Absorb up to RATE = 8 elements.
		i := 0
		for ; i < 8 && len(rem) > 0; i, rem = i+1, rem[1:] {
			state[i] = rem[0]
		}
		if i == 8 {
			// Full block.
			Poseidon2Permute(&state)
			if len(rem) == 0 {
				break
			}
			continue
		}
		// Partial block. Permute only if at least one element was absorbed
		// (matches the `if i != 0` branch in PaddingFreeSponge).
		if i != 0 {
			Poseidon2Permute(&state)
		}
		break
	}
	var out [8]uint32
	copy(out[:], state[:8])
	return out
}
