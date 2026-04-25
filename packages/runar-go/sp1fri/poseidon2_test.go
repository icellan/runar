package sp1fri

import "testing"

// TestPoseidon2DefaultWidth16 cross-checks the runtime permutation against the
// Plonky3 test vector in `koala-bear/src/poseidon2.rs::test_default_koalabear_poseidon2_width_16`.
//
// Plonky3 source (lines 591-609):
//
//	let mut input: [F; 16] = KoalaBear::new_array([
//	    894848333, 1437655012, 1200606629, 1690012884, 71131202, 1749206695,
//	    1717947831, 120589055, 19776022, 42382981, 1831865506, 724844064,
//	    171220207, 1299207443, 227047920, 1783754913,
//	]);
//	let expected: [F; 16] = KoalaBear::new_array([
//	    1934285469, 604889435, 133449501, 1026180808, 1830659359, 176667110,
//	    1391183747, 351743874, 1238264085, 1292768839, 2023573270, 1201586780,
//	    1360691759, 1230682461, 748270449, 651545025,
//	]);
//	let perm = default_koalabear_poseidon2_16();
//	perm.permute_mut(&mut input);
//	assert_eq!(input, expected);
func TestPoseidon2DefaultWidth16(t *testing.T) {
	input := [poseidon2Width]uint32{
		894848333, 1437655012, 1200606629, 1690012884, 71131202, 1749206695,
		1717947831, 120589055, 19776022, 42382981, 1831865506, 724844064,
		171220207, 1299207443, 227047920, 1783754913,
	}
	expected := [poseidon2Width]uint32{
		1934285469, 604889435, 133449501, 1026180808, 1830659359, 176667110,
		1391183747, 351743874, 1238264085, 1292768839, 2023573270, 1201586780,
		1360691759, 1230682461, 748270449, 651545025,
	}

	Poseidon2Permute(&input)
	if input != expected {
		t.Errorf("permutation mismatch\n got:  %v\n want: %v", input, expected)
	}
}
