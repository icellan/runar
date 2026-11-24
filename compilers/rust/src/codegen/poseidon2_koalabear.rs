//! Poseidon2 permutation over KoalaBear field -- codegen for Bitcoin Script.
//!
//! Port of compilers/go/codegen/poseidon2_koalabear.go.
//!
//! Parameters (SP1 v6.0.2):
//!   - State width: 16 KoalaBear field elements
//!   - Sbox: x^3 (cube)
//!   - External rounds: 8 (4 before internal, 4 after)
//!   - Internal rounds: 20
//!   - Total rounds: 28
//!   - Digest: first 8 elements of the output state

use super::koalabear::{
    kb_field_add, kb_field_add_unreduced, kb_field_mul, kb_field_mul_const, kb_field_sqr,
    KBTracker,
};
use super::stack::StackOp;

// ===========================================================================
// Poseidon2 KoalaBear constants
// ===========================================================================

const POSEIDON2_KB_WIDTH: usize = 16;
const POSEIDON2_KB_EXTERNAL_ROUNDS: usize = 8;
const POSEIDON2_KB_INTERNAL_ROUNDS: usize = 20;
const POSEIDON2_KB_TOTAL_ROUNDS: usize =
    POSEIDON2_KB_EXTERNAL_ROUNDS + POSEIDON2_KB_INTERNAL_ROUNDS;

/// Internal diagonal M-1 for the KoalaBear Poseidon2 diffusion layer.
/// From Plonky3 p3-koala-bear DiffusionMatrixKoalaBear.
static POSEIDON2_KB_INTERNAL_DIAG_M1: [i64; POSEIDON2_KB_WIDTH] = [
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
];

/// Round constants for all 28 rounds.
/// External rounds have all 16 constants; internal rounds (4-23) only use element [0].
static POSEIDON2_KB_ROUND_CONSTANTS: [[i64; POSEIDON2_KB_WIDTH]; POSEIDON2_KB_TOTAL_ROUNDS] = [
    // External initial rounds (0-3)
    [2128964168, 288780357, 316938561, 2126233899, 426817493, 1714118888, 1045008582, 1738510837, 889721787, 8866516, 681576474, 419059826, 1596305521, 1583176088, 1584387047, 1529751136],
    [1863858111, 1072044075, 517831365, 1464274176, 1138001621, 428001039, 245709561, 1641420379, 1365482496, 770454828, 693167409, 757905735, 136670447, 436275702, 525466355, 1559174242],
    [1030087950, 869864998, 322787870, 267688717, 948964561, 740478015, 679816114, 113662466, 2066544572, 1744924186, 367094720, 1380455578, 1842483872, 416711434, 1342291586, 1692058446],
    [1493348999, 1113949088, 210900530, 1071655077, 610242121, 1136339326, 2020858841, 1019840479, 678147278, 1678413261, 1361743414, 61132629, 1209546658, 64412292, 1936878279, 1980661727],
    // Internal rounds (4-23) -- only element [0] is used
    [1423960925, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [2101391318, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1915532054, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [275400051,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1168624859, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1141248885, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [356546469,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1165250474, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1320543726, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [932505663,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1204226364, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1452576828, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1774936729, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [926808140,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1184948056, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1186493834, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [843181003,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [185193011,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [452207447,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [510054082,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    // External final rounds (24-27)
    [1139268644, 630873441, 669538875, 462500858, 876500520, 1214043330, 383937013, 375087302, 636912601, 307200505, 390279673, 1999916485, 1518476730, 1606686591, 1410677749, 1581191572],
    [1004269969, 143426723, 1747283099, 1016118214, 1749423722, 66331533, 1177761275, 1581069649, 1851371119, 852520128, 1499632627, 1820847538, 150757557, 884787840, 619710451, 1651711087],
    [505263814, 212076987, 1482432120, 1458130652, 382871348, 417404007, 2066495280, 1996518884, 902934924, 582892981, 1337064375, 1199354861, 2102596038, 1533193853, 1436311464, 2012303432],
    [839997195, 1225781098, 2011967775, 575084315, 1309329169, 786393545, 995788880, 1702925345, 1444525226, 908073383, 1811535085, 1531002367, 1635653662, 1585100155, 867006515, 879151050],
];

// ===========================================================================
// State naming helpers
// ===========================================================================

pub(crate) fn p2kb_state_name(i: usize) -> String {
    format!("_p2s{}", i)
}

pub(crate) fn p2kb_state_names() -> [String; POSEIDON2_KB_WIDTH] {
    std::array::from_fn(|i| p2kb_state_name(i))
}

// ===========================================================================
// Sbox: x^3 (cube) over KoalaBear field
// ===========================================================================

/// p2kb_sbox computes state[idx] = state[idx]^3 mod p.
/// Uses: x^3 = x * x^2. Two multiplications, one squaring copy.
pub(crate) fn p2kb_sbox(t: &mut KBTracker, name: &str, round: i32, idx: usize) {
    let tmp = format!("_p2sbox_r{}_{}", round, idx);

    // x^2
    t.copy_to_top(name, &format!("{}_sq_copy", tmp));
    kb_field_sqr(t, &format!("{}_sq_copy", tmp), &format!("{}_sq", tmp));
    // x^3 = x * x^2
    kb_field_mul(t, name, &format!("{}_sq", tmp), &format!("{}_cube", tmp));
    t.rename(name);
}

// ===========================================================================
// External MDS: circ(2, 3, 1, 1) applied blockwise to 4 groups of 4
// ===========================================================================

/// p2kb_external_mds4 applies the circulant matrix circ(2,3,1,1) to a
/// 4-element block [a, b, c, d]:
///
///   sum = a + b + c + d
///   out0 = sum + a + 2*b  (= 2a + 3b + c + d)
///   out1 = sum + b + 2*c  (= a + 2b + 3c + d)
///   out2 = sum + c + 2*d  (= a + b + 2c + 3d)
///   out3 = sum + d + 2*a  (= 3a + b + c + 2d)
pub(crate) fn p2kb_external_mds4(
    t: &mut KBTracker,
    names: &[String; 4],
    round: i32,
    group: usize,
) {
    let prefix = format!("_p2mds_r{}_{}", round, group);

    // Compute sum = a + b + c + d (unreduced)
    t.copy_to_top(&names[0], &format!("{}_ca", prefix));
    t.copy_to_top(&names[1], &format!("{}_cb", prefix));
    kb_field_add_unreduced(t, &format!("{}_ca", prefix), &format!("{}_cb", prefix), &format!("{}_ab", prefix));
    t.copy_to_top(&names[2], &format!("{}_cc", prefix));
    kb_field_add_unreduced(t, &format!("{}_ab", prefix), &format!("{}_cc", prefix), &format!("{}_abc", prefix));
    t.copy_to_top(&names[3], &format!("{}_cd", prefix));
    kb_field_add_unreduced(t, &format!("{}_abc", prefix), &format!("{}_cd", prefix), &format!("{}_sum", prefix));

    // out0 = sum + a + 2*b
    t.copy_to_top(&format!("{}_sum", prefix), &format!("{}_s0", prefix));
    t.copy_to_top(&names[0], &format!("{}_a0", prefix));
    kb_field_add_unreduced(t, &format!("{}_s0", prefix), &format!("{}_a0", prefix), &format!("{}_sa0", prefix));
    t.copy_to_top(&names[1], &format!("{}_b0", prefix));
    kb_field_mul_const(t, &format!("{}_b0", prefix), 2, &format!("{}_2b0", prefix));
    kb_field_add(t, &format!("{}_sa0", prefix), &format!("{}_2b0", prefix), &format!("{}_out0", prefix));

    // out1 = sum + b + 2*c
    t.copy_to_top(&format!("{}_sum", prefix), &format!("{}_s1", prefix));
    t.copy_to_top(&names[1], &format!("{}_b1", prefix));
    kb_field_add_unreduced(t, &format!("{}_s1", prefix), &format!("{}_b1", prefix), &format!("{}_sb1", prefix));
    t.copy_to_top(&names[2], &format!("{}_c1", prefix));
    kb_field_mul_const(t, &format!("{}_c1", prefix), 2, &format!("{}_2c1", prefix));
    kb_field_add(t, &format!("{}_sb1", prefix), &format!("{}_2c1", prefix), &format!("{}_out1", prefix));

    // out2 = sum + c + 2*d
    t.copy_to_top(&format!("{}_sum", prefix), &format!("{}_s2", prefix));
    t.copy_to_top(&names[2], &format!("{}_c2", prefix));
    kb_field_add_unreduced(t, &format!("{}_s2", prefix), &format!("{}_c2", prefix), &format!("{}_sc2", prefix));
    t.copy_to_top(&names[3], &format!("{}_d2", prefix));
    kb_field_mul_const(t, &format!("{}_d2", prefix), 2, &format!("{}_2d2", prefix));
    kb_field_add(t, &format!("{}_sc2", prefix), &format!("{}_2d2", prefix), &format!("{}_out2", prefix));

    // out3 = sum + d + 2*a
    t.copy_to_top(&format!("{}_sum", prefix), &format!("{}_s3", prefix));
    t.copy_to_top(&names[3], &format!("{}_d3", prefix));
    kb_field_add_unreduced(t, &format!("{}_s3", prefix), &format!("{}_d3", prefix), &format!("{}_sd3", prefix));
    t.copy_to_top(&names[0], &format!("{}_a3", prefix));
    kb_field_mul_const(t, &format!("{}_a3", prefix), 2, &format!("{}_2a3", prefix));
    kb_field_add(t, &format!("{}_sd3", prefix), &format!("{}_2a3", prefix), &format!("{}_out3", prefix));

    // Drop old state elements and sum
    for name in names.iter() {
        t.to_top(name);
        t.drop();
    }
    t.to_top(&format!("{}_sum", prefix));
    t.drop();

    // Rename outputs to the original state names
    t.to_top(&format!("{}_out0", prefix));
    t.rename(&names[0]);
    t.to_top(&format!("{}_out1", prefix));
    t.rename(&names[1]);
    t.to_top(&format!("{}_out2", prefix));
    t.rename(&names[2]);
    t.to_top(&format!("{}_out3", prefix));
    t.rename(&names[3]);
}

/// p2kb_external_mds_full applies the external MDS to all 16 state elements.
pub(crate) fn p2kb_external_mds_full(
    t: &mut KBTracker,
    names: &mut [String; POSEIDON2_KB_WIDTH],
    round: i32,
) {
    // Step 1: Apply 4x4 MDS blockwise
    for g in 0..4 {
        let group: [String; 4] = [
            names[g * 4].clone(),
            names[g * 4 + 1].clone(),
            names[g * 4 + 2].clone(),
            names[g * 4 + 3].clone(),
        ];
        p2kb_external_mds4(t, &group, round, g);
    }

    // Step 2: Cross-group mixing
    // For each position k (0..3), compute sums[k] = state[k] + state[k+4] + state[k+8] + state[k+12]
    // Then add sums[k] to each state[i] where i % 4 == k
    let prefix = format!("_p2xg_r{}", round);
    for k in 0..4 {
        let sum_name = format!("{}_s{}", prefix, k);
        t.copy_to_top(&names[k], &sum_name);
        for j in 1..4 {
            let idx = k + j * 4;
            let add_name = format!("{}_a{}_{}", prefix, k, j);
            t.copy_to_top(&names[idx], &add_name);
            let new_sum = format!("{}_n", sum_name);
            kb_field_add(t, &sum_name, &add_name, &new_sum);
            t.rename(&sum_name);
        }
    }

    // Add sums[i%4] to each element
    for i in 0..POSEIDON2_KB_WIDTH {
        let k = i % 4;
        let sum_name = format!("{}_s{}", prefix, k);
        let copy_name = format!("{}_sc{}", prefix, i);
        t.copy_to_top(&sum_name, &copy_name);
        let name_i = names[i].clone();
        kb_field_add(t, &name_i, &copy_name, &name_i);
    }

    // Clean up: drop the 4 sum accumulators
    for k in 0..4 {
        t.to_top(&format!("{}_s{}", prefix, k));
        t.drop();
    }
}

// ===========================================================================
// Internal diffusion: diagonal matrix + sum
// ===========================================================================

/// p2kb_internal_diffusion applies the internal linear layer:
///   sum = sum(state[i])
///   state[i] = state[i] * diag_m_1[i] + sum   for each i
pub(crate) fn p2kb_internal_diffusion(
    t: &mut KBTracker,
    names: &mut [String; POSEIDON2_KB_WIDTH],
    round: i32,
) {
    let prefix = format!("_p2id_r{}", round);

    // Step 1: Compute sum of all state elements.
    t.copy_to_top(&names[0], &format!("{}_acc", prefix));
    for i in 1..POSEIDON2_KB_WIDTH {
        let add_name = format!("{}_add{}", prefix, i);
        t.copy_to_top(&names[i], &add_name);
        let new_acc = format!("{}_acc_new", prefix);
        kb_field_add(t, &format!("{}_acc", prefix), &add_name, &new_acc);
        t.rename(&format!("{}_acc", prefix));
    }
    t.rename(&format!("{}_sum", prefix));

    // Step 2: For each element, compute state[i] = state[i] * diag_m_1[i] + sum.
    for i in 0..POSEIDON2_KB_WIDTH {
        let diag = POSEIDON2_KB_INTERNAL_DIAG_M1[i];
        let prod_name = format!("{}_prod{}", prefix, i);

        if diag == 1 {
            // Multiplication by 1 is identity -- just copy
            t.copy_to_top(&names[i], &prod_name);
        } else {
            let si_name = format!("{}_si{}", prefix, i);
            t.copy_to_top(&names[i], &si_name);
            kb_field_mul_const(t, &si_name, diag, &prod_name);
        }

        // Add sum
        let sc_name = format!("{}_sc{}", prefix, i);
        t.copy_to_top(&format!("{}_sum", prefix), &sc_name);
        let result_name = format!("{}_out{}", prefix, i);
        kb_field_add(t, &prod_name, &sc_name, &result_name);
    }

    // Step 3: Drop old state elements and sum, rename outputs.
    for i in 0..POSEIDON2_KB_WIDTH {
        t.to_top(&names[i]);
        t.drop();
    }
    t.to_top(&format!("{}_sum", prefix));
    t.drop();

    for i in 0..POSEIDON2_KB_WIDTH {
        t.to_top(&format!("{}_out{}", prefix, i));
        t.rename(&names[i]);
    }
}

// ===========================================================================
// Add round constants
// ===========================================================================

/// p2kb_add_round_constants adds round constants to all 16 state elements.
/// Used in external rounds.
pub(crate) fn p2kb_add_round_constants(
    t: &mut KBTracker,
    names: &mut [String; POSEIDON2_KB_WIDTH],
    round: usize,
) {
    for i in 0..POSEIDON2_KB_WIDTH {
        let rc = POSEIDON2_KB_ROUND_CONSTANTS[round][i];
        if rc == 0 {
            continue; // Skip zero round constants (no-op addition)
        }
        let prefix = format!("_p2rc_r{}_{}", round, i);
        let c_name = format!("{}_c", prefix);
        let sum_name = format!("{}_sum", prefix);
        t.push_int(&c_name, rc);
        let name_i = names[i].clone();
        kb_field_add(t, &name_i, &c_name, &sum_name);
        t.rename(&names[i]);
    }
}

/// p2kb_add_round_constant_elem0 adds the round constant to element 0 only.
/// Used in internal rounds.
pub(crate) fn p2kb_add_round_constant_elem0(
    t: &mut KBTracker,
    names: &mut [String; POSEIDON2_KB_WIDTH],
    round: usize,
) {
    let rc = POSEIDON2_KB_ROUND_CONSTANTS[round][0];
    if rc == 0 {
        return;
    }
    let prefix = format!("_p2rc_r{}_0", round);
    let c_name = format!("{}_c", prefix);
    let sum_name = format!("{}_sum", prefix);
    t.push_int(&c_name, rc);
    let name0 = names[0].clone();
    kb_field_add(t, &name0, &c_name, &sum_name);
    t.rename(&names[0]);
}

// ===========================================================================
// Full Poseidon2 permutation
// ===========================================================================

/// p2kb_permute applies the full Poseidon2 permutation to 16 state elements.
///
/// Algorithm:
///   Initial -- external MDS (Plonky3's external_initial_permute_state)
///   Phase 1 -- 4 external rounds (rounds 0-3):
///     add round constants, full sbox, external MDS (blockwise + cross-group)
///   Phase 2 -- 20 internal rounds (rounds 4-23):
///     add round constant to elem 0, sbox on elem 0, internal diffusion
///   Phase 3 -- 4 external rounds (rounds 24-27):
///     add round constants, full sbox, external MDS (blockwise + cross-group)
pub(crate) fn p2kb_permute(t: &mut KBTracker, names: &mut [String; POSEIDON2_KB_WIDTH]) {
    // Initial MDS before external rounds
    p2kb_external_mds_full(t, names, -1);

    // Phase 1: 4 external rounds (rounds 0-3)
    for r in 0..4 {
        p2kb_add_round_constants(t, names, r);
        for i in 0..POSEIDON2_KB_WIDTH {
            let name = names[i].clone();
            p2kb_sbox(t, &name, r as i32, i);
        }
        p2kb_external_mds_full(t, names, r as i32);
    }

    // Phase 2: 20 internal rounds (rounds 4-23)
    for r in 4..(4 + POSEIDON2_KB_INTERNAL_ROUNDS) {
        p2kb_add_round_constant_elem0(t, names, r);
        let name0 = names[0].clone();
        p2kb_sbox(t, &name0, r as i32, 0);
        p2kb_internal_diffusion(t, names, r as i32);
    }

    // Phase 3: 4 external rounds (rounds 24-27)
    for r in (4 + POSEIDON2_KB_INTERNAL_ROUNDS)..POSEIDON2_KB_TOTAL_ROUNDS {
        p2kb_add_round_constants(t, names, r);
        for i in 0..POSEIDON2_KB_WIDTH {
            let name = names[i].clone();
            p2kb_sbox(t, &name, r as i32, i);
        }
        p2kb_external_mds_full(t, names, r as i32);
    }
}

// ===========================================================================
// Public emit functions
// ===========================================================================

/// emit_poseidon2_kb_permute emits the full Poseidon2 permutation over KoalaBear.
///
/// Stack in:  [..., s0, s1, ..., s15] (s15 on top)
/// Stack out: [..., s0', s1', ..., s15'] (s15' on top)
pub fn emit_poseidon2_kb_permute(emit: &mut dyn FnMut(StackOp)) {
    let init_names: Vec<String> = (0..POSEIDON2_KB_WIDTH).map(p2kb_state_name).collect();
    let t = &mut KBTracker::new_from_strings(&init_names, emit);
    t.push_prime_cache();

    let mut names = p2kb_state_names();
    p2kb_permute(t, &mut names);

    t.pop_prime_cache();

    // Reorder so _p2s0 is deepest and _p2s15 is on top
    for i in 0..POSEIDON2_KB_WIDTH {
        t.to_top(&p2kb_state_name(i));
    }
}

/// emit_poseidon2_kb_compress emits Poseidon2 compression (permute + truncate to 8 elements).
///
/// Stack in:  [..., s0, s1, ..., s15] (s15 on top)
/// Stack out: [..., h0, h1, ..., h7] (h7 on top)
///
/// The digest is the first 8 elements of the permuted state.
pub fn emit_poseidon2_kb_compress(emit: &mut dyn FnMut(StackOp)) {
    let init_names: Vec<String> = (0..POSEIDON2_KB_WIDTH).map(p2kb_state_name).collect();
    let t = &mut KBTracker::new_from_strings(&init_names, emit);
    t.push_prime_cache();

    let mut names = p2kb_state_names();
    p2kb_permute(t, &mut names);

    t.pop_prime_cache();

    // Drop elements 8-15 (the non-digest portion)
    for i in 8..POSEIDON2_KB_WIDTH {
        t.to_top(&p2kb_state_name(i));
        t.drop();
    }

    // Reorder digest elements so _p2s0 is deepest, _p2s7 on top
    for i in 0..8 {
        t.to_top(&p2kb_state_name(i));
    }
}
