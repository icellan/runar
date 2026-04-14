//! Poseidon2 permutation over KoalaBear field — codegen for Bitcoin Script.
//!
//! Implements the Poseidon2 hash function used by SP1 v6 for Merkle commitments
//! and Fiat-Shamir challenges. All operations use the KoalaBear prime field
//! (p = 2^31 - 2^24 + 1 = 2,130,706,433).
//!
//! Parameters (SP1 v6.0.2):
//!   - State width: 16 KoalaBear field elements
//!   - Sbox: x^3 (cube)
//!   - External rounds: 8 (4 before internal, 4 after)
//!   - Internal rounds: 20
//!   - Total rounds: 28
//!   - Digest: first 8 elements of the output state
//!
//! Constants from Plonky3 p3-koala-bear/src/poseidon2.rs (SP1 v6.0.2).
//!
//! This module provides internal codegen functions called by Merkle verification
//! and sponge codegen modules. It is NOT registered as a contract-level builtin.

const std = @import("std");
const kb = @import("koalabear_emitters.zig");
const ec = @import("ec_emitters.zig");

const Allocator = std.mem.Allocator;
const KBTracker = kb.KBTracker;
const EcOpBundle = ec.EcOpBundle;
const StackOp = ec.StackOp;
const PushValue = ec.PushValue;

// ===========================================================================
// Poseidon2 KoalaBear constants
// ===========================================================================

const poseidon2KBWidth: usize = 16;
const poseidon2KBExternalRounds: usize = 8;
const poseidon2KBInternalRounds: usize = 20;
const poseidon2KBTotalRounds: usize = poseidon2KBExternalRounds + poseidon2KBInternalRounds;

/// Internal diagonal M-1 entries for the diffusion layer.
/// From Plonky3 DiffusionMatrixKoalaBear.
///
/// V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/8, 1/2^24, -1/2^8, -1/8, -1/16, -1/2^24]
const poseidon2KBInternalDiagM1 = [poseidon2KBWidth]i64{
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
};

/// Round constants for all 28 rounds.
/// For external rounds all 16 entries are used.
/// For internal rounds (4-23) only element [0] is used.
const poseidon2KBRoundConstants = [poseidon2KBTotalRounds][poseidon2KBWidth]i64{
    // External initial rounds (0-3)
    .{ 2128964168, 288780357, 316938561, 2126233899, 426817493, 1714118888, 1045008582, 1738510837, 889721787, 8866516, 681576474, 419059826, 1596305521, 1583176088, 1584387047, 1529751136 },
    .{ 1863858111, 1072044075, 517831365, 1464274176, 1138001621, 428001039, 245709561, 1641420379, 1365482496, 770454828, 693167409, 757905735, 136670447, 436275702, 525466355, 1559174242 },
    .{ 1030087950, 869864998, 322787870, 267688717, 948964561, 740478015, 679816114, 113662466, 2066544572, 1744924186, 367094720, 1380455578, 1842483872, 416711434, 1342291586, 1692058446 },
    .{ 1493348999, 1113949088, 210900530, 1071655077, 610242121, 1136339326, 2020858841, 1019840479, 678147278, 1678413261, 1361743414, 61132629, 1209546658, 64412292, 1936878279, 1980661727 },
    // Internal rounds (4-23) — only element [0] is used
    .{ 1423960925, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 2101391318, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1915532054, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 275400051, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1168624859, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1141248885, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 356546469, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1165250474, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1320543726, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 932505663, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1204226364, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1452576828, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1774936729, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 926808140, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1184948056, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1186493834, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 843181003, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 185193011, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 452207447, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 510054082, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    // External final rounds (24-27)
    .{ 1139268644, 630873441, 669538875, 462500858, 876500520, 1214043330, 383937013, 375087302, 636912601, 307200505, 390279673, 1999916485, 1518476730, 1606686591, 1410677749, 1581191572 },
    .{ 1004269969, 143426723, 1747283099, 1016118214, 1749423722, 66331533, 1177761275, 1581069649, 1851371119, 852520128, 1499632627, 1820847538, 150757557, 884787840, 619710451, 1651711087 },
    .{ 505263814, 212076987, 1482432120, 1458130652, 382871348, 417404007, 2066495280, 1996518884, 902934924, 582892981, 1337064375, 1199354861, 2102596038, 1533193853, 1436311464, 2012303432 },
    .{ 839997195, 1225781098, 2011967775, 575084315, 1309329169, 786393545, 995788880, 1702925345, 1444525226, 908073383, 1811535085, 1531002367, 1635653662, 1585100155, 867006515, 879151050 },
};

// ===========================================================================
// State naming helpers
// ===========================================================================

/// p2kbStateName returns the canonical name for state element i.
pub fn p2kbStateName(i: usize, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "_p2s{d}", .{i}) catch unreachable;
}

// ===========================================================================
// Sbox: x^3 (cube) over KoalaBear field
// ===========================================================================

/// poseidon2KBSbox computes state[name] = state[name]^3 mod p.
/// Uses: x^3 = x * x^2.
fn poseidon2KBSbox(t: *KBTracker, name: []const u8, round: usize, idx: usize, alloc: Allocator) !void {
    var tmp_sq_copy_buf: [32]u8 = undefined;
    var tmp_sq_buf: [32]u8 = undefined;
    var tmp_cube_buf: [32]u8 = undefined;

    const tmp_sq_copy = try std.fmt.bufPrint(&tmp_sq_copy_buf, "_p2sbox_r{d}_{d}_sq_copy", .{ round, idx });
    const tmp_sq = try std.fmt.bufPrint(&tmp_sq_buf, "_p2sbox_r{d}_{d}_sq", .{ round, idx });
    const tmp_cube = try std.fmt.bufPrint(&tmp_cube_buf, "_p2sbox_r{d}_{d}_cube", .{ round, idx });

    // Allocate owned copies for the tracker's name list
    const sq_copy_owned = try alloc.dupe(u8, tmp_sq_copy);
    errdefer alloc.free(sq_copy_owned);
    const sq_owned = try alloc.dupe(u8, tmp_sq);
    errdefer alloc.free(sq_owned);
    const cube_owned = try alloc.dupe(u8, tmp_cube);
    errdefer alloc.free(cube_owned);

    try t.owned_bytes.append(alloc, sq_copy_owned);
    try t.owned_bytes.append(alloc, sq_owned);
    try t.owned_bytes.append(alloc, cube_owned);

    // x^2
    try t.copyToTop(name, sq_copy_owned);
    try kb.kbFieldSqr(t, sq_copy_owned, sq_owned);
    // x^3 = x * x^2
    try kb.kbFieldMul(t, name, sq_owned, cube_owned);
    t.renameTop(name);
}

// ===========================================================================
// External MDS: circ(2, 3, 1, 1) applied blockwise to 4 groups of 4
// ===========================================================================

/// poseidon2KBExternalMDS4 applies the circulant matrix circ(2,3,1,1) to a
/// 4-element block [a, b, c, d]:
///   sum = a + b + c + d
///   out0 = sum + a + 2*b  (= 2a + 3b + c + d)
///   out1 = sum + b + 2*c  (= a + 2b + 3c + d)
///   out2 = sum + c + 2*d  (= a + b + 2c + 3d)
///   out3 = sum + d + 2*a  (= 3a + b + c + 2d)
fn poseidon2KBExternalMDS4(
    t: *KBTracker,
    names: *[4][]const u8,
    round: usize,
    group: usize,
    alloc: Allocator,
) !void {
    // All temp name buffers
    var prefix_buf: [32]u8 = undefined;
    const prefix = try std.fmt.bufPrint(&prefix_buf, "_p2mds_r{d}_g{d}", .{ round, group });

    // Helper to create owned temp names
    const mkname = struct {
        fn f(a: Allocator, p: []const u8, suffix: []const u8, owned: *std.ArrayListUnmanaged([]u8)) ![]const u8 {
            var buf: [64]u8 = undefined;
            const s = try std.fmt.bufPrint(&buf, "{s}{s}", .{ p, suffix });
            const owned_copy = try a.dupe(u8, s);
            try owned.append(a, owned_copy);
            return owned_copy;
        }
    }.f;

    const n_ca = try mkname(alloc, prefix, "_ca", &t.owned_bytes);
    const n_cb = try mkname(alloc, prefix, "_cb", &t.owned_bytes);
    const n_ab = try mkname(alloc, prefix, "_ab", &t.owned_bytes);
    const n_cc = try mkname(alloc, prefix, "_cc", &t.owned_bytes);
    const n_abc = try mkname(alloc, prefix, "_abc", &t.owned_bytes);
    const n_cd = try mkname(alloc, prefix, "_cd", &t.owned_bytes);
    const n_sum = try mkname(alloc, prefix, "_sum", &t.owned_bytes);

    // Compute sum = a + b + c + d (unreduced)
    try t.copyToTop(names[0], n_ca);
    try t.copyToTop(names[1], n_cb);
    try kb.kbFieldAddUnreduced(t, n_ca, n_cb, n_ab);
    try t.copyToTop(names[2], n_cc);
    try kb.kbFieldAddUnreduced(t, n_ab, n_cc, n_abc);
    try t.copyToTop(names[3], n_cd);
    try kb.kbFieldAddUnreduced(t, n_abc, n_cd, n_sum);

    // out0 = sum + a + 2*b
    const n_s0 = try mkname(alloc, prefix, "_s0", &t.owned_bytes);
    const n_a0 = try mkname(alloc, prefix, "_a0", &t.owned_bytes);
    const n_sa0 = try mkname(alloc, prefix, "_sa0", &t.owned_bytes);
    const n_b0 = try mkname(alloc, prefix, "_b0", &t.owned_bytes);
    const n_2b0 = try mkname(alloc, prefix, "_2b0", &t.owned_bytes);
    const n_out0 = try mkname(alloc, prefix, "_out0", &t.owned_bytes);
    try t.copyToTop(n_sum, n_s0);
    try t.copyToTop(names[0], n_a0);
    try kb.kbFieldAddUnreduced(t, n_s0, n_a0, n_sa0);
    try t.copyToTop(names[1], n_b0);
    try kb.kbFieldMulConst(t, n_b0, 2, n_2b0);
    try kb.kbFieldAdd(t, n_sa0, n_2b0, n_out0);

    // out1 = sum + b + 2*c
    const n_s1 = try mkname(alloc, prefix, "_s1", &t.owned_bytes);
    const n_b1 = try mkname(alloc, prefix, "_b1", &t.owned_bytes);
    const n_sb1 = try mkname(alloc, prefix, "_sb1", &t.owned_bytes);
    const n_c1 = try mkname(alloc, prefix, "_c1", &t.owned_bytes);
    const n_2c1 = try mkname(alloc, prefix, "_2c1", &t.owned_bytes);
    const n_out1 = try mkname(alloc, prefix, "_out1", &t.owned_bytes);
    try t.copyToTop(n_sum, n_s1);
    try t.copyToTop(names[1], n_b1);
    try kb.kbFieldAddUnreduced(t, n_s1, n_b1, n_sb1);
    try t.copyToTop(names[2], n_c1);
    try kb.kbFieldMulConst(t, n_c1, 2, n_2c1);
    try kb.kbFieldAdd(t, n_sb1, n_2c1, n_out1);

    // out2 = sum + c + 2*d
    const n_s2 = try mkname(alloc, prefix, "_s2", &t.owned_bytes);
    const n_c2 = try mkname(alloc, prefix, "_c2", &t.owned_bytes);
    const n_sc2 = try mkname(alloc, prefix, "_sc2", &t.owned_bytes);
    const n_d2 = try mkname(alloc, prefix, "_d2", &t.owned_bytes);
    const n_2d2 = try mkname(alloc, prefix, "_2d2", &t.owned_bytes);
    const n_out2 = try mkname(alloc, prefix, "_out2", &t.owned_bytes);
    try t.copyToTop(n_sum, n_s2);
    try t.copyToTop(names[2], n_c2);
    try kb.kbFieldAddUnreduced(t, n_s2, n_c2, n_sc2);
    try t.copyToTop(names[3], n_d2);
    try kb.kbFieldMulConst(t, n_d2, 2, n_2d2);
    try kb.kbFieldAdd(t, n_sc2, n_2d2, n_out2);

    // out3 = sum + d + 2*a
    const n_s3 = try mkname(alloc, prefix, "_s3", &t.owned_bytes);
    const n_d3 = try mkname(alloc, prefix, "_d3", &t.owned_bytes);
    const n_sd3 = try mkname(alloc, prefix, "_sd3", &t.owned_bytes);
    const n_a3 = try mkname(alloc, prefix, "_a3", &t.owned_bytes);
    const n_2a3 = try mkname(alloc, prefix, "_2a3", &t.owned_bytes);
    const n_out3 = try mkname(alloc, prefix, "_out3", &t.owned_bytes);
    try t.copyToTop(n_sum, n_s3);
    try t.copyToTop(names[3], n_d3);
    try kb.kbFieldAddUnreduced(t, n_s3, n_d3, n_sd3);
    try t.copyToTop(names[0], n_a3);
    try kb.kbFieldMulConst(t, n_a3, 2, n_2a3);
    try kb.kbFieldAdd(t, n_sd3, n_2a3, n_out3);

    // Drop old state elements and sum
    try t.toTop(names[0]);
    try t.drop();
    try t.toTop(names[1]);
    try t.drop();
    try t.toTop(names[2]);
    try t.drop();
    try t.toTop(names[3]);
    try t.drop();
    try t.toTop(n_sum);
    try t.drop();

    // Rename outputs to the original state names
    try t.toTop(n_out0);
    t.renameTop(names[0]);
    try t.toTop(n_out1);
    t.renameTop(names[1]);
    try t.toTop(n_out2);
    t.renameTop(names[2]);
    try t.toTop(n_out3);
    t.renameTop(names[3]);
}

/// poseidon2KBExternalMDSFull applies the external MDS to all 16 state elements.
fn poseidon2KBExternalMDSFull(
    t: *KBTracker,
    names: *[poseidon2KBWidth][]const u8,
    round: usize,
    alloc: Allocator,
) !void {
    // Step 1: Apply 4x4 MDS blockwise
    for (0..4) |g| {
        var group = [4][]const u8{
            names[g * 4],
            names[g * 4 + 1],
            names[g * 4 + 2],
            names[g * 4 + 3],
        };
        try poseidon2KBExternalMDS4(t, &group, round, g, alloc);
    }

    // Step 2: Cross-group mixing
    // For each position k (0..3), compute sums[k] = state[k] + state[k+4] + state[k+8] + state[k+12]
    // Then add sums[k] to each state[i] where i % 4 == k
    var prefix_buf: [32]u8 = undefined;
    const prefix = try std.fmt.bufPrint(&prefix_buf, "_p2xg_r{d}", .{round});

    const mkname = struct {
        fn f(a: Allocator, p: []const u8, k: usize, suffix: []const u8, owned: *std.ArrayListUnmanaged([]u8)) ![]const u8 {
            var buf: [64]u8 = undefined;
            const s = try std.fmt.bufPrint(&buf, "{s}_s{d}{s}", .{ p, k, suffix });
            const owned_copy = try a.dupe(u8, s);
            try owned.append(a, owned_copy);
            return owned_copy;
        }
    }.f;

    // Build cross-group sums
    var sum_names: [4][]const u8 = undefined;
    for (0..4) |k| {
        const sum_name = try mkname(alloc, prefix, k, "", &t.owned_bytes);
        sum_names[k] = sum_name;
        try t.copyToTop(names[k], sum_name);
        for (1..4) |j| {
            const idx = k + j * 4;
            var add_buf: [64]u8 = undefined;
            const add_name_str = try std.fmt.bufPrint(&add_buf, "{s}_a{d}_{d}", .{ prefix, k, j });
            const add_name_owned = try alloc.dupe(u8, add_name_str);
            try t.owned_bytes.append(alloc, add_name_owned);

            var new_sum_buf: [64]u8 = undefined;
            const new_sum_str = try std.fmt.bufPrint(&new_sum_buf, "{s}_s{d}_n{d}", .{ prefix, k, j });
            const new_sum_owned = try alloc.dupe(u8, new_sum_str);
            try t.owned_bytes.append(alloc, new_sum_owned);

            try t.copyToTop(names[idx], add_name_owned);
            try kb.kbFieldAdd(t, sum_name, add_name_owned, new_sum_owned);
            t.renameTop(sum_name);
        }
    }

    // Add sums[i%4] to each element
    for (0..poseidon2KBWidth) |i| {
        const k = i % 4;
        var copy_buf: [64]u8 = undefined;
        const copy_name_str = try std.fmt.bufPrint(&copy_buf, "{s}_sc{d}", .{ prefix, i });
        const copy_name_owned = try alloc.dupe(u8, copy_name_str);
        try t.owned_bytes.append(alloc, copy_name_owned);

        try t.copyToTop(sum_names[k], copy_name_owned);
        try kb.kbFieldAdd(t, names[i], copy_name_owned, names[i]);
    }

    // Drop the 4 sum accumulators
    for (0..4) |k| {
        try t.toTop(sum_names[k]);
        try t.drop();
    }
}

// ===========================================================================
// Internal diffusion: diagonal matrix + sum
// ===========================================================================

/// poseidon2KBInternalDiffusion applies the internal linear layer:
///   sum = sum(state[i])
///   state[i] = state[i] * diag_m_1[i] + sum   for each i
fn poseidon2KBInternalDiffusion(
    t: *KBTracker,
    names: *[poseidon2KBWidth][]const u8,
    round: usize,
    alloc: Allocator,
) !void {
    var prefix_buf: [32]u8 = undefined;
    const prefix = try std.fmt.bufPrint(&prefix_buf, "_p2id_r{d}", .{round});

    const mkowned = struct {
        fn f(a: Allocator, s: []const u8, owned: *std.ArrayListUnmanaged([]u8)) ![]const u8 {
            const copy = try a.dupe(u8, s);
            try owned.append(a, copy);
            return copy;
        }
    }.f;

    // Step 1: Compute sum of all state elements.
    var acc_buf: [64]u8 = undefined;
    const acc_name = try mkowned(alloc, try std.fmt.bufPrint(&acc_buf, "{s}_acc", .{prefix}), &t.owned_bytes);
    try t.copyToTop(names[0], acc_name);

    for (1..poseidon2KBWidth) |i| {
        var add_buf: [64]u8 = undefined;
        const add_name = try mkowned(alloc, try std.fmt.bufPrint(&add_buf, "{s}_add{d}", .{ prefix, i }), &t.owned_bytes);
        var new_acc_buf: [64]u8 = undefined;
        const new_acc = try mkowned(alloc, try std.fmt.bufPrint(&new_acc_buf, "{s}_acc_new{d}", .{ prefix, i }), &t.owned_bytes);

        try t.copyToTop(names[i], add_name);
        try kb.kbFieldAdd(t, acc_name, add_name, new_acc);
        t.renameTop(acc_name);
    }

    var sum_buf: [64]u8 = undefined;
    const sum_name = try mkowned(alloc, try std.fmt.bufPrint(&sum_buf, "{s}_sum", .{prefix}), &t.owned_bytes);
    t.renameTop(sum_name);

    // Step 2: For each element, compute state[i] = state[i] * diag_m_1[i] + sum.
    var prod_names: [poseidon2KBWidth][]const u8 = undefined;
    for (0..poseidon2KBWidth) |i| {
        const diag = poseidon2KBInternalDiagM1[i];
        var prod_buf: [64]u8 = undefined;
        const prod_name = try mkowned(alloc, try std.fmt.bufPrint(&prod_buf, "{s}_prod{d}", .{ prefix, i }), &t.owned_bytes);
        prod_names[i] = prod_name;

        if (diag == 1) {
            // Multiplication by 1 is identity — just copy
            try t.copyToTop(names[i], prod_name);
        } else {
            var si_buf: [64]u8 = undefined;
            const si_name = try mkowned(alloc, try std.fmt.bufPrint(&si_buf, "{s}_si{d}", .{ prefix, i }), &t.owned_bytes);
            try t.copyToTop(names[i], si_name);
            try kb.kbFieldMulConst(t, si_name, diag, prod_name);
        }

        // Add sum
        var sc_buf: [64]u8 = undefined;
        const sc_name = try mkowned(alloc, try std.fmt.bufPrint(&sc_buf, "{s}_sc{d}", .{ prefix, i }), &t.owned_bytes);
        var out_buf: [64]u8 = undefined;
        const out_name = try mkowned(alloc, try std.fmt.bufPrint(&out_buf, "{s}_out{d}", .{ prefix, i }), &t.owned_bytes);

        try t.copyToTop(sum_name, sc_name);
        try kb.kbFieldAdd(t, prod_name, sc_name, out_name);
    }

    // Step 3: Drop old state elements and sum, rename outputs.
    for (0..poseidon2KBWidth) |i| {
        try t.toTop(names[i]);
        try t.drop();
    }
    try t.toTop(sum_name);
    try t.drop();

    for (0..poseidon2KBWidth) |i| {
        var out_buf: [64]u8 = undefined;
        const out_name = try std.fmt.bufPrint(&out_buf, "{s}_out{d}", .{ prefix, i });
        // Find by linear scan (owned_bytes holds the pointer)
        try t.toTop(out_name);
        t.renameTop(names[i]);
    }
}

// ===========================================================================
// Add round constants
// ===========================================================================

/// poseidon2KBAddRoundConstants adds round constants to all 16 state elements.
/// Used in external rounds.
fn poseidon2KBAddRoundConstants(
    t: *KBTracker,
    names: *[poseidon2KBWidth][]const u8,
    round: usize,
    alloc: Allocator,
) !void {
    for (0..poseidon2KBWidth) |i| {
        const rc = poseidon2KBRoundConstants[round][i];
        if (rc == 0) continue; // Skip zero round constants
        var prefix_buf: [64]u8 = undefined;
        const prefix = try std.fmt.bufPrint(&prefix_buf, "_p2rc_r{d}_{d}", .{ round, i });
        var c_buf: [64]u8 = undefined;
        const c_name_str = try std.fmt.bufPrint(&c_buf, "{s}_c", .{prefix});
        const c_name = try alloc.dupe(u8, c_name_str);
        try t.owned_bytes.append(alloc, c_name);
        var sum_buf: [64]u8 = undefined;
        const sum_name_str = try std.fmt.bufPrint(&sum_buf, "{s}_sum", .{prefix});
        const sum_name = try alloc.dupe(u8, sum_name_str);
        try t.owned_bytes.append(alloc, sum_name);

        try t.pushInt(c_name, rc);
        try kb.kbFieldAdd(t, names[i], c_name, sum_name);
        t.renameTop(names[i]);
    }
}

/// poseidon2KBAddRoundConstantElem0 adds the round constant to element 0 only.
/// Used in internal rounds.
fn poseidon2KBAddRoundConstantElem0(
    t: *KBTracker,
    names: *[poseidon2KBWidth][]const u8,
    round: usize,
    alloc: Allocator,
) !void {
    const rc = poseidon2KBRoundConstants[round][0];
    if (rc == 0) return;
    var prefix_buf: [64]u8 = undefined;
    const prefix = try std.fmt.bufPrint(&prefix_buf, "_p2rc_r{d}_0", .{round});
    var c_buf: [64]u8 = undefined;
    const c_name_str = try std.fmt.bufPrint(&c_buf, "{s}_c", .{prefix});
    const c_name = try alloc.dupe(u8, c_name_str);
    try t.owned_bytes.append(alloc, c_name);
    var sum_buf: [64]u8 = undefined;
    const sum_name_str = try std.fmt.bufPrint(&sum_buf, "{s}_sum", .{prefix});
    const sum_name = try alloc.dupe(u8, sum_name_str);
    try t.owned_bytes.append(alloc, sum_name);

    try t.pushInt(c_name, rc);
    try kb.kbFieldAdd(t, names[0], c_name, sum_name);
    t.renameTop(names[0]);
}

// ===========================================================================
// Full Poseidon2 permutation
// ===========================================================================

/// poseidon2KBPermute applies the full Poseidon2 permutation to 16 state elements.
///
/// Algorithm:
///   Initial — external MDS (Plonky3's external_initial_permute_state)
///   Phase 1 — 4 external rounds (rounds 0-3)
///   Phase 2 — 20 internal rounds (rounds 4-23)
///   Phase 3 — 4 external rounds (rounds 24-27)
fn poseidon2KBPermute(t: *KBTracker, names: *[poseidon2KBWidth][]const u8, alloc: Allocator) !void {
    // Initial MDS before external rounds
    try poseidon2KBExternalMDSFull(t, names, poseidon2KBTotalRounds, alloc); // use sentinel round for names

    // Phase 1: 4 external rounds (rounds 0-3)
    for (0..4) |r| {
        try poseidon2KBAddRoundConstants(t, names, r, alloc);
        for (0..poseidon2KBWidth) |i| {
            try poseidon2KBSbox(t, names[i], r, i, alloc);
        }
        try poseidon2KBExternalMDSFull(t, names, r, alloc);
    }

    // Phase 2: 20 internal rounds (rounds 4-23)
    for (4..4 + poseidon2KBInternalRounds) |r| {
        try poseidon2KBAddRoundConstantElem0(t, names, r, alloc);
        try poseidon2KBSbox(t, names[0], r, 0, alloc);
        try poseidon2KBInternalDiffusion(t, names, r, alloc);
    }

    // Phase 3: 4 external rounds (rounds 24-27)
    for (4 + poseidon2KBInternalRounds..poseidon2KBTotalRounds) |r| {
        try poseidon2KBAddRoundConstants(t, names, r, alloc);
        for (0..poseidon2KBWidth) |i| {
            try poseidon2KBSbox(t, names[i], r, i, alloc);
        }
        try poseidon2KBExternalMDSFull(t, names, r, alloc);
    }
}

// ===========================================================================
// Public emit functions
// ===========================================================================

/// emitPoseidon2KBPermute emits the full Poseidon2 permutation over KoalaBear.
///
/// Stack in:  [..., s0, s1, ..., s15] (s15 on top)
/// Stack out: [..., s0', s1', ..., s15'] (s15' on top)
pub fn emitPoseidon2KBPermute(allocator: Allocator, emit_fn: *const fn (StackOp) void) !void {
    // Build static state names
    var name_bufs: [poseidon2KBWidth][16]u8 = undefined;
    var name_ptrs: [poseidon2KBWidth][]const u8 = undefined;
    for (0..poseidon2KBWidth) |i| {
        const s = std.fmt.bufPrint(&name_bufs[i], "_p2s{d}", .{i}) catch unreachable;
        name_ptrs[i] = s;
    }

    // We need a KBTracker that wraps a function pointer emitter.
    // Use an arena-style approach: build ops into a list then replay.
    var ops_list: std.ArrayListUnmanaged(StackOp) = .empty;
    defer {
        ec.deinitOpsRecursive(allocator, ops_list.items);
        ops_list.deinit(allocator);
    }

    // Wrap emit function into a closure that appends to ops_list.
    // We use a struct with state for the callback.
    const emit_ctx = EmitCtx{ .list = &ops_list, .allocator = allocator };

    var initial_names: [poseidon2KBWidth]?[]const u8 = undefined;
    for (0..poseidon2KBWidth) |i| {
        initial_names[i] = name_ptrs[i];
    }

    var tracker = try KBTracker.init(allocator, &initial_names);
    defer tracker.deinit();

    try tracker.pushPrimeCache();

    var names_copy: [poseidon2KBWidth][]const u8 = name_ptrs;
    try poseidon2KBPermute(&tracker, &names_copy, allocator);

    try tracker.popPrimeCache();

    // Reorder so _p2s0 is deepest and _p2s15 is on top
    for (0..poseidon2KBWidth) |i| {
        try tracker.toTop(names_copy[i]);
    }

    // Replay ops via emit_fn
    _ = emit_ctx;
    for (tracker.ops.items) |op| {
        emit_fn(op);
    }
}

/// EmitCtx is a placeholder (unused but kept for pattern consistency).
const EmitCtx = struct {
    list: *std.ArrayListUnmanaged(StackOp),
    allocator: Allocator,
};

/// buildPermuteBundleOps builds a KBTracker bundle for the full permutation.
/// Used internally by fiat_shamir_kb.zig and poseidon2_merkle.zig.
pub fn buildPermuteBundleOps(allocator: Allocator) !EcOpBundle {
    var name_bufs: [poseidon2KBWidth][16]u8 = undefined;
    var initial_names: [poseidon2KBWidth]?[]const u8 = undefined;
    for (0..poseidon2KBWidth) |i| {
        const s = std.fmt.bufPrint(&name_bufs[i], "_p2s{d}", .{i}) catch unreachable;
        initial_names[i] = s;
    }

    var tracker = try KBTracker.init(allocator, &initial_names);
    errdefer tracker.deinit();

    try tracker.pushPrimeCache();

    var name_ptrs: [poseidon2KBWidth][]const u8 = undefined;
    for (0..poseidon2KBWidth) |i| {
        name_ptrs[i] = initial_names[i].?;
    }

    try poseidon2KBPermute(&tracker, &name_ptrs, allocator);
    try tracker.popPrimeCache();

    // Reorder so _p2s0 is deepest and _p2s15 is on top
    for (0..poseidon2KBWidth) |i| {
        try tracker.toTop(name_ptrs[i]);
    }

    return tracker.takeBundle();
}

/// buildCompressBundleOps builds ops for Poseidon2 compression (permute + drop elems 8-15).
pub fn buildCompressBundleOps(allocator: Allocator) !EcOpBundle {
    var name_bufs: [poseidon2KBWidth][16]u8 = undefined;
    var initial_names: [poseidon2KBWidth]?[]const u8 = undefined;
    for (0..poseidon2KBWidth) |i| {
        const s = std.fmt.bufPrint(&name_bufs[i], "_p2s{d}", .{i}) catch unreachable;
        initial_names[i] = s;
    }

    var tracker = try KBTracker.init(allocator, &initial_names);
    errdefer tracker.deinit();

    try tracker.pushPrimeCache();

    var name_ptrs: [poseidon2KBWidth][]const u8 = undefined;
    for (0..poseidon2KBWidth) |i| {
        name_ptrs[i] = initial_names[i].?;
    }

    try poseidon2KBPermute(&tracker, &name_ptrs, allocator);
    try tracker.popPrimeCache();

    // Drop elements 8-15 (non-digest portion)
    for (8..poseidon2KBWidth) |i| {
        try tracker.toTop(name_ptrs[i]);
        try tracker.drop();
    }

    // Reorder digest elements so _p2s0 is deepest, _p2s7 on top
    for (0..8) |i| {
        try tracker.toTop(name_ptrs[i]);
    }

    return tracker.takeBundle();
}

/// poseidon2KBPermuteShared runs the full Poseidon2 permutation directly on
/// an existing KBTracker that already has the 16 _p2s* names in scope.
/// Used by fiat_shamir_kb.zig to share a tracker across sponge operations.
/// The names array is updated in-place by the permutation.
pub fn poseidon2KBPermuteShared(t: *KBTracker, names: *[poseidon2KBWidth][]const u8, alloc: Allocator) !void {
    try poseidon2KBPermute(t, names, alloc);
    // Reorder so names[0] is deepest and names[15] is on top
    for (0..poseidon2KBWidth) |i| {
        try t.toTop(names[i]);
    }
}

// ===========================================================================
// Tests
// ===========================================================================

test "buildPermuteBundleOps produces ops" {
    const allocator = std.testing.allocator;
    var bundle = try buildPermuteBundleOps(allocator);
    defer bundle.deinit();
    try std.testing.expect(bundle.ops.len > 100);
}

test "buildCompressBundleOps produces fewer ops than permute" {
    const allocator = std.testing.allocator;
    var perm_bundle = try buildPermuteBundleOps(allocator);
    defer perm_bundle.deinit();
    var comp_bundle = try buildCompressBundleOps(allocator);
    defer comp_bundle.deinit();
    // Compress = permute + drops. Both should have substantial ops.
    try std.testing.expect(comp_bundle.ops.len > 100);
}

test "round constants array has correct dimensions" {
    try std.testing.expectEqual(@as(usize, 28), poseidon2KBTotalRounds);
    try std.testing.expectEqual(@as(usize, 16), poseidon2KBWidth);
    // Check first external round constant
    try std.testing.expectEqual(@as(i64, 2128964168), poseidon2KBRoundConstants[0][0]);
    // Check last external round constant
    try std.testing.expectEqual(@as(i64, 879151050), poseidon2KBRoundConstants[27][15]);
    // Check first internal round constant
    try std.testing.expectEqual(@as(i64, 1423960925), poseidon2KBRoundConstants[4][0]);
    try std.testing.expectEqual(@as(i64, 0), poseidon2KBRoundConstants[4][1]);
}
