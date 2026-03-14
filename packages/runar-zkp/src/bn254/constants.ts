/**
 * BN254 curve constants.
 *
 * BN254 (alt_bn128) is the pairing-friendly curve used by Ethereum's
 * precompiles and most Groth16 implementations. The curve equation is
 * y^2 = x^3 + 3 over Fp where p is a 254-bit prime.
 *
 * References:
 * - EIP-196/197 (Ethereum BN254 precompiles)
 * - https://eips.ethereum.org/EIPS/eip-197
 */

/** BN254 base field prime: p = 21888242871839275222246405745257275088696311157297823662689037894645226208583 */
export const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

/** BN254 scalar field order (group order): r = 21888242871839275222246405745257275088548364400416034343698204186575808495617 */
export const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Curve coefficient b = 3 (y^2 = x^3 + b). */
export const B = 3n;

/** Twist coefficient b' = 3 / (9 + u) for the G2 twist curve over Fp2. */
export const B_TWIST_C0 = 19485874751759354771024239261021720505790618469301721065564631296452457478373n;
export const B_TWIST_C1 = 266929791119991161246907387137283842545076965332900288569378510910307636690n;

/** G1 generator. */
export const G1_X = 1n;
export const G1_Y = 2n;

/** G2 generator. */
export const G2_X_C0 = 10857046999023057135944570762232829481370756359578518086990519993285655852781n;
export const G2_X_C1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634n;
export const G2_Y_C0 = 8495653923123431417604973247489272438418190587263600148770280649306958101930n;
export const G2_Y_C1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531n;

/** p - 2, for Fermat inverse: a^{-1} = a^{p-2} mod p */
export const P_MINUS_2 = P - 2n;

/** (p - 1) / 2, for Euler criterion (Legendre symbol) */
export const P_MINUS_1_OVER_2 = (P - 1n) / 2n;

/** Number of bits in p. */
export const P_BITS = 254;

/** BN254 parameter x (used in Miller loop and final exponentiation).
 * x = 0x44e992b44a6909f1, satisfying p = 36x^4 + 36x^3 + 24x^2 + 6x + 1. */
export const BN_X = 4965661367192848881n;
