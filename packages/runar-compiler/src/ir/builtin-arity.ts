/**
 * Builtin call arities, for validating ANF IR that never went through the
 * frontend (R-163 / R-165, ported to the TS `--from-ir` path by N-215).
 *
 * The source pipeline type-checks every call. `loadANFFromJSON` runs no
 * frontend, so a wrong-arity call reached stack lowering, which pops
 * `args.length` from the stack MODEL and then emits a FIXED-arity opcode
 * blob: `cat` with one argument compiled to a bare OP_CAT.
 *
 * A verbatim copy of Go's `ir.BuiltinArity` (compilers/go/ir/builtin_arity.go),
 * whose own drift test pins it to the frontend signature table. Values are the
 * ALLOWED argument counts; `assert` takes 1 or 2 (the optional message) and
 * `extractPrevOutputScript` 2 or 3 (the optional prefix length). A name not in
 * the table is not a fixed-arity builtin and is not checked here.
 */
const BUILTIN_ARITY: Readonly<Record<string, readonly number[]>> = {
  abs: [1],
  assert: [1, 2],
  assertGroth16WitnessAssisted: [0],
  assertGroth16WitnessAssistedWithMSM: [0],
  bbExt4Inv0: [4],
  bbExt4Inv1: [4],
  bbExt4Inv2: [4],
  bbExt4Inv3: [4],
  bbExt4Mul0: [8],
  bbExt4Mul1: [8],
  bbExt4Mul2: [8],
  bbExt4Mul3: [8],
  bbFieldAdd: [2],
  bbFieldInv: [1],
  bbFieldMul: [2],
  bbFieldSub: [2],
  bin2num: [1],
  blake3Compress: [2],
  blake3Hash: [1],
  bn254FieldAdd: [2],
  bn254FieldInv: [1],
  bn254FieldMul: [2],
  bn254FieldNeg: [1],
  bn254FieldSub: [2],
  bn254G1Add: [2],
  bn254G1Negate: [1],
  bn254G1OnCurve: [1],
  bn254G1ScalarMul: [2],
  bn254MultiPairing3: [27],
  bn254MultiPairing4: [20],
  bn254Pairing: [5],
  bool: [1],
  buildChangeOutput: [2],
  cat: [2],
  checkMultiSig: [2],
  checkPreimage: [1],
  checkSig: [2],
  clamp: [3],
  currentBlockHeight: [0],
  continuationAmount: [0],
  divmod: [2],
  ecAdd: [2],
  ecEncodeCompressed: [1],
  ecMakePoint: [2],
  ecModReduce: [2],
  ecMul: [2],
  ecMulGen: [1],
  ecNegate: [1],
  ecOnCurve: [1],
  ecPointX: [1],
  ecPointY: [1],
  exit: [1],
  extractAmount: [1],
  extractHashPrevouts: [1],
  extractHashSequence: [1],
  extractInputIndex: [1],
  extractLocktime: [1],
  extractOutpoint: [1],
  extractOutputHash: [1],
  extractOutputs: [1],
  extractPrevOutputScript: [2, 3],
  extractScriptCode: [1],
  extractSequence: [1],
  extractSigHashType: [1],
  extractVersion: [1],
  gcd: [2],
  groth16PublicInput: [1],
  hash160: [1],
  hash256: [1],
  int2str: [2],
  kbExt4Inv0: [4],
  kbExt4Inv1: [4],
  kbExt4Inv2: [4],
  kbExt4Inv3: [4],
  kbExt4Mul0: [8],
  kbExt4Mul1: [8],
  kbExt4Mul2: [8],
  kbExt4Mul3: [8],
  kbFieldAdd: [2],
  kbFieldInv: [1],
  kbFieldMul: [2],
  kbFieldSub: [2],
  left: [2],
  len: [1],
  log2: [1],
  max: [2],
  merkleRootHash256: [4],
  merkleRootSha256: [4],
  min: [2],
  mulDiv: [3],
  num2bin: [2],
  p256Add: [2],
  p256EncodeCompressed: [1],
  p256Mul: [2],
  p256MulGen: [1],
  p256Negate: [1],
  p256OnCurve: [1],
  p384Add: [2],
  p384EncodeCompressed: [1],
  p384Mul: [2],
  p384MulGen: [1],
  p384Negate: [1],
  p384OnCurve: [1],
  pack: [1],
  percentOf: [2],
  pow: [2],
  requireOutputP2PKH: [3],
  reverseBytes: [1],
  right: [2],
  ripemd160: [1],
  safediv: [2],
  safemod: [2],
  sha256: [1],
  sha256Compress: [2],
  sha256Finalize: [3],
  sign: [1],
  split: [2],
  sqrt: [1],
  substr: [3],
  toByteString: [1],
  unpack: [1],
  verifyECDSA_P256: [3],
  verifyECDSA_P384: [3],
  verifyRabinSig: [4],
  verifySLHDSA_SHA2_128f: [3],
  verifySLHDSA_SHA2_128s: [3],
  verifySLHDSA_SHA2_192f: [3],
  verifySLHDSA_SHA2_192s: [3],
  verifySLHDSA_SHA2_256f: [3],
  verifySLHDSA_SHA2_256s: [3],
  verifySP1FRI: [3],
  verifyWOTS: [3],
  within: [3],
};

/**
 * `null` if `args` is a legal count for `func` (or `func` is not a builtin
 * with an arity rule), else the "it takes ..." text for the diagnostic.
 * `merkleRootPoseidon2KB` takes 8*depth + 10 arguments (Go `VariadicArityOK`).
 */
export function builtinArityViolation(func: string, args: number): string | null {
  if (func === 'merkleRootPoseidon2KB') {
    if (args < 10) return 'at least 10 arguments (8 leaf + index + depth)';
    if ((args - 10) % 8 !== 0) return '8*depth + 10 arguments';
    return null;
  }
  if (!Object.prototype.hasOwnProperty.call(BUILTIN_ARITY, func)) return null;
  const allowed = BUILTIN_ARITY[func]!;
  if (allowed.includes(args)) return null;
  // Go `formatAllowedArity`: "2", or "2 or 3".
  if (allowed.length === 0) return 'no arguments';
  if (allowed.length === 1) return String(allowed[0]);
  return `${allowed.slice(0, -1).join(', ')} or ${allowed[allowed.length - 1]}`;
}
