// ---------------------------------------------------------------------------
// runar-lang/runtime — Off-chain simulation runtime
// ---------------------------------------------------------------------------
// Re-exports everything from runar-lang, then overrides throwing stubs with
// working implementations. Import from 'runar-lang/runtime' instead of
// 'runar-lang' to get runtime-safe builtins.
// ---------------------------------------------------------------------------

// Re-export all types, constructors, constants, SigHash
export {
  // Type constructors
  toByteString,
  PubKey,
  Sig,
  Ripemd160,
  Sha256,
  Addr,
  SigHashPreimage,
  OpCodeType,
  Point,
  SigHash,
  // Pure types
  type ByteString,
  type SigHashType,
  type RabinSig,
  type RabinPubKey,
  type FixedArray,
} from '../types.js';

// EC constants
export { EC_P, EC_N, EC_G } from '../ec.js';

// Override builtins with runtime implementations
export {
  // Crypto hashes
  sha256,
  ripemd160,
  hash160,
  hash256,
  // Signature verification (mocked)
  checkSig,
  checkMultiSig,
  // Byte operations
  len,
  cat,
  substr,
  left,
  right,
  split,
  reverseBytes,
  // Conversion
  num2bin,
  bin2num,
  int2str,
  // Assertion
  assert,
  // Math
  abs,
  min,
  max,
  within,
  safediv,
  safemod,
  clamp,
  sign,
  pow,
  mulDiv,
  percentOf,
  sqrt,
  gcd,
  divmod,
  log2,
  bool,
  // Rabin
  verifyRabinSig,
  // Post-quantum
  verifyWOTS,
  verifySLHDSA_SHA2_128s,
  verifySLHDSA_SHA2_128f,
  verifySLHDSA_SHA2_192s,
  verifySLHDSA_SHA2_192f,
  verifySLHDSA_SHA2_256s,
  verifySLHDSA_SHA2_256f,
  // EC operations
  ecAdd,
  ecMul,
  ecMulGen,
  ecNegate,
  ecOnCurve,
  ecModReduce,
  ecEncodeCompressed,
  ecMakePoint,
  ecPointX,
  ecPointY,
  // Baby Bear field arithmetic
  bbFieldAdd,
  bbFieldSub,
  bbFieldMul,
  bbFieldInv,
  // KoalaBear field arithmetic
  kbFieldAdd,
  kbFieldSub,
  kbFieldMul,
  kbFieldInv,
  // Merkle proof verification
  merkleRootSha256,
  merkleRootHash256,
} from './builtins.js';

// Override preimage functions with mock implementations
export {
  checkPreimage,
  extractVersion,
  extractHashPrevouts,
  extractHashSequence,
  extractOutpoint,
  extractInputIndex,
  extractScriptCode,
  extractAmount,
  extractSequence,
  extractOutputHash,
  extractOutputs,
  extractLocktime,
  extractSigHashType,
} from './preimage.js';

// Override base classes with runtime-safe versions
export { SmartContract, StatefulSmartContract } from './contract.js';
