/**
 * runar-testing — Bitcoin Script VM, reference interpreter, fuzzer, and test
 * helpers for the Rúnar compiler.
 */

// VM
export {
  Opcode,
  opcodeName,
  ScriptVM,
  encodeScriptNumber,
  decodeScriptNumber,
  isTruthy,
  hexToBytes,
  bytesToHex,
  disassemble,
} from './vm/index.js';
export type { VMResult, VMOptions, VMFlags, StepResult } from './vm/index.js';

// Interpreter
export { RunarInterpreter } from './interpreter/index.js';
export type { RunarValue, InterpreterResult } from './interpreter/index.js';

// Fuzzer
export {
  arbContract,
  arbStatelessContract,
  arbArithmeticContract,
  arbCryptoContract,
} from './fuzzer/index.js';

// Test helpers
export {
  TestSmartContract,
  expectScriptSuccess,
  expectScriptFailure,
  expectStackTop,
  expectStackTopNum,
} from './helpers.js';

// TestContract API
export { TestContract } from './test-contract.js';
export type { TestCallResult, OutputSnapshot, MockPreimage } from './test-contract.js';

// Script execution (BSV SDK)
export { ScriptExecutionContract } from './script-execution.js';
export type { ScriptExecResult } from './script-execution.js';

// Source map resolver (for debugger)
export { SourceMapResolver } from './source-map.js';
export type { SourceLocation } from './source-map.js';

// Test keys (deterministic, pre-generated with @bsv/sdk)
export {
  TEST_KEYS, ALICE, BOB, CHARLIE, DAVE, EVE,
  FRANK, GRACE, HEIDI, IVAN, JUDY,
} from './test-keys.js';
export type { TestKey } from './test-keys.js';

// ECDSA crypto (real signing/verification over fixed test message)
export {
  signTestMessage,
  pubKeyFromPrivKey,
  verifyTestMessageSig,
  verifyTestMessageSigHex,
  TEST_MESSAGE,
  TEST_MESSAGE_DIGEST,
} from './crypto/ecdsa.js';

// Rabin signature primitives (real signing/verification)
export {
  rabinSign,
  rabinVerify,
  rabinVerifyHex,
  generateRabinKeyPair,
  RABIN_TEST_KEY,
} from './crypto/rabin.js';
export type { RabinKeyPair } from './crypto/rabin.js';

// Post-quantum crypto primitives
export { wotsKeygen, wotsSign, wotsVerify, WOTS_PARAMS } from './crypto/wots.js';
export type { WOTSKeyPair } from './crypto/wots.js';
export {
  slhKeygen, slhSign, slhVerify, slhVerifyVerbose,
  SLH_SHA2_128s, SLH_SHA2_128f, SLH_SHA2_192s, SLH_SHA2_192f,
  SLH_SHA2_256s, SLH_SHA2_256f, ALL_SHA2_PARAMS,
} from './crypto/slh-dsa.js';
export type { SLHParams, SLHKeyPair } from './crypto/slh-dsa.js';

// Mock preimage helpers (standalone BIP-143 preimage building for stateful contracts)
export {
  buildStatefulPreimage,
  buildLockingScript,
  buildContinuationOutput,
  computeHashOutputs,
  serializeState,
} from './mock-preimage.js';
export type { StatefulPreimageParams, StatefulPreimageResult } from './mock-preimage.js';
