/**
 * tsop-testing — Bitcoin Script VM, reference interpreter, fuzzer, and test
 * helpers for the TSOP compiler.
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
export type { VMResult, VMOptions, VMFlags } from './vm/index.js';

// Interpreter
export { TSOPInterpreter } from './interpreter/index.js';
export type { TSOPValue, InterpreterResult } from './interpreter/index.js';

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
