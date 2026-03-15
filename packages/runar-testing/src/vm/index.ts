/**
 * VM module re-exports.
 */

export { Opcode, opcodeName } from './opcodes.js';
export { ScriptVM } from './script-vm.js';
export type { VMResult, VMOptions, VMFlags, StepResult } from './script-vm.js';
export {
  encodeScriptNumber,
  decodeScriptNumber,
  isTruthy,
  hexToBytes,
  bytesToHex,
  disassemble,
} from './utils.js';
