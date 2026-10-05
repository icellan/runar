/**
 * Signature verification hygiene analyzer.
 *
 * Checks that every execution path includes proper signature verification
 * and that OP_CHECKSIG results are consumed (not left on stack or dropped).
 */

import { Opcode } from '../vm/opcodes.js';
import type { ParsedOpcode } from './script-parser.js';
// isCheckSigOpcode imported for future use in signature verification analysis
import { isCheckSigOpcode as _isCheckSigOpcode } from './script-parser.js';
import type { AnalysisFinding, ExecutionPath } from './types.js';

/**
 * Analyze signature verification hygiene across all execution paths.
 */
export function analyzeSigHygiene(
  opcodes: ParsedOpcode[],
  paths: ExecutionPath[],
): AnalysisFinding[] {
  const findings: AnalysisFinding[] = [];

  // Check each path for signature verification
  for (const path of paths) {
    if (!path.reachable) continue;

    if (!path.hasCheckSig) {
      findings.push({
        severity: 'warning',
        code: 'NO_SIG_CHECK',
        message: `Execution path has no signature verification (OP_CHECKSIG/OP_CHECKMULTISIG)`,
        path: path.description,
      });
    }
  }

  // Check for OP_CHECKSIG results not being verified
  // Look for patterns where OP_CHECKSIG is immediately followed by an opcode
  // that pops the result without reading it: OP_DROP or OP_2DROP (spec §9).
  for (let i = 0; i < opcodes.length - 1; i++) {
    const op = opcodes[i]!;
    const next = opcodes[i + 1]!;

    if (
      (op.opcode === Opcode.OP_CHECKSIG || op.opcode === Opcode.OP_CHECKMULTISIG) &&
      (next.opcode === Opcode.OP_DROP || next.opcode === Opcode.OP_2DROP)
    ) {
      findings.push({
        severity: 'warning',
        code: 'CHECKSIG_RESULT_DROPPED',
        message: `${op.name} result is dropped by ${next.name} — signature check has no effect`,
        offset: op.offset,
        opcode: op.name,
      });
    }
  }

  return findings;
}
