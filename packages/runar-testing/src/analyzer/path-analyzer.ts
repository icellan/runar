/**
 * Spending path analyzer — enumerates all execution paths through a Bitcoin
 * Script by following OP_IF/OP_NOTIF/OP_ELSE/OP_ENDIF branching.
 *
 * For each path, tracks which opcodes execute and what the stack depth is,
 * enabling downstream checks (signature hygiene, unconditional success, etc.).
 */

import { Opcode } from '../vm/opcodes.js';
import type { ParsedOpcode } from './script-parser.js';
import { isCheckSigOpcode } from './script-parser.js';
import { analyzeStackLinear } from './stack-analyzer.js';
import type { AnalysisFinding, ExecutionPath } from './types.js';

// ---------------------------------------------------------------------------
// Path enumeration
// ---------------------------------------------------------------------------

/** Maximum number of paths to enumerate before bailing. */
const MAX_PATHS = 256;

interface BranchPoint {
  /** Index into the opcode array where the OP_IF/OP_NOTIF is. */
  ifIndex: number;
  /** Index of the corresponding OP_ELSE (or -1 if no ELSE clause). */
  elseIndex: number;
  /** Index of the corresponding OP_ENDIF. */
  endifIndex: number;
  /** Whether this is OP_NOTIF (inverts the branch condition). */
  isNotIf: boolean;
}

/**
 * Build the branch structure of the script by matching IF/ELSE/ENDIF.
 */
function buildBranchStructure(
  opcodes: ParsedOpcode[],
): { branches: BranchPoint[]; findings: AnalysisFinding[] } {
  const findings: AnalysisFinding[] = [];
  const branches: BranchPoint[] = [];

  const stack: Array<{
    ifIndex: number;
    elseIndex: number;
    isNotIf: boolean;
  }> = [];

  for (let i = 0; i < opcodes.length; i++) {
    const op = opcodes[i]!;

    if (op.opcode === Opcode.OP_IF || op.opcode === Opcode.OP_NOTIF) {
      stack.push({
        ifIndex: i,
        elseIndex: -1,
        isNotIf: op.opcode === Opcode.OP_NOTIF,
      });
    } else if (op.opcode === Opcode.OP_ELSE) {
      if (stack.length === 0) {
        findings.push({
          severity: 'error',
          code: 'UNBALANCED_IF_ENDIF',
          message: 'OP_ELSE without matching OP_IF',
          offset: op.offset,
          opcode: 'OP_ELSE',
        });
      } else {
        stack[stack.length - 1]!.elseIndex = i;
      }
    } else if (op.opcode === Opcode.OP_ENDIF) {
      if (stack.length === 0) {
        findings.push({
          severity: 'error',
          code: 'UNBALANCED_IF_ENDIF',
          message: 'OP_ENDIF without matching OP_IF',
          offset: op.offset,
          opcode: 'OP_ENDIF',
        });
      } else {
        const branch = stack.pop()!;
        branches.push({
          ifIndex: branch.ifIndex,
          elseIndex: branch.elseIndex,
          endifIndex: i,
          isNotIf: branch.isNotIf,
        });
      }
    }
  }

  // Any remaining open IFs are unbalanced
  for (const open of stack) {
    const op = opcodes[open.ifIndex]!;
    findings.push({
      severity: 'error',
      code: 'UNBALANCED_IF_ENDIF',
      message: `${op.name} at offset ${op.offset} has no matching OP_ENDIF`,
      offset: op.offset,
      opcode: op.name,
    });
  }

  return { branches, findings };
}

/**
 * Build a lookup: for a given IF opcode index, get the branch structure.
 */
function buildBranchLookup(
  branches: BranchPoint[],
): Map<number, BranchPoint> {
  const map = new Map<number, BranchPoint>();
  for (const b of branches) {
    map.set(b.ifIndex, b);
  }
  return map;
}

/**
 * Collect the opcodes that execute for a given set of branch decisions.
 *
 * This walks through the opcode array, and at each OP_IF/OP_NOTIF, picks
 * the branch based on the next decision in the choices array. Returns the
 * list of opcodes that would execute on this path.
 */
function collectPathOpcodes(
  opcodes: ParsedOpcode[],
  choices: boolean[],
  branchLookup: Map<number, BranchPoint>,
): ParsedOpcode[] {
  const result: ParsedOpcode[] = [];
  let choiceIdx = 0;
  let i = 0;

  while (i < opcodes.length) {
    const op = opcodes[i]!;

    if (op.opcode === Opcode.OP_IF || op.opcode === Opcode.OP_NOTIF) {
      const branch = branchLookup.get(i);
      if (!branch) {
        // No branch info — shouldn't happen if structure is valid
        i++;
        continue;
      }

      const choice = choiceIdx < choices.length ? choices[choiceIdx]! : true;
      choiceIdx++;

      if (choice) {
        // Take the TRUE branch: execute from ifIndex+1 to elseIndex (or endifIndex)
        // Skip the IF opcode itself, continue into body
        i++;
        // The body runs until we hit ELSE or ENDIF for this branch
        // We handle this by tracking what to skip at ELSE
      } else {
        // Take the FALSE branch: skip to ELSE (or ENDIF)
        if (branch.elseIndex >= 0) {
          // Jump past the ELSE opcode
          i = branch.elseIndex + 1;
        } else {
          // No ELSE — skip to after ENDIF
          i = branch.endifIndex + 1;
        }
      }
      continue;
    }

    if (op.opcode === Opcode.OP_ELSE) {
      // We're in the TRUE branch and hit ELSE — skip to after ENDIF
      // Find the branch that owns this ELSE
      const owningBranch = findBranchByElse(branchLookup, i);
      if (owningBranch) {
        i = owningBranch.endifIndex + 1;
      } else {
        i++;
      }
      continue;
    }

    if (op.opcode === Opcode.OP_ENDIF) {
      // Just skip ENDIF — it's a structural marker
      i++;
      continue;
    }

    // Normal opcode — add to path
    result.push(op);
    i++;
  }

  return result;
}

/**
 * Find the branch that has a given ELSE index.
 */
function findBranchByElse(
  lookup: Map<number, BranchPoint>,
  elseIndex: number,
): BranchPoint | undefined {
  for (const branch of lookup.values()) {
    if (branch.elseIndex === elseIndex) return branch;
  }
  return undefined;
}

/**
 * Count the number of branch points (OP_IF/OP_NOTIF) in the script.
 */
function countBranchPoints(opcodes: ParsedOpcode[]): number {
  return opcodes.filter(
    (op) => op.opcode === Opcode.OP_IF || op.opcode === Opcode.OP_NOTIF,
  ).length;
}

/**
 * Enumerate all execution paths through the script.
 */
export function analyzePaths(
  opcodes: ParsedOpcode[],
): { paths: ExecutionPath[]; findings: AnalysisFinding[] } {
  const { branches, findings } = buildBranchStructure(opcodes);

  // If there are structural errors, we can't reliably enumerate paths
  if (findings.some((f) => f.code === 'UNBALANCED_IF_ENDIF')) {
    return { paths: [], findings };
  }

  const branchLookup = buildBranchLookup(branches);
  const numBranches = countBranchPoints(opcodes);
  const paths: ExecutionPath[] = [];

  if (numBranches === 0) {
    // Linear script — single path
    const pathOpcodes = opcodes.filter(
      (op) =>
        op.opcode !== Opcode.OP_IF &&
        op.opcode !== Opcode.OP_NOTIF &&
        op.opcode !== Opcode.OP_ELSE &&
        op.opcode !== Opcode.OP_ENDIF,
    );

    const stackResult = analyzeStackLinear(pathOpcodes);
    findings.push(...stackResult.findings);

    const hasCheckSig = pathOpcodes.some((op) => isCheckSigOpcode(op));

    paths.push({
      id: 0,
      description: 'linear (no branches)',
      branchChoices: [],
      reachable: true,
      hasCheckSig,
      stackDepthAtEnd: stackResult.depth,
    });
  } else {
    // Enumerate all 2^n combinations (up to MAX_PATHS)
    const totalCombinations = Math.min(1 << numBranches, MAX_PATHS);

    for (let combo = 0; combo < totalCombinations; combo++) {
      // Build choices array from bit pattern
      const choices: boolean[] = [];
      for (let b = 0; b < numBranches; b++) {
        choices.push(((combo >> b) & 1) === 1);
      }

      const pathOpcodes = collectPathOpcodes(opcodes, choices, branchLookup);
      const stackResult = analyzeStackLinear(pathOpcodes);
      const hasCheckSig = pathOpcodes.some((op) => isCheckSigOpcode(op));

      const description = describeChoices(choices, opcodes, branches);

      // Add stack findings with path context
      for (const f of stackResult.findings) {
        findings.push({ ...f, path: description });
      }

      paths.push({
        id: paths.length,
        description,
        branchChoices: choices,
        reachable: true,
        hasCheckSig,
        stackDepthAtEnd: stackResult.depth,
      });
    }
  }

  return { paths, findings };
}

/**
 * Create a human-readable description of the branch choices.
 */
function describeChoices(
  choices: boolean[],
  opcodes: ParsedOpcode[],
  _branches: BranchPoint[],
): string {
  if (choices.length === 0) {
    return 'linear (no branches)';
  }

  // Collect IF opcodes in order of appearance
  const ifOpcodes: Array<{ index: number; op: ParsedOpcode; isNotIf: boolean }> = [];
  for (let i = 0; i < opcodes.length; i++) {
    const op = opcodes[i]!;
    if (op.opcode === Opcode.OP_IF || op.opcode === Opcode.OP_NOTIF) {
      ifOpcodes.push({ index: i, op, isNotIf: op.opcode === Opcode.OP_NOTIF });
    }
  }

  const parts: string[] = [];
  for (let c = 0; c < choices.length && c < ifOpcodes.length; c++) {
    const choice = choices[c]!;
    const info = ifOpcodes[c]!;
    const label = info.isNotIf ? 'NOTIF' : 'IF';
    parts.push(`${label}[${choice ? 'true' : 'false'}] at ${info.op.offset}`);
  }

  return parts.join(' -> ');
}
