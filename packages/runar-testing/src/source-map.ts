/**
 * SourceMapResolver — maps between script byte offsets and source locations.
 *
 * Used by the debugger to show which source line corresponds to the current
 * opcode, and to set breakpoints by source line.
 */

import type { SourceMap, SourceMapping } from 'runar-ir-schema';

/** A resolved source location for a script opcode. */
export interface SourceLocation {
  file: string;
  line: number;
  column: number;
  opcodeIndex: number;
}

export class SourceMapResolver {
  private readonly mappings: SourceMapping[];
  /** Sorted by opcodeIndex for binary search. */
  private readonly sortedMappings: SourceMapping[];

  constructor(sourceMap: SourceMap) {
    this.mappings = sourceMap.mappings;
    this.sortedMappings = [...sourceMap.mappings].sort(
      (a, b) => a.opcodeIndex - b.opcodeIndex,
    );
  }

  /**
   * Given a script opcode index, return the source location.
   * Returns null if no mapping exists for this opcode.
   */
  resolve(opcodeIndex: number): SourceLocation | null {
    // Binary search for the largest opcodeIndex <= target
    const mappings = this.sortedMappings;
    let lo = 0;
    let hi = mappings.length - 1;
    let best: SourceMapping | null = null;

    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const m = mappings[mid]!;
      if (m.opcodeIndex <= opcodeIndex) {
        best = m;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }

    if (!best) return null;

    return {
      file: best.sourceFile,
      line: best.line,
      column: best.column,
      opcodeIndex: best.opcodeIndex,
    };
  }

  /**
   * Given a source file and line, return all matching script opcode indices.
   * Used for setting breakpoints by source location.
   */
  reverseResolve(file: string, line: number): number[] {
    return this.mappings
      .filter((m) => m.sourceFile === file && m.line === line)
      .map((m) => m.opcodeIndex);
  }

  /** Check if the source map has any mappings. */
  get isEmpty(): boolean {
    return this.mappings.length === 0;
  }

  /** Get all unique source files referenced in the source map. */
  get sourceFiles(): string[] {
    return [...new Set(this.mappings.map((m) => m.sourceFile))];
  }
}
