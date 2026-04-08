/**
 * SX IR -- BitcoinSX output types.
 *
 * Produced by Pass 7 (07-sx-emit), which takes ANF IR and emits
 * human-readable BitcoinSX (.sx) text preserving high-level structure
 * (macros, repeat blocks, named variables).
 */

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

export interface SXSection {
  kind: 'comment' | 'macro' | 'body' | 'dispatch';
  name: string;
  sx: string;
}

// ---------------------------------------------------------------------------
// Emit result
// ---------------------------------------------------------------------------

export interface SXEmitResult {
  /** The complete BitcoinSX source text */
  sx: string;
  /** Per-section breakdown (for tooling) */
  sections: SXSection[];
}
