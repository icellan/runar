import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile } from '../index.js';

/**
 * R-131 / CL-DOC-024 — `docs/formats/rust.md` and `spec/frontend-spec.md` both
 * documented a `.runar.rs` if-expression that no tier implements, and they
 * documented it independently, so correcting one would have left the other.
 *
 *   docs/formats/rust.md      "### Ternary (if expression)"
 *                             `let x = if cond { a } else { b };`
 *   spec/frontend-spec.md     the TernaryExpr per-format table:
 *                             | Rust | `if cond { a } else { b }` (expression) |
 *
 * Measured by exit code — not by grepping output text, which is how an earlier
 * probe of mine misread a tier that writes diagnostics to stderr — on exactly
 * the documented spelling:
 *
 *   ts / go / rust / python / zig / ruby   exit 1
 *   java                                   exit 65 (EX_DATAERR)
 *
 * All seven refuse it, in both the statement-first and statement-last
 * arrangement (the second shape checked separately, because a parser that
 * silently DROPS what it cannot read would have accepted that one).
 *
 * The statement form the docs should have shown compiles everywhere: all seven
 * tiers exit 0 on the `let mut` + `if` rewrite below.
 *
 * This guard pins both halves. Restore either doc's old wording and the first
 * two cases fail by name.
 */

const REPO = resolve(__dirname, '../../../..');
const RUST_DOC = resolve(REPO, 'docs/formats/rust.md');
const FRONTEND_SPEC = resolve(REPO, 'spec/frontend-spec.md');

/** The spelling both documents used to promise. */
const IF_EXPRESSION_SAMPLE = `use runar::prelude::*;

#[runar::contract]
struct RustTernary {
    #[readonly]
    threshold: Int,
}

impl RustTernary {
    pub fn pick(&self, amount: Int) {
        let x: Int = if amount > self.threshold { amount } else { self.threshold };
        assert!(x >= self.threshold);
    }
}
`;

/** The statement form that actually compiles, in all seven tiers. */
const IF_STATEMENT_SAMPLE = `use runar::prelude::*;

#[runar::contract]
struct RustIfStmt {
    #[readonly]
    threshold: Int,
}

impl RustIfStmt {
    pub fn pick(&self, amount: Int) {
        let mut x: Int = self.threshold;
        if amount > self.threshold {
            x = amount;
        }
        assert!(x >= self.threshold);
    }
}
`;

describe('R-131 the .runar.rs if-expression no tier implements', () => {
  it('the reference compiler still refuses it — this is what made the docs false', () => {
    const r = compile(IF_EXPRESSION_SAMPLE, { fileName: 'RustTernary.runar.rs' });
    expect(r.success).toBe(false);
    expect(r.diagnostics.map((d) => d.message).join('\n')).toMatch(/if/);
  });

  it('the statement form compiles, so the docs have something true to show', () => {
    const r = compile(IF_STATEMENT_SAMPLE, { fileName: 'RustIfStmt.runar.rs' });
    expect(r.diagnostics.filter((d) => d.severity === 'error')).toEqual([]);
    expect(r.success).toBe(true);
  });

  it('docs/formats/rust.md no longer promises an if-expression', () => {
    const text = readFileSync(RUST_DOC, 'utf8');
    expect(text, 'the "Ternary (if expression)" heading is back').not.toMatch(
      /^#+\s*Ternary \(if expression\)\s*$/m,
    );
    // The corrected doc quotes the old spelling in order to say it does NOT
    // work, so a bare grep for `let x = if` matches the correction itself.
    // Match the CLAIM: an if-expression assignment PRESENTED AS VALID, i.e.
    // one whose line carries no "NOT Rúnar" marker. (Same shape as R-112's
    // guard, for the same reason.)
    const promised = text
      .split('\n')
      .filter((l) => /^\s*let\s+(?:mut\s+)?\w+(?::\s*\w+)?\s*=\s*if\s/.test(l))
      .filter((l) => !/NOT Rúnar/.test(l));
    expect(promised, 'rust.md shows an if-expression assignment as valid Rúnar').toEqual([]);
  });

  /**
   * The per-format table under `### TernaryExpr`, not the first `| Rust |` row
   * in the file — frontend-spec.md carries several per-format tables and
   * grabbing the wrong one is how a guard passes while saying nothing.
   */
  const ternaryTable = (): string[] => {
    const text = readFileSync(FRONTEND_SPEC, 'utf8');
    const start = text.indexOf('### TernaryExpr');
    expect(start, 'the TernaryExpr section is gone').toBeGreaterThan(-1);
    const rest = text.slice(start);
    const end = rest.indexOf('\n### ', 1);
    return (end === -1 ? rest : rest.slice(0, end)).split('\n');
  };

  it('spec/frontend-spec.md no longer lists an expression form for Rust', () => {
    const row = ternaryTable().find((l) => /^\|\s*Rust\s*\|/.test(l));
    expect(row, 'the TernaryExpr per-format table lost its Rust row').toBeDefined();
    expect(row, 'frontend-spec.md still claims Rust has an if-expression').not.toMatch(
      /\(expression\)/,
    );
    expect(row).toMatch(/[Nn]ot supported/);
  });

  it('the Go row is the model the Rust row should match', () => {
    const goRow = ternaryTable().find((l) => /^\|\s*Go\s*\|/.test(l));
    expect(goRow).toMatch(/[Nn]ot supported/);
  });
});
