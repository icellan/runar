import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import type { CompilerDiagnostic } from '../errors.js';

/**
 * R-143 / CL-BUG-042 — the addOutput-family diagnostics in the
 * `isStatefulContextType` branch of 03-typecheck omit their location, while the
 * sibling branches a hundred lines away pass it for the identical checks.
 *
 * That branch is the `ctx: runar.StatefulContext` calling convention — the
 * shape the `.runar.zig` surface uses (`ctx.addOutput(...)`,
 * examples/zig/tic-tac-toe/TicTacToe.v2.runar.zig:58). So the same mistake
 * reported `Counter.runar.ts:14:4: addOutput() expects …` on the TypeScript
 * surface and a bare `addOutput() expects …` with no file, line or column on
 * the Zig one.
 *
 * Measured before the fix: 13 location-less `makeDiagnostic` calls in the file,
 * all inside that branch (the finding said eleven; the two extra are the
 * `getStateScript()` arity check and one addDataOutput operand check).
 *
 * These are the cheapest diagnostics in the compiler to get right — the
 * location is already in hand at every site, as `expr.sourceLocation` or the
 * argument's own. What made them worth a finding is that an author on the Zig
 * surface cannot find the call the compiler is complaining about.
 */

const CONTRACT = (body: string) => `const runar = @import("runar");

pub const CtxProbe = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64,

    pub fn init(count: i64) CtxProbe {
        return .{ .count = count };
    }

    pub fn bump(self: *CtxProbe, ctx: runar.StatefulContext, n: i64, raw: runar.ByteString) void {
        runar.assert(n > 0);
        self.count = self.count + n;
${body}
    }
};
`;

function errorsFor(body: string): CompilerDiagnostic[] {
  const r = compile(CONTRACT(body), { fileName: 'CtxProbe.runar.zig' });
  return r.diagnostics.filter((d) => d.severity === 'error');
}

/** Every error carries a real file:line:column. */
function expectAllLocated(diags: CompilerDiagnostic[], label: string): void {
  expect(diags.length, `${label}: expected at least one error`).toBeGreaterThan(0);
  for (const d of diags) {
    expect(
      d.loc,
      `${label}: "${d.message}" has no location — an author on the .runar.zig ` +
        `surface cannot find the call this is about`,
    ).toBeDefined();
    expect(d.loc!.line, `${label}: "${d.message}" reports line ${d.loc?.line}`).toBeGreaterThan(0);
    expect(d.loc!.file).toMatch(/CtxProbe\.runar\.zig/);
  }
}

describe('R-143 ctx.<output-intrinsic> diagnostics carry a location', () => {
  it('addOutput arity', () => {
    expectAllLocated(errorsFor('        ctx.addOutput(1000, self.count, n);'), 'addOutput arity');
  });

  it('addOutput satoshis type', () => {
    expectAllLocated(errorsFor('        ctx.addOutput(raw, self.count);'), 'addOutput satoshis');
  });

  it('addOutput state-value type', () => {
    expectAllLocated(errorsFor('        ctx.addOutput(1000, raw);'), 'addOutput state value');
  });

  it('addRawOutput arity and operand types', () => {
    expectAllLocated(errorsFor('        ctx.addRawOutput(1000);'), 'addRawOutput arity');
    expectAllLocated(errorsFor('        ctx.addRawOutput(raw, raw);'), 'addRawOutput satoshis');
    expectAllLocated(errorsFor('        ctx.addRawOutput(1000, n);'), 'addRawOutput scriptBytes');
  });

  it('addDataOutput arity and operand types', () => {
    expectAllLocated(errorsFor('        ctx.addDataOutput(1000);'), 'addDataOutput arity');
    expectAllLocated(errorsFor('        ctx.addDataOutput(raw, raw);'), 'addDataOutput satoshis');
    expectAllLocated(errorsFor('        ctx.addDataOutput(1000, n);'), 'addDataOutput scriptBytes');
  });

  it('getStateScript arity', () => {
    expectAllLocated(
      errorsFor('        const s: runar.ByteString = ctx.getStateScript(n);\n        runar.assert(runar.len(s) > 0);'),
      'getStateScript arity',
    );
  });

  it('reports the line the offending call is actually on', () => {
    // The contract template puts the injected body at line 15.
    const diags = errorsFor('        ctx.addOutput(1000, self.count, n);');
    expect(diags[0]!.loc!.line).toBe(15);
  });

  it('no makeDiagnostic in 03-typecheck omits its location argument', async () => {
    const { readFileSync } = await import('node:fs');
    const { resolve } = await import('node:path');
    const src = readFileSync(resolve(__dirname, '../passes/03-typecheck.ts'), 'utf8');

    // Bracket-match each `makeDiagnostic(` call and count its top-level commas.
    // A regex cannot do this: the message is a template literal that routinely
    // contains both parentheses and commas, which is why an earlier version of
    // this check passed while thirteen unlocated sites were sitting in the file.
    const offenders: number[] = [];
    for (let at = src.indexOf('makeDiagnostic('); at !== -1; at = src.indexOf('makeDiagnostic(', at + 1)) {
      let depth = 0;
      let commas = 0;
      let k = at + 'makeDiagnostic'.length;
      for (; k < src.length; k++) {
        const ch = src[k]!;
        if (ch === '(' || ch === '[' || ch === '{') depth++;
        else if (ch === ')' || ch === ']' || ch === '}') {
          depth--;
          if (depth === 0) break;
        } else if (ch === ',' && depth === 1) commas++;
      }
      // message, severity[, location] — fewer than 2 commas means no location.
      if (commas < 2) offenders.push(src.slice(0, at).split('\n').length);
    }
    expect(
      offenders,
      `03-typecheck.ts has location-less makeDiagnostic calls at lines: ${offenders.join(', ')}`,
    ).toEqual([]);
  });
});
