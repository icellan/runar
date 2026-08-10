/**
 * CF1 — control-flow tree parser. Lifts a flat op stream into a nested tree of
 * `linear` runs and `if`/`notif` blocks (with then/else children). The tree is
 * the structural backbone the native-if renderer walks; it must (a) nest
 * balanced IF/ELSE/ENDIF correctly and (b) tile the byte stream exactly — every
 * byte lands in either a linear leaf or an IF/ELSE/ENDIF marker.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { hexToBytes, bytesToHex } from 'runar-testing';
import { disassemble } from '../src/disasm.js';
import { parseControlFlow, flattenSpans, type CFNode } from '../src/control-flow.js';

function leaves(nodes: CFNode[]): CFNode[] {
  const out: CFNode[] = [];
  for (const n of nodes) {
    out.push(n);
    if (n.kind === 'if') out.push(...leaves(n.then), ...leaves(n.else));
  }
  return out;
}

describe('parseControlFlow — shapes (CF1)', () => {
  it('returns a single linear node for a straight-line script', () => {
    const ops = disassemble(hexToBytes('515293')); // OP_1 OP_2 OP_ADD
    const tree = parseControlFlow(ops);
    expect(tree).toHaveLength(1);
    expect(tree[0]!.kind).toBe('linear');
    expect(tree[0]!.span).toEqual([0, 3]);
  });

  it('parses `cond OP_IF a OP_ENDIF` into linear + if(then=[a], else=[])', () => {
    // OP_1 (cond) OP_IF OP_2 OP_ENDIF  => 51 63 52 68
    const ops = disassemble(hexToBytes('51635268'));
    const tree = parseControlFlow(ops);
    expect(tree).toHaveLength(2);
    expect(tree[0]!.kind).toBe('linear'); // the condition run
    const ifn = tree[1]!;
    expect(ifn.kind).toBe('if');
    if (ifn.kind !== 'if') throw new Error('expected if');
    expect(ifn.op).toBe('if');
    expect(ifn.else).toHaveLength(0);
    expect(ifn.then).toHaveLength(1);
    expect(ifn.then[0]!.kind).toBe('linear');
  });

  it('parses then/else and OP_NOTIF', () => {
    // OP_1 OP_NOTIF OP_2 OP_ELSE OP_3 OP_ENDIF => 51 64 52 67 53 68
    const ops = disassemble(hexToBytes('516452675368'));
    const tree = parseControlFlow(ops);
    const ifn = tree[1]!;
    if (ifn.kind !== 'if') throw new Error('expected if');
    expect(ifn.op).toBe('notif');
    expect(ifn.then).toHaveLength(1);
    expect(ifn.else).toHaveLength(1);
  });

  it('nests inner conditionals', () => {
    // OP_1 OP_IF ( OP_1 OP_IF OP_2 OP_ENDIF ) OP_ENDIF
    const ops = disassemble(hexToBytes('516351635268' + '68'));
    const tree = parseControlFlow(ops);
    const outer = tree[1]!;
    if (outer.kind !== 'if') throw new Error('expected outer if');
    const inner = outer.then.find((n) => n.kind === 'if');
    expect(inner).toBeDefined();
  });
});

describe('parseControlFlow — tiling (CF1)', () => {
  const ftkHex = readFileSync(new URL('./fixtures/ftk-demo.hex', import.meta.url), 'utf8').trim();
  const bytes = hexToBytes(ftkHex);
  const ops = disassemble(bytes);
  const tree = parseControlFlow(ops);

  it('reconstructs the exact byte stream by flattening the tree', () => {
    const flat = flattenSpans(tree, bytes);
    expect(bytesToHex(flat)).toBe(ftkHex);
  });

  it('recovers the known top-level branch structure of the FTK script', () => {
    const topIfs = tree.filter((n) => n.kind === 'if');
    expect(topIfs).toHaveLength(41);
    // the 436-op main branch is an OP_NOTIF
    const big = topIfs.find((n) => n.kind === 'if' && n.endIndex - n.ifIndex > 400);
    expect(big).toBeDefined();
    if (big && big.kind === 'if') expect(big.op).toBe('notif');
  });

  it('every leaf span is non-empty and ordered', () => {
    const ls = leaves(tree);
    let prevEnd = 0;
    for (const n of ls) {
      if (n.kind === 'linear') {
        expect(n.span[0]).toBeLessThan(n.span[1]);
        expect(n.span[0]).toBeGreaterThanOrEqual(prevEnd);
        prevEnd = Math.max(prevEnd, n.span[1]);
      }
    }
  });
});
