/**
 * N-096 — the `syntheticArrayChain` validity rule for `--ir` input.
 *
 * The chain is what 03b-expand-fixed-arrays hangs off each scalar leaf of a
 * FixedArray property, and what the artifact assembler consumes, one level per
 * pass, to regroup the leaves into one ABI / state entry. On the IR path it
 * comes from outside the compiler, and the seven tiers disagreed about a chain
 * the pass could not have written (Go panicked, Rust/Ruby refused, Python and
 * Java published a scalar, Zig dropped it, TS compiled it).
 *
 * Every tier checks the same rule, property by property in declaration order,
 * and refuses with the same words:
 *
 *   1. at most MAX_SYNTHETIC_ARRAY_DEPTH levels. The pass itself has no
 *      nesting bound; the regrouper's 1024 passes are the only one the
 *      pipeline has, and a chain deeper than 1023 is one it cannot regroup.
 *   2. every level has 0 <= index < length.
 *   3. level k's base is `<base>__<index>` of level k-1, and the property is
 *      named `<innermost base>__<innermost index>`: the names the pass mints.
 *   4. the leaves sharing a root (level 0's base) are exactly one expansion:
 *      contiguous, row-major from element 0, one type and one list of level
 *      lengths, and complete.
 *
 *   IR validation: malformed syntheticArrayChain on property '<p>': <detail>
 */

import type { ANFProgram, ANFSyntheticArrayLevel } from './anf-ir.js';

/** The regrouper's 1024-pass cap leaves room for this many levels. */
export const MAX_SYNTHETIC_ARRAY_DEPTH = 1023;

function refuse(prop: string, detail: string): Error {
  return new Error(`IR validation: malformed syntheticArrayChain on property '${prop}': ${detail}`);
}

interface Family {
  root: string;
  type: string;
  lengths: number[];
  tuple: number[];
  last: string;
}

const leafName = (root: string, tuple: number[]): string =>
  tuple.reduce((name, i) => `${name}__${i}`, root);

const isComplete = (f: Family): boolean => f.tuple.every((i, k) => i === f.lengths[k]! - 1);

/** The row-major successor of `f.tuple`; only called when it is not complete. */
function nextTuple(f: Family): number[] {
  const t = [...f.tuple];
  for (let k = t.length - 1; k >= 0; k--) {
    if (t[k]! + 1 < f.lengths[k]!) {
      t[k] = t[k]! + 1;
      return t;
    }
    t[k] = 0;
  }
  return t;
}

const expects = (f: { root: string; type: string; lengths: number[] }, tuple: number[]): string =>
  `'${f.root}' expects its element '${leafName(f.root, tuple)}' here ` +
  `(type ${f.type}, level lengths [${f.lengths.join(', ')}])`;

function checkLevels(name: string, chain: ANFSyntheticArrayLevel[]): void {
  if (chain.length > MAX_SYNTHETIC_ARRAY_DEPTH) {
    throw refuse(name, `${chain.length} levels exceed the limit of ${MAX_SYNTHETIC_ARRAY_DEPTH}`);
  }
  chain.forEach((lvl, k) => {
    const { base, index, length } = (typeof lvl === 'object' && lvl !== null ? lvl : {}) as Partial<ANFSyntheticArrayLevel>;
    if (typeof base !== 'string' || !Number.isInteger(index) || !Number.isInteger(length)) {
      throw refuse(name, `level ${k} is not a {base: string, index: integer, length: integer} object`);
    }
    if (!(index! >= 0 && index! < length!)) {
      throw refuse(
        name,
        `level ${k} has index ${index} and length ${length}; expand-fixed-arrays writes 0 <= index < length`,
      );
    }
    if (k > 0) {
      const prev = chain[k - 1]!;
      const want = `${prev.base}__${prev.index}`;
      if (base !== want) {
        throw refuse(name, `level ${k} has base '${base}'; expand-fixed-arrays writes '${want}'`);
      }
    }
  });
  const inner = chain[chain.length - 1]!;
  const want = `${inner.base}__${inner.index}`;
  if (name !== want) {
    throw refuse(
      name,
      `its innermost level is element ${inner.index} of '${inner.base}'; ` +
        `expand-fixed-arrays names that property '${want}'`,
    );
  }
}

/** Throws the shared diagnostic for the first chain the rule refuses. */
export function assertSyntheticArrayChains(program: ANFProgram): void {
  let open: Family | null = null;
  const seen = new Set<string>();

  const close = (): void => {
    if (open !== null && !isComplete(open)) {
      throw refuse(open.last, `'${open.root}' ends here, before its element '${leafName(open.root, nextTuple(open))}'`);
    }
    open = null;
  };

  for (const prop of program.properties) {
    const raw = (prop as { syntheticArrayChain?: unknown }).syntheticArrayChain;
    if (raw !== undefined && raw !== null && !Array.isArray(raw)) {
      throw refuse(prop.name, 'the chain is not an array');
    }
    const chain = (raw ?? []) as ANFSyntheticArrayLevel[];
    const root = chain.length > 0 ? chain[0]!.base : undefined;
    if (open !== null && root !== (open as Family).root) close();
    if (chain.length === 0) continue;

    checkLevels(prop.name, chain);
    const tuple = chain.map((l) => l.index);
    const lengths = chain.map((l) => l.length);

    if (open !== null) {
      const f: Family = open;
      if (isComplete(f)) throw refuse(prop.name, `'${f.root}' already ended before this property`);
      const want = nextTuple(f);
      if (prop.type !== f.type || lengths.join() !== f.lengths.join() || tuple.join() !== want.join()) {
        throw refuse(prop.name, expects(f, want));
      }
      f.tuple = want;
      f.last = prop.name;
      continue;
    }

    if (seen.has(root!)) throw refuse(prop.name, `'${root}' already ended before this property`);
    const start = lengths.map(() => 0);
    if (tuple.join() !== start.join()) {
      throw refuse(prop.name, expects({ root: root!, type: prop.type, lengths }, start));
    }
    seen.add(root!);
    open = { root: root!, type: prop.type, lengths, tuple, last: prop.name };
  }
  close();
}
