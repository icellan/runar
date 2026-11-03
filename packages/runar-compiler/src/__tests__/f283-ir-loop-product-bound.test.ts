import { describe, it, expect } from 'vitest';
import { loadANFFromJSON } from '../index.js';
import { MAX_LOOP_COUNT } from '../ir/index.js';

/**
 * F-283 / CL-GAP-164 — `loadANFFromJSON` (the reference tier's `--from-ir`
 * entry point, `packages/runar-cli`'s `compile --from-ir`) had NO bound at
 * all on a loop's iteration count: `MAX_LOOP_COUNT` (CL-BUG-088) is read
 * only by `04-anf-lower.ts` on the SOURCE path, which `compileFromANF` never
 * runs. The six native loaders already bounded a single loop's own count
 * (Go `ir.MaxLoopCount`, Python/Ruby/Rust/Zig/Java's own copies) but never
 * the PRODUCT across nesting — two loops of `MAX_LOOP_COUNT` each, one
 * inside the other, each individually satisfy that bound while the real
 * unrolled work is `MAX_LOOP_COUNT x MAX_LOOP_COUNT` = 100,000,000. A
 * payload shaped that way loads instantly and then drives whatever lowers
 * it into multi-GB memory growth (measured on the Ruby tier, same shape: a
 * 1,175-byte payload loaded in 0.0s and then drove compilation to 5m07s /
 * 3.7GB RSS and climbing).
 *
 * This file closes BOTH gaps on the reference tier in one pass, per the
 * ESCALATION RULE: the reference tier is fail-open too, so it is fixed
 * alongside the six native tiers rather than left out of the fix.
 *
 * What this proves: `loadANFFromJSON` rejects a loop count exceeding
 * MAX_LOOP_COUNT, and rejects a nested-loop IR whose counts each
 * individually satisfy MAX_LOOP_COUNT but whose product does not, before
 * any lowering pass sees the program.
 * What this does not prove: that stack lowering itself would be safe
 * against such a count or product if it arrived some other way (e.g.
 * synthesized rather than loaded from JSON) — only that this loader-level
 * route is closed. Nor does it exercise the `runar-cli compile --from-ir`
 * process boundary; that is `packages/runar-cli`'s own test surface.
 */

const singleLoopProgram = (count: number) =>
  JSON.stringify({
    contractName: 'Bounded',
    properties: [],
    methods: [
      {
        name: 'unlock',
        isPublic: true,
        params: [],
        body: [
          {
            name: 't0',
            value: { kind: 'loop', count, iterVar: 'i', start: 0, step: 1, body: [] },
          },
        ],
      },
    ],
  });

const nestedLoopProgram = (outerCount: number, innerCount: number) =>
  JSON.stringify({
    contractName: 'Bounded',
    properties: [],
    methods: [
      {
        name: 'unlock',
        isPublic: true,
        params: [],
        body: [
          {
            name: 'outer',
            value: {
              kind: 'loop',
              count: outerCount,
              iterVar: 'i',
              start: 0,
              step: 1,
              body: [
                {
                  name: 'inner',
                  value: {
                    kind: 'loop',
                    count: innerCount,
                    iterVar: 'j',
                    start: 0,
                    step: 1,
                    body: [],
                  },
                },
              ],
            },
          },
        ],
      },
    ],
  });

describe('F-283 loadANFFromJSON bounds loop count (single and nested product)', () => {
  it('accepts a single loop at exactly MAX_LOOP_COUNT (control)', () => {
    expect(() => loadANFFromJSON(singleLoopProgram(MAX_LOOP_COUNT))).not.toThrow();
  });

  it('refuses a single loop count exceeding MAX_LOOP_COUNT', () => {
    expect(() => loadANFFromJSON(singleLoopProgram(MAX_LOOP_COUNT + 1))).toThrow(
      /loop count 10001 exceeding maximum 10000/,
    );
  });

  it('accepts nested loops whose product stays within MAX_LOOP_COUNT (control)', () => {
    expect(() => loadANFFromJSON(nestedLoopProgram(10, 10))).not.toThrow();
  });

  it('refuses nested loops whose product (MAX_LOOP_COUNT x MAX_LOOP_COUNT) exceeds the maximum', () => {
    expect(() => loadANFFromJSON(nestedLoopProgram(MAX_LOOP_COUNT, MAX_LOOP_COUNT))).toThrow(
      /100000000/,
    );
  });

  it('refuses small nested counts whose product alone exceeds the maximum', () => {
    // Neither 101 nor 100 alone trips the single-binding ceiling (both are
    // far below MAX_LOOP_COUNT), but their product (10,100) does. Proves the
    // rule is the product, not a disguised re-check of the single bound.
    expect(() => loadANFFromJSON(nestedLoopProgram(101, 100))).toThrow(/10100/);
  });
});
