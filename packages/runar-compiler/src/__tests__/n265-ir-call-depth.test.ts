import { describe, it, expect } from 'vitest';
import { compileFromANF, loadANFFromJSON } from '../index.js';

/**
 * N-265 — `--ir` bypasses N-180's call-depth bound and (outside Go's
 * recursive F-071 `checkIRNoRecursion`) the recursion check entirely.
 *
 * `compileFromANF` skips 02-validate, whose `checkNoRecursion` enforces both
 * the call-graph cycle rule and N-180's `MAX_CALL_DEPTH` (128) bound. Stack
 * lowering inlines every `method_call` to a private method by lowering its
 * body in place with no cycle or depth guard, so externally supplied IR with
 * a self/mutually-recursive method recurses the host call stack until it
 * crashes, and an acyclic chain past `MAX_CALL_DEPTH` recurses it just as
 * deep — the n180-call-depth-parity.test.ts header says outright this path
 * ("the --ir path: an externally supplied ANF program never meets the
 * source validator") is unproven.
 *
 * Proves: `compileFromANF` now runs one iterative (no host recursion) pass
 * over the IR call graph before stack lowering, refuses a direct or mutual
 * cycle with the shared "recursion detected" wording, accepts a chain right
 * at `MAX_CALL_DEPTH`, refuses one past it naming the first offending method
 * in declaration order with N-180's shared diagnostic, and refuses a
 * 20000-link chain promptly (no RangeError, no multi-second hang) rather than
 * silently compiling or stack-overflowing in `lowerToStack`'s inlining.
 *
 * Does not prove: that the other six tiers' `--ir` loaders agree —
 * conformance/negatives/n265-ir-call-depth-parity.test.ts does; call graphs
 * other than a chain or a 2/3-node cycle; or that 128 is the right number
 * (N-180 already measured that).
 */

const MAX_CALL_DEPTH = 128;

/**
 * `verify(a)` calls `m0(a)`; m_i calls m_{i+1} for i < n; m_{n-1} returns its
 * argument unchanged. verify's call depth is n (it calls m0, which has depth
 * n-1). Declaration order is m0..m(n-1) THEN verify, matching N-180's own
 * `chain()` fixture (conformance/negatives/n180-call-depth-parity.test.ts) —
 * "first offender in declaration order" depends on it: at n=128 only
 * `verify` exceeds the bound (every m_i sits at or under it), but at
 * n=20000 `m0` is declared before `verify` and already exceeds it, so `m0`
 * is reported first.
 */
function chainIR(n: number): unknown {
  const methods: unknown[] = [];
  for (let i = 0; i < n; i++) {
    const isLast = i === n - 1;
    methods.push({
      name: `m${i}`,
      isPublic: false,
      params: [{ name: 'x', type: 'bigint' }],
      body: isLast
        ? [{ name: 't0', value: { kind: 'load_param', name: 'x' } }]
        : [
            { name: 't0', value: { kind: 'load_const', value: '@this' } },
            { name: 't1', value: { kind: 'load_param', name: 'x' } },
            { name: 't2', value: { kind: 'method_call', object: 't0', method: `m${i + 1}`, args: ['t1'] } },
          ],
    });
  }
  methods.push({
    name: 'verify',
    isPublic: true,
    params: [{ name: 'a', type: 'bigint' }],
    body: [
      { name: 't0', value: { kind: 'load_const', value: '@this' } },
      { name: 't1', value: { kind: 'load_param', name: 'a' } },
      { name: 't2', value: { kind: 'method_call', object: 't0', method: 'm0', args: ['t1'] } },
      { name: 't3', value: { kind: 'load_const', value: 0 } },
      { name: 't4', value: { kind: 'bin_op', op: '>=', left: 't2', right: 't3' } },
      { name: 't5', value: { kind: 'assert', value: 't4' } },
    ],
  });
  return { contractName: 'Chain', properties: [], methods };
}

/** `unlock(x)` calls private `p(x)`, whose body is given explicitly. */
function cycleIR(privateMethods: Array<{ name: string; callee: string | null }>): unknown {
  const methods: unknown[] = [
    {
      name: 'unlock',
      isPublic: true,
      params: [{ name: 'x', type: 'bigint' }],
      body: [
        { name: 't0', value: { kind: 'load_const', value: '@this' } },
        { name: 't1', value: { kind: 'load_param', name: 'x' } },
        { name: 't2', value: { kind: 'method_call', object: 't0', method: 'p', args: ['t1'] } },
        { name: 't3', value: { kind: 'load_const', value: 0 } },
        { name: 't4', value: { kind: 'bin_op', op: '>=', left: 't2', right: 't3' } },
        { name: 't5', value: { kind: 'assert', value: 't4' } },
      ],
    },
  ];
  for (const pm of privateMethods) {
    methods.push({
      name: pm.name,
      isPublic: false,
      params: [{ name: 'x', type: 'bigint' }],
      body:
        pm.callee === null
          ? [{ name: 't0', value: { kind: 'load_param', name: 'x' } }]
          : [
              { name: 't0', value: { kind: 'load_const', value: '@this' } },
              { name: 't1', value: { kind: 'load_param', name: 'x' } },
              { name: 't2', value: { kind: 'method_call', object: 't0', method: pm.callee, args: ['t1'] } },
            ],
    });
  }
  return { contractName: 'Rec', properties: [], methods };
}

const compile = (ir: unknown) => compileFromANF(loadANFFromJSON(JSON.stringify(ir)));

describe('N-265: compileFromANF bounds the --ir call graph', () => {
  it('a chain at MAX_CALL_DEPTH compiles', () => {
    expect(compile(chainIR(MAX_CALL_DEPTH)).scriptHex).not.toBe('');
  });

  it('a chain one past MAX_CALL_DEPTH is refused naming the first offending method', () => {
    expect(() => compile(chainIR(MAX_CALL_DEPTH + 1))).toThrow(
      `call depth of method 'verify' exceeds MAX_CALL_DEPTH (limit=${MAX_CALL_DEPTH})`,
    );
  });

  it('a 20000-link chain is refused promptly, not silently compiled or stack-overflowed', () => {
    const start = Date.now();
    expect(() => compile(chainIR(20000))).toThrow(
      `call depth of method 'm0' exceeds MAX_CALL_DEPTH (limit=${MAX_CALL_DEPTH})`,
    );
    // "Promptly": well under the host's recursion-crash timescale, and no
    // RangeError ("Maximum call stack size exceeded") leaked out instead of
    // our diagnostic — the `toThrow` above with an exact substring already
    // rules that out, but the wall-clock bound catches a quadratic rewrite.
    expect(Date.now() - start).toBeLessThan(5000);
  });

  it('direct self-recursion is refused with the shared recursion diagnostic', () => {
    expect(() => compile(cycleIR([{ name: 'p', callee: 'p' }]))).toThrow(
      /recursion detected: method 'p' calls itself directly or indirectly/,
    );
  });

  it('mutual recursion is refused, naming a method on the cycle', () => {
    expect(() =>
      compile(cycleIR([{ name: 'p', callee: 'q' }, { name: 'q', callee: 'p' }])),
    ).toThrow(/recursion detected: method '[pq]' calls itself directly or indirectly/);
  });

  it('a non-recursive diamond (two helpers sharing a third) still compiles', () => {
    const ir = {
      contractName: 'Diamond',
      properties: [],
      methods: [
        {
          name: 'unlock',
          isPublic: true,
          params: [{ name: 'x', type: 'bigint' }],
          body: [
            { name: 't0', value: { kind: 'load_const', value: '@this' } },
            { name: 't1', value: { kind: 'load_param', name: 'x' } },
            { name: 't2', value: { kind: 'method_call', object: 't0', method: 'a', args: ['t1'] } },
            { name: 't3', value: { kind: 'load_const', value: '@this' } },
            { name: 't4', value: { kind: 'method_call', object: 't3', method: 'b', args: ['t2'] } },
            { name: 't5', value: { kind: 'load_const', value: 0 } },
            { name: 't6', value: { kind: 'bin_op', op: '>=', left: 't4', right: 't5' } },
            { name: 't7', value: { kind: 'assert', value: 't6' } },
          ],
        },
        {
          name: 'a',
          isPublic: false,
          params: [{ name: 'x', type: 'bigint' }],
          body: [
            { name: 't0', value: { kind: 'load_const', value: '@this' } },
            { name: 't1', value: { kind: 'load_param', name: 'x' } },
            { name: 't2', value: { kind: 'method_call', object: 't0', method: 'c', args: ['t1'] } },
          ],
        },
        {
          name: 'b',
          isPublic: false,
          params: [{ name: 'x', type: 'bigint' }],
          body: [
            { name: 't0', value: { kind: 'load_const', value: '@this' } },
            { name: 't1', value: { kind: 'load_param', name: 'x' } },
            { name: 't2', value: { kind: 'method_call', object: 't0', method: 'c', args: ['t1'] } },
          ],
        },
        {
          name: 'c',
          isPublic: false,
          params: [{ name: 'x', type: 'bigint' }],
          body: [{ name: 't0', value: { kind: 'load_param', name: 'x' } }],
        },
      ],
    };
    expect(compile(ir).scriptHex).not.toBe('');
  });
});
