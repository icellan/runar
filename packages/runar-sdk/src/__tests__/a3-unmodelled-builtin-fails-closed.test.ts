/**
 * A-3 (round-three audit): the NEW-006 "fail closed" guard could not fire for
 * 76 of runar-lang's 105 builtins.
 *
 * `evalCall` in `anf-interpreter.ts` ended `default: return undefined`. The
 * guard at `contract.ts` is a `try/catch` around the interpreter, so a
 * builtin the interpreter does not model returned quietly and the guard was
 * STRUCTURALLY unable to fire. `contract.ts` then spreads
 * `{ ...autoFlatState, ...autoComputedState }`, and the `undefined` overwrote
 * the real value.
 *
 * Severity is contained — nothing broadcasts: a `bigint` field throws
 * downstream, a `ByteString` field dies at @bsv/sdk with "not hex encoded",
 * and the one silent arm (`boolean` -> `"00"`, silently false) is still
 * caught by the C8 pre-broadcast dry-run. But that silent arm's feeders are
 * exactly the signature verifiers (`verifyWOTS`, all six `verifySLHDSA_*`,
 * `verifyRabinSig`, `ecOnCurve`, `p256OnCurve`, `p384OnCurve`,
 * `verifyECDSA_P256/P384`, `bn254G1OnCurve`), and the resulting error pointed
 * at the covenant rather than at the interpreter gap.
 *
 * The fix makes `default:` throw, naming the builtin. Measured before it:
 * `ecOnCurve` yielded `{"ok":"<<undefined>>"}` with no diagnostic.
 *
 * WHAT LEGITIMATELY RETURNS `undefined`. Not every `kind:'call'` func is a
 * runar-lang builtin: `04-anf-lower.ts` synthesizes `extractSigHashType`,
 * `computeStateOutput`, `buildChangeOutput` and `super`, none of which appear
 * in `builtins.ts`. They are covenant / constructor scaffolding the SDK
 * builds itself and they carry no off-chain value. Measured by instrumenting
 * the `default:` arm and running this package's suite plus `examples/` and
 * `packages/runar-testing`: `extractSigHashType` and `computeStateOutput` are
 * hit (89 + 82 times in runar-sdk alone) — so a blanket throw would have
 * broken every stateful call. They are allowlisted by name.
 * `__array_access` (ByteString `data[i]`) is NOT: it is a value-producing
 * operation the interpreter genuinely does not model, i.e. the same defect.
 */
import { describe, it, expect } from 'vitest';
import type { ANFProgram } from 'runar-ir-schema';
import { computeNewStateAndDataOutputs } from '../anf-interpreter.js';
import * as runarLang from 'runar-lang';

/**
 * Minimal stateful ANF: `ok = <func>()`. Enough to route one `kind:'call'`
 * through `evalCall` and observe what lands in the state delta.
 */
function anfCalling(func: string): ANFProgram {
  return {
    contractName: 'Probe',
    properties: [{ name: 'ok', type: 'boolean', readonly: false }],
    methods: [
      {
        name: 'm',
        isPublic: true,
        params: [],
        body: [
          { name: 't0', value: { kind: 'call', func, args: [] } },
          { name: 'u0', value: { kind: 'update_prop', name: 'ok', value: 't0' } },
        ],
      },
    ],
  };
}

type Outcome =
  | { kind: 'refused'; message: string }
  | { kind: 'threw-other'; message: string }
  | { kind: 'silent-undefined' }
  | { kind: 'value'; value: unknown };

function probe(func: string): Outcome {
  let result;
  try {
    result = computeNewStateAndDataOutputs(anfCalling(func), 'm', { ok: true }, {});
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return message.includes(func) && /does not model|not modelled|unmodelled/i.test(message)
      ? { kind: 'refused', message }
      : { kind: 'threw-other', message };
  }
  return result.state.ok === undefined
    ? { kind: 'silent-undefined' }
    : { kind: 'value', value: result.state.ok };
}

/** Every function runar-lang exports as a contract builtin. */
const ALL_BUILTINS = Object.keys(runarLang).filter(
  (k) => typeof (runarLang as Record<string, unknown>)[k] === 'function',
);

/** Compiler-synthesized pseudo-funcs that are NOT runar-lang builtins and
 * legitimately have no off-chain value — the allowlist the fix must keep. */
const SYNTHESIZED_SCAFFOLDING = [
  'computeStateOutput',
  'buildChangeOutput',
  'super',
];

/**
 * The ONLY runar-lang builtins allowed to evaluate to `undefined`, each for a
 * reason that is not the A-3 defect:
 *
 * - `assert` — control flow, not a value. Lenient mode skips the predicate
 *   and strict mode throws `AssertionFailureError` from the dedicated arm;
 *   nothing ever reads its result.
 * - `extractSigHashType` — a genuine remaining gap, kept deliberately. It is
 *   emitted on every stateful method and measured at 317 evaluations across
 *   runar-sdk + examples/ + runar-testing, always consumed by an `assert`
 *   that lenient mode skips, so the `undefined` never reaches a state field.
 *   Refusing it would break every stateful call for a value nothing reads;
 *   giving it a dummy would change strict-mode assert outcomes.
 *
 * Asserted as an EXACT set, so a newly-silent builtin fails here.
 */
const PERMITTED_SILENT = ['assert', 'extractSigHashType'];

describe('A-3 — an unmodelled builtin must fail closed, naming itself', () => {
  it('RED: ecOnCurve is refused by name instead of silently yielding undefined', () => {
    const outcome = probe('ecOnCurve');
    expect(outcome.kind).toBe('refused');
    expect((outcome as { message: string }).message).toMatch(/ecOnCurve/);
  });

  it('RED: the boolean-arm feeders — the signature verifiers — are all refused', () => {
    const verifiers = [
      'verifyWOTS',
      'verifyRabinSig',
      'verifySLHDSA_SHA2_128s',
      'verifySLHDSA_SHA2_128f',
      'verifySLHDSA_SHA2_192s',
      'verifySLHDSA_SHA2_192f',
      'verifySLHDSA_SHA2_256s',
      'verifySLHDSA_SHA2_256f',
      'verifyECDSA_P256',
      'verifyECDSA_P384',
      'p256OnCurve',
      'p384OnCurve',
      'bn254G1OnCurve',
    ];
    for (const name of verifiers) {
      expect(probe(name), `${name} must be refused`).toMatchObject({ kind: 'refused' });
    }
  });

  it('RED: the byte-slicing gap (left / right / split / sha256Compress / merkleRootSha256) is refused too', () => {
    for (const name of ['left', 'right', 'split', 'sha256Compress', 'sha256Finalize', 'merkleRootSha256']) {
      expect(probe(name), `${name} must be refused`).toMatchObject({ kind: 'refused' });
    }
  });

  it('RED: `__array_access` (ByteString data[i]) is refused — it is a value-producing op the interpreter does not model', () => {
    expect(probe('__array_access')).toMatchObject({ kind: 'refused' });
  });

  it('INVARIANT: no runar-lang builtin may silently evaluate to undefined beyond the two documented exemptions', () => {
    const silent = ALL_BUILTINS.filter((name) => probe(name).kind === 'silent-undefined');
    expect(silent.sort()).toEqual([...PERMITTED_SILENT].sort());
  });

  it('INVARIANT: the gap is real and large — most builtins reach the refusal, not a modelled arm', () => {
    const refused = ALL_BUILTINS.filter((name) => probe(name).kind === 'refused');
    // 76 of 105 at the time of the fix; asserted as a floor so adding an
    // interpreter arm (which shrinks it) is never blocked by this test.
    expect(refused.length).toBeGreaterThanOrEqual(60);
  });

  it('CONTROL (teeth): compiler-synthesized scaffolding still evaluates to undefined and does NOT throw', () => {
    for (const name of SYNTHESIZED_SCAFFOLDING) {
      const outcome = probe(name);
      expect(outcome, `${name} must stay silent`).toMatchObject({ kind: 'silent-undefined' });
    }
  });

  it('CONTROL (teeth): a modelled builtin still computes its real value', () => {
    const anf: ANFProgram = {
      contractName: 'Probe',
      properties: [{ name: 'h', type: 'ByteString', readonly: false }],
      methods: [
        {
          name: 'm',
          isPublic: true,
          params: [{ name: 'data', type: 'ByteString' }],
          body: [
            { name: 't0', value: { kind: 'load_param', name: 'data' } },
            { name: 't1', value: { kind: 'call', func: 'sha256', args: ['t0'] } },
            { name: 'u0', value: { kind: 'update_prop', name: 'h', value: 't1' } },
          ],
        },
      ],
    };
    const res = computeNewStateAndDataOutputs(anf, 'm', { h: '' }, { data: 'abcd' });
    // sha256(0xabcd)
    expect(res.state.h).toBe('123d4c7ef2d1600a1b3a0f6addc60a10f05a3495c9409f2ecbf4cc095d000a6b');
  });

  it('extractHashPrevouts is a modelled dummy, not a refusal', () => {
    // Needed so SDK prepareCall can build token-ft merge (W8) without dropping anf.
    const outcome = probe('extractHashPrevouts');
    expect(outcome.kind).toBe('value');
    expect((outcome as { value: unknown }).value).toBe('00'.repeat(32));
  });
});
