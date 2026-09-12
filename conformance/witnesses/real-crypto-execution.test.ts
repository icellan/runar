/**
 * Real-crypto execution oracle (post-mortem remediation #1).
 *
 * Each `real-crypto/<fixture>.json` spec declares concrete spends that are
 * executed through @bsv/sdk's production `Spend` interpreter with REAL
 * secp256k1 — real DER signatures over the real BIP-143 sighash and, for
 * stateful contracts, a real state-continuation preimage synthesised by the
 * deploy→call SDK path. This closes the blind spot behind BUG-100 / #99 / #100
 * / #44: fixtures needing a signature or a tx-context preimage used to be
 * routed out to the coverage ledger (`coverage-ledger.json`, formerly split
 * across `crypto-exempt.json` / `harness-inapplicable.json`) and got NO real
 * execution — all seven tiers agreed on bytes nobody ever ran.
 *
 * Two spec kinds:
 *   - `stateless-signed` — a stateless SmartContract; `$sig` args are filled
 *     with real DER signatures; the accept path is additionally cross-checked
 *     against the ANF interpreter (source-vs-script agreement).
 *   - `stateful` — a StatefulSmartContract driven deploy→call through the SDK
 *     and re-validated on `Spend` (real checkPreimage + OP_CODESEPARATOR +
 *     optional user checkSig).
 *
 * Every spend asserts the REAL engine matches the declared expectation. Each
 * fixture carries ≥1 accept and ≥1 reject/near-miss (wrong key, wrong signer,
 * or a tampered continuation output → must fail). A `cryptoNearMiss` reject is
 * a script-only rejection (the interpreter models crypto with real-but-fixed
 * TEST_MESSAGE checks and cannot model an arbitrary tx-context rejection).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  runStatelessSigned,
  runStatefulSpend,
  testKey,
  type StatelessArg,
} from '../../packages/runar-testing/src/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TESTS_DIR = join(__dirname, '..', 'tests');
const SPEC_DIR = join(__dirname, 'real-crypto');

interface Spec {
  fixture: string;
  kind: 'stateless-signed' | 'stateful';
  signerKey?: string;
  constructorArgs?: unknown;
  spends: SpendSpec[];
}
interface SpendSpec {
  method: string;
  args: unknown[];
  expect: 'accept' | 'reject';
  note?: string;
  // stateless
  checkInterpreter?: boolean;
  // stateful
  signerKey?: string;
  constructorArgs?: unknown;
  lockTime?: number;
  satoshis?: number;
  tamperOutput?: boolean;
  /** Independent, hand-authored expected continuation state after an accepted
   *  stateful spend (audit #4). Property → scalar ("1n" | true | "0x.."). The
   *  on-chain state decoded from the call tx MUST equal this — accept/reject
   *  cannot catch a state-transition miscompile that is self-consistent between
   *  the SDK-built output and the covenant. Required for every stateful accept
   *  spend unless `noStateCheck` is set. */
  expectedState?: Record<string, unknown>;
  /** Opt out of the state-value check (justify in `note`) — only for a stateful
   *  accept whose continuation genuinely carries no decodable state. Requires
   *  a non-empty `issue` field alongside `note` (audit P2-3) — a free opt-out
   *  with no residual accounting is exactly the hole this check exists to
   *  keep loud. Nothing uses it today; `coverage-claims.test.ts` pins the
   *  count at 0. */
  noStateCheck?: boolean;
  /** Mandatory when `noStateCheck` is set — see above. */
  issue?: string;
  // both
  cryptoNearMiss?: boolean;
}

/** Resolve the `.runar.ts` source for a fixture. */
function loadSource(fixture: string): { source: string; fileName: string } {
  const cfg = JSON.parse(readFileSync(join(TESTS_DIR, fixture, 'source.json'), 'utf-8'));
  const rel: string | undefined = cfg.sources?.['.runar.ts'] ?? cfg.path;
  if (!rel) throw new Error(`no .runar.ts source in ${fixture}/source.json`);
  const p = resolve(join(TESTS_DIR, fixture), rel);
  return { source: readFileSync(p, 'utf-8'), fileName: p.split('/').pop()! };
}

const hexBytes = (hex: string): Uint8Array =>
  Uint8Array.from(Buffer.from(hex.startsWith('0x') ? hex.slice(2) : hex, 'hex'));

/** Placeholder object like {"$pubkey":"alice"}. */
function placeholder(v: unknown): { tag: string; key: string } | null {
  if (v && typeof v === 'object' && !Array.isArray(v)) {
    const keys = Object.keys(v as object);
    if (keys.length === 1 && keys[0]!.startsWith('$')) {
      return { tag: keys[0]!.slice(1), key: (v as Record<string, string>)[keys[0]!]! };
    }
  }
  return null;
}

/**
 * Decode a scalar literal: "27n"→bigint, "0x.."→hex string, bool passthrough,
 * bare string→hex byte payload.
 *
 * DIALECT WARNING — this is NOT interchangeable with `decodeCtor`/`decodeArg`
 * in witnesses/differential.test.ts. That harness reads `witnesses/*.json` and
 * REJECTS a bare (un-prefixed) string; this one reads `witnesses/real-crypto/`
 * and accepts it as hex, which its specs rely on ("deadbeef", a 20-byte PKH of
 * zeros, "00"/"01"). The two spec sets are disjoint directories, so no single
 * file is decoded both ways — but a spec COPIED between the directories will
 * decode differently (or throw). Keep bare-hex literals in real-crypto/ and
 * 0x-prefixed literals in witnesses/, or convert on the move.
 */
function scalar(v: unknown): bigint | boolean | string {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') {
    if (/^-?\d+n$/.test(v)) return BigInt(v.slice(0, -1));
    if (v.startsWith('0x')) return v.slice(2);
    return v; // bare hex string (byte payload) — see DIALECT WARNING above
  }
  throw new Error(`unencodable scalar ${JSON.stringify(v)}`);
}

/**
 * Decode an `expectedState` VALUE, which unlike a constructor arg may be an
 * array: a `FixedArray<T, N>` property is expanded into N scalar slots by pass
 * 3b and regrouped by the artifact assembler, so the decoded continuation state
 * hands it back as a real array (R-094).
 *
 * Nested arrays decode too — `FixedArray<FixedArray<T, A>, B>` regroups into an
 * array of arrays — so the recursion is not speculative.
 */
function stateValue(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(stateValue);
  return scalar(v);
}

/** Resolve constructor args (record for stateless, array for stateful). */
function resolveCtorRecord(raw: unknown): Record<string, bigint | boolean | string> {
  const out: Record<string, bigint | boolean | string> = {};
  for (const [k, v] of Object.entries((raw ?? {}) as Record<string, unknown>)) {
    const ph = placeholder(v);
    if (ph?.tag === 'pubkey') out[k] = testKey(ph.key).pubKey;
    else if (ph?.tag === 'pkh') out[k] = testKey(ph.key).pubKeyHash;
    else out[k] = scalar(v);
  }
  return out;
}
function resolveCtorArray(raw: unknown): (bigint | boolean | string)[] {
  return ((raw ?? []) as unknown[]).map((v) => {
    const ph = placeholder(v);
    if (ph?.tag === 'pubkey') return testKey(ph.key).pubKey;
    if (ph?.tag === 'pkh') return testKey(ph.key).pubKeyHash;
    return scalar(v);
  });
}

/** Resolve stateless method args (sig → SignMarker, pubkey/pkh → bytes). */
function resolveStatelessArgs(raw: unknown[]): StatelessArg[] {
  return raw.map((v) => {
    const ph = placeholder(v);
    if (ph?.tag === 'sig') return { signWith: ph.key };
    if (ph?.tag === 'pubkey') return hexBytes(testKey(ph.key).pubKey);
    if (ph?.tag === 'pkh') return hexBytes(testKey(ph.key).pubKeyHash);
    const s = scalar(v);
    return typeof s === 'string' ? hexBytes(s) : s;
  });
}

/** Resolve stateful method args (null passthrough, pubkey → hex string). */
function resolveStatefulArgs(raw: unknown[]): unknown[] {
  return raw.map((v) => {
    if (v === null) return null;
    const ph = placeholder(v);
    if (ph?.tag === 'pubkey') return testKey(ph.key).pubKey;
    if (ph?.tag === 'pkh') return testKey(ph.key).pubKeyHash;
    return scalar(v);
  });
}

const specFiles = readdirSync(SPEC_DIR).filter((f) => f.endsWith('.json'));

/** A crypto near-miss reject must be rejected BY THE SCRIPT GUARD on the real
 *  Spend engine, not by a harness/SDK error before the engine ran — otherwise a
 *  reject that fails for an unrelated SDK reason silently passes and the guard it
 *  was meant to exercise stops being tested (audit #12). */
function assertNearMissReachedEngine(
  fixture: string,
  s: SpendSpec,
  r: { reachedEngine?: boolean; vmError?: string },
): void {
  if (s.expect !== 'reject' || !s.cryptoNearMiss) return;
  expect(
    r.reachedEngine,
    `${fixture}.${s.method}: crypto near-miss reject must reach the Spend engine ` +
      `(reachedEngine=${r.reachedEngine}, vmErr=${r.vmError}) — a false here means it failed ` +
      `at the SDK/harness before the script guard ran (audit #12)`,
  ).toBe(true);
}

describe('real-crypto execution (source vs real @bsv/sdk Spend, fold-ON)', () => {
  for (const specFile of specFiles) {
    const spec: Spec = JSON.parse(readFileSync(join(SPEC_DIR, specFile), 'utf-8'));
    const { source, fileName } = loadSource(spec.fixture);

    describe(spec.fixture, () => {
      for (const s of spec.spends) {
        const label = `${s.method}(${JSON.stringify(s.args)}) → ${s.expect}${
          s.tamperOutput ? ' [tamper]' : ''
        } [${s.note ?? ''}]`;

        it(label, async () => {
          if (spec.kind === 'stateless-signed') {
            const r = runStatelessSigned({
              source,
              fileName,
              method: s.method,
              args: resolveStatelessArgs(s.args),
              constructorArgs: resolveCtorRecord(s.constructorArgs ?? spec.constructorArgs),
              checkInterpreter: s.checkInterpreter,
            });
            expect(r.vmAccepted, `real Spend: vmErr=${r.vmError} unlocking=${r.unlockingHex}`).toBe(
              s.expect === 'accept',
            );
            // Source-vs-script agreement where the interpreter is meaningful.
            if (r.interpreterAccepted !== undefined && !s.cryptoNearMiss) {
              expect(
                r.interpreterAccepted,
                `interpreter=${r.interpreterAccepted} vm=${r.vmAccepted} interpErr=${r.interpreterError}`,
              ).toBe(r.vmAccepted);
            }
            assertNearMissReachedEngine(spec.fixture, s, r);
          } else {
            const r = await runStatefulSpend({
              source,
              fileName,
              method: s.method,
              args: resolveStatefulArgs(s.args),
              constructorArgs: resolveCtorArray(s.constructorArgs ?? spec.constructorArgs),
              signerKey: s.signerKey ?? spec.signerKey ?? 'alice',
              lockTime: s.lockTime,
              satoshis: s.satoshis,
              tamperOutput: s.tamperOutput,
            });
            expect(r.vmAccepted, `real Spend: vmErr=${r.vmError}`).toBe(s.expect === 'accept');
            assertNearMissReachedEngine(spec.fixture, s, r);
            // Independent state-VALUE check (audit #4): accept/reject is blind to
            // an ANF state-transition miscompile that produces the same wrong
            // state in both the SDK-built output and the covenant. Decode the
            // on-chain continuation state and compare to a hand-authored value.
            if (s.expect === 'accept' && !s.tamperOutput) {
              if (s.expectedState !== undefined) {
                const want: Record<string, unknown> = {};
                for (const [k, v] of Object.entries(s.expectedState)) {
                  const p = placeholder(v);
                  if (p?.tag === 'pubkey') want[k] = testKey(p.key).pubKey;
                  else if (p?.tag === 'pkh') want[k] = testKey(p.key).pubKeyHash;
                  else want[k] = stateValue(v);
                }
                expect(
                  r.continuationState,
                  `${spec.fixture}.${s.method}: on-chain continuation state must equal the ` +
                    `hand-authored expectation (audit #4)` +
                    (r.stateDecodeError ? ` — state decode error: ${r.stateDecodeError}` : ''),
                ).toEqual(want);
              } else if (!s.noStateCheck) {
                throw new Error(
                  `${spec.fixture}: stateful accept spend "${s.method}" must declare ` +
                    `"expectedState" (independent state-value check, audit #4) or set ` +
                    `"noStateCheck": true with a reason in "note"`,
                );
              } else {
                // "noStateCheck": true is an opt-OUT, not a free pass. Enforce
                // the same honesty requirement at RUN TIME that
                // coverage-claims.test.ts already enforces statically (audit
                // P2-3) — a non-empty "note" AND a non-empty "issue" field —
                // so the two gates can never silently diverge.
                if (typeof s.note !== 'string' || s.note.trim().length === 0) {
                  throw new Error(
                    `${spec.fixture}: stateful accept spend "${s.method}" sets ` +
                      `"noStateCheck": true but has no non-empty "note" explaining why`,
                  );
                }
                if (typeof s.issue !== 'string' || s.issue.trim().length === 0) {
                  throw new Error(
                    `${spec.fixture}: stateful accept spend "${s.method}" sets ` +
                      `"noStateCheck": true but has no non-empty "issue" field describing the follow-up`,
                  );
                }
              }
            }
          }
        });
      }
    });
  }
});
