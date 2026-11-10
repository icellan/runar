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
 * Three spec kinds:
 *   - `stateless-signed` — a stateless SmartContract; `$sig` args are filled
 *     with real DER signatures; the accept path is additionally cross-checked
 *     against the ANF interpreter (source-vs-script agreement).
 *   - `stateful` — a StatefulSmartContract driven deploy→call through the SDK
 *     and re-validated on `Spend` (real checkPreimage + OP_CODESEPARATOR +
 *     optional user checkSig).
 *   - `precompiled-hex` (N-314) — a constructor-less stateless fixture whose
 *     `compilers` allowlist excludes ts (Go-only codegen), so nothing here can
 *     compile it. The COMMITTED `expected-script.hex` is executed as-is, with
 *     argument types read from the committed `expected-ir.json`, and the spec
 *     must content-pin that hex in `goldenHashes` — the pin is checked below,
 *     so a spec can never silently run bytes other than the ones it vouches for.
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
import { createHash } from 'node:crypto';
import {
  runStatelessSigned,
  runStatefulSpend,
  runPrecompiledHexSpend,
  testKey,
  type StatelessArg,
} from '../../packages/runar-testing/src/index.js';
import { extractConstructorArgs, matchesArtifact } from '../../packages/runar-sdk/src/script-utils.js';
import { MalformedScriptError } from '../../packages/runar-sdk/src/errors.js';
import { computeTemplateHash, resolveSlotLayout } from '../../packages/runar-sdk/src/slot-layout.js';
import type { RunarArtifact } from '../../packages/runar-ir-schema/src/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TESTS_DIR = join(__dirname, '..', 'tests');
const SPEC_DIR = join(__dirname, 'real-crypto');

interface Spec {
  fixture: string;
  kind: 'stateless-signed' | 'stateful' | 'precompiled-hex';
  /** precompiled-hex: sha256 pins of the committed goldens it executes. */
  goldenHashes?: Record<string, string>;
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
  /** nSequence for every input of the call tx. Unset = the SDK default
   *  (0xfffffffe when `lockTime` is non-zero, else 0xffffffff). Set it to model
   *  an all-final transaction, whose nLockTime consensus ignores entirely. */
  sequence?: number;
  satoshis?: number;
  /** Satoshis the deploy locks (F-024 value-conservation specs). */
  deploySatoshis?: number;
  tamperOutput?: boolean;
  /** N-045: build the call with an attacker SDK that believes these
   *  fixed-width types have these byte widths (see `attackerFieldWidths` in
   *  real-crypto-execution.ts), so the covenant's own width check rejects. */
  attackerFieldWidths?: Record<string, number>;
  /** N-051: claim a truncated `_codePart` ending at a 0x6a inside a baked
   *  readonly value (see `truncatedCodePart` in real-crypto-execution.ts). */
  truncatedCodePart?: { within: string; at: number };
  /** F-134-FU: build the call as an attacker who skips the SDK's local ANF
   *  pre-check and commits this continuation state (see `attackerNewState` in
   *  real-crypto-execution.ts). Only for a `cryptoNearMiss` reject: the row
   *  also asserts the default SDK path still refuses the same call. */
  attackerNewState?: Record<string, unknown>;
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
  /** Stateful accept only: read the EXECUTED deploy locking script back
   *  through the SDK's `matchesArtifact` / `extractConstructorArgs` (see
   *  `checkArtifactReadback`). */
  artifactReadback?: ArtifactReadback;
  // both
  cryptoNearMiss?: boolean;
  /** precompiled-hex reject: the engine error must match this (case-insensitive)
   *  regex, pinning the FAILURE CLASS and not just the verdict. */
  vmErrorPattern?: string;
  /** Stateful accept only: the slot layout and slot-excised template hash of
   *  the EXECUTED deployment (see `checkTemplateHash`). */
  templateHash?: TemplateHashPin;
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

/** Hex bytes written as one literal, a placeholder, or a list of either. */
type HexParts = string | Record<string, string> | (string | Record<string, string>)[];
function hexOf(v: HexParts): string {
  if (Array.isArray(v)) return v.map(hexOf).join('');
  const ph = placeholder(v);
  if (ph?.tag === 'pubkey') return testKey(ph.key).pubKey;
  if (ph?.tag === 'pkh') return testKey(ph.key).pubKeyHash;
  if (typeof v === 'string' && /^([0-9a-f]{2})*$/.test(v)) return v;
  throw new Error(`not a hex literal or placeholder: ${JSON.stringify(v)}`);
}

/** One change to the executed script, at a DEPLOYED byte offset. `was` is
 *  what must already be there (hand-derived from the artifact's template
 *  offsets and the deploy args); `with` replaces exactly those bytes. */
interface ScriptEdit {
  at: number;
  was: HexParts;
  with: HexParts;
}
interface ArtifactReadback {
  /** What extractConstructorArgs must return for the executed script. */
  constructorArgs: Record<string, unknown>;
  /** Byte where the code part ends; the OP_RETURN (0x6a) must sit there. */
  codePartByteLength: number;
  /** Hand-derived bytes at hand-derived deployed offsets, checked as-is. */
  holds: { at: number; was: HexParts }[];
  /** Scripts no deployment of this artifact produces: matchesArtifact must
   *  return false for every one. `extractThrows`: extractConstructorArgs must
   *  refuse it with MalformedScriptError. `dropStateTail`: cut the script at
   *  codePartByteLength (the code part with no OP_RETURN and no state). */
  notDeployments: { name: string; edits?: ScriptEdit[]; dropStateTail?: boolean; extractThrows?: boolean }[];
}

function bytesAt(hex: string, at: number, len: number): string {
  return hex.slice(at * 2, (at + len) * 2);
}

/**
 * The executed deploy script, read back through the SDK. The expectations are
 * the spec's own deploy args and hand-derived offsets — not anything the SDK
 * computed — and the script is the one the real Spend engine just accepted a
 * spend of, so a matchesArtifact / extractConstructorArgs that disagrees with
 * a real deployment, or that takes a script no deployment produces, fails.
 */
function checkArtifactReadback(
  label: string,
  rb: ArtifactReadback,
  artifact: RunarArtifact,
  lockingHex: string,
): void {
  for (const h of rb.holds) {
    const want = hexOf(h.was);
    expect(bytesAt(lockingHex, h.at, want.length / 2), `${label}: executed bytes at ${h.at}`).toBe(want);
  }
  expect(bytesAt(lockingHex, rb.codePartByteLength, 1), `${label}: OP_RETURN after the code part`).toBe('6a');

  expect(matchesArtifact(artifact, lockingHex), `${label}: the executed deployment must match`).toBe(true);
  const want: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(rb.constructorArgs)) {
    const ph = placeholder(v);
    want[k] = ph ? hexOf(v as Record<string, string>) : scalar(v);
  }
  expect(extractConstructorArgs(artifact, lockingHex), `${label}: constructor args read back`).toEqual(want);

  for (const t of rb.notDeployments) {
    let script = lockingHex;
    if (t.dropStateTail) script = script.slice(0, rb.codePartByteLength * 2);
    // Apply from the highest offset down so each `at` stays a deployed offset.
    for (const e of [...(t.edits ?? [])].sort((a, b) => b.at - a.at)) {
      const was = hexOf(e.was);
      expect(bytesAt(script, e.at, was.length / 2), `${label} ${t.name}: bytes at ${e.at}`).toBe(was);
      script = script.slice(0, e.at * 2) + hexOf(e.with) + script.slice(e.at * 2 + was.length);
    }
    expect(matchesArtifact(artifact, script), `${label} ${t.name}: not a deployment`).toBe(false);
    if (t.extractThrows) {
      expect(() => extractConstructorArgs(artifact, script), `${label} ${t.name}`).toThrow(MalformedScriptError);
    }
  }
}

const specFiles = readdirSync(SPEC_DIR).filter((f) => f.endsWith('.json'));

/** Per-test budget for a `precompiled-hex` spend only: the bn254-pairing golden
 *  is a ~4.7 MB script (~2.5 s per spend on @bsv/sdk Spend locally). Every other
 *  kind keeps the default timeout. */
const PRECOMPILED_TIMEOUT_MS = 120_000;

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

interface TemplateHashPin {
  /** hash256 of the code part with every constructor slot's value bytes cut
   *  out, push headers kept. Derived offline from the compiler's template
   *  (`artifact.script` with the excised placeholder bytes removed), not
   *  from slot-layout.ts. */
  hash256: string;
  /** Byte where the code part ends; the OP_RETURN (0x6a) must sit there. */
  codePartByteLength: number;
  /** Every constructor slot, at its DEPLOYED offset: `was` is the hand-derived
   *  bytes deploy writes there, `pushHeaderBytes` how many of them are a
   *  push header (kept in the hash) rather than value (cut). */
  slots: { param: string; at: number; was: string; encoding: string; pushHeaderBytes: number }[];
}

const hash256 = (hex: string): string => {
  const sha = (b: Buffer) => createHash('sha256').update(b).digest();
  return sha(sha(Buffer.from(hex, 'hex'))).toString('hex');
};

/**
 * The executed deployment, read back through resolveSlotLayout and
 * computeTemplateHash. The layout must agree with hand-derived bytes at
 * hand-derived offsets of the script the real Spend engine just accepted a
 * spend of, and the template hash must equal both the offline pin and the
 * hash of that executed code part with the declared value bytes cut out.
 */
function checkTemplateHash(
  label: string,
  pin: TemplateHashPin,
  artifact: RunarArtifact,
  lockingHex: string,
  constructorArgs: unknown[],
): void {
  const code = lockingHex.slice(0, pin.codePartByteLength * 2);
  expect(lockingHex.slice(pin.codePartByteLength * 2, pin.codePartByteLength * 2 + 2), `${label}: OP_RETURN`).toBe('6a');
  let excised = code;
  for (const sl of [...pin.slots].sort((a, b) => b.at - a.at)) {
    expect(code.slice(sl.at * 2, sl.at * 2 + sl.was.length), `${label}: executed bytes at ${sl.at}`).toBe(sl.was);
    excised = excised.slice(0, (sl.at + sl.pushHeaderBytes) * 2) + excised.slice(sl.at * 2 + sl.was.length);
  }
  expect(hash256(excised), `${label}: offline template-hash pin vs the executed code part`).toBe(pin.hash256);

  const layout = resolveSlotLayout(artifact, constructorArgs);
  expect(layout.codeByteLength, `${label}: resolved code length`).toBe(pin.codePartByteLength);
  expect(
    layout.slots.map((x) => ({
      param: x.name,
      at: x.byteOffset,
      encoding: x.encoding,
      byteLength: x.byteLength,
      pushHeaderBytes: x.pushHeaderBytes,
      valueByteOffset: x.valueByteOffset,
      valueByteLength: x.valueByteLength,
    })),
    `${label}: resolved slot layout`,
  ).toEqual(
    pin.slots.map((sl) => ({
      param: sl.param,
      at: sl.at,
      encoding: sl.encoding,
      byteLength: sl.was.length / 2,
      pushHeaderBytes: sl.pushHeaderBytes,
      valueByteOffset: sl.at + sl.pushHeaderBytes,
      valueByteLength: sl.was.length / 2 - sl.pushHeaderBytes,
    })),
  );
  expect(computeTemplateHash(artifact, constructorArgs), `${label}: computeTemplateHash`).toBe(pin.hash256);
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
          if (spec.kind === 'precompiled-hex') {
            const dir = join(TESTS_DIR, spec.fixture);
            const r = runPrecompiledHexSpend({
              scriptHex: readFileSync(join(dir, 'expected-script.hex'), 'utf-8'),
              irJson: readFileSync(join(dir, 'expected-ir.json'), 'utf-8'),
              method: s.method,
              args: resolveStatelessArgs(s.args) as (bigint | boolean | Uint8Array)[],
            });
            expect(r.vmAccepted, `real Spend: vmErr=${r.vmError}`).toBe(s.expect === 'accept');
            if (s.expect === 'reject') {
              // Every precompiled reject is a script rejection: no interpreter
              // runs, so a harness error must never pass for one.
              expect(r.reachedEngine, `harness error before the engine ran: ${r.vmError}`).toBe(true);
              if (s.vmErrorPattern !== undefined) {
                expect(r.vmError ?? '').toMatch(new RegExp(s.vmErrorPattern, 'i'));
              }
            }
          } else if (spec.kind === 'stateless-signed') {
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
            const spendOpts = {
              source,
              fileName,
              method: s.method,
              args: resolveStatefulArgs(s.args),
              constructorArgs: resolveCtorArray(s.constructorArgs ?? spec.constructorArgs),
              signerKey: s.signerKey ?? spec.signerKey ?? 'alice',
              lockTime: s.lockTime,
              sequence: s.sequence,
              satoshis: s.satoshis,
              deploySatoshis: s.deploySatoshis,
              tamperOutput: s.tamperOutput,
              attackerFieldWidths: s.attackerFieldWidths,
              truncatedCodePart: s.truncatedCodePart,
            };
            let attackerNewState: Record<string, unknown> | undefined;
            if (s.attackerNewState !== undefined) {
              // The attacker path exists only to put a REJECTED spend in front
              // of the engine; it must never manufacture an accept.
              expect(
                s.expect === 'reject' && s.cryptoNearMiss === true,
                `${spec.fixture}.${s.method}: attackerNewState is only valid on a cryptoNearMiss reject`,
              ).toBe(true);
              attackerNewState = {};
              for (const [k, v] of Object.entries(s.attackerNewState)) attackerNewState[k] = stateValue(v);
              // F-134 default stays fail-closed: the honest SDK refuses this
              // call before any transaction exists.
              const honest = await runStatefulSpend(spendOpts);
              expect(honest.vmAccepted).toBe(false);
              expect(honest.reachedEngine, `honest SDK must refuse before the engine: ${honest.vmError}`).toBe(false);
              expect(honest.vmError).toMatch(/the ANF interpreter could not evaluate the method body/);
            }
            const r = await runStatefulSpend({ ...spendOpts, attackerNewState });
            expect(r.vmAccepted, `real Spend: vmErr=${r.vmError}`).toBe(s.expect === 'accept');
            assertNearMissReachedEngine(spec.fixture, s, r);
            if (s.artifactReadback !== undefined) {
              expect(s.expect === 'accept' && !s.tamperOutput, 'artifactReadback is for an accepted spend').toBe(true);
              expect(r.vmAccepted).toBe(true);
              checkArtifactReadback(`${spec.fixture}.${s.method}`, s.artifactReadback, r.artifact!, r.lockingHex!);
            }
            if (s.templateHash !== undefined) {
              expect(s.expect === 'accept' && !s.tamperOutput, 'templateHash is for an accepted spend').toBe(true);
              checkTemplateHash(
                `${spec.fixture}.${s.method}`,
                s.templateHash,
                r.artifact!,
                r.lockingHex!,
                spendOpts.constructorArgs,
              );
            }
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
        }, spec.kind === 'precompiled-hex' ? PRECOMPILED_TIMEOUT_MS : undefined);
      }
    });
  }
});

// N-314: a `precompiled-hex` spec is route (A) evidence for a golden nothing in
// TS can re-derive, so it must be held to the bytes it vouches for. Every such
// spec pins the CURRENT sha256 of the hex it executes (and of the IR it reads
// argument types from), and is only legal for a fixture whose `compilers`
// allowlist excludes ts — anywhere TS can compile the fixture, compiling fresh
// (`stateless-signed`) is the stronger check and must be used instead.
describe('real-crypto precompiled-hex specs pin the exact goldens they execute (N-314)', () => {
  const sha256 = (p: string) => createHash('sha256').update(readFileSync(p)).digest('hex');
  const precompiled = specFiles
    .map((f) => JSON.parse(readFileSync(join(SPEC_DIR, f), 'utf-8')) as Spec)
    .filter((sp) => sp.kind === 'precompiled-hex');

  it('at least one precompiled-hex spec exists (the bn254-pairing Go-only fixture)', () => {
    expect(precompiled.map((sp) => sp.fixture)).toContain('bn254-pairing');
  });

  for (const sp of precompiled) {
    it(`${sp.fixture}: goldenHashes equal the committed goldens; allowlist excludes ts`, () => {
      const dir = join(TESTS_DIR, sp.fixture);
      for (const g of ['expected-script.hex', 'expected-ir.json']) {
        expect(sp.goldenHashes?.[g], `${sp.fixture}: goldenHashes["${g}"]`).toBe(sha256(join(dir, g)));
      }
      const cfg = JSON.parse(readFileSync(join(dir, 'source.json'), 'utf-8')) as { compilers?: string[] };
      expect(Array.isArray(cfg.compilers), `${sp.fixture}: needs a "compilers" allowlist`).toBe(true);
      expect(cfg.compilers).not.toContain('ts');
    });
  }
});
