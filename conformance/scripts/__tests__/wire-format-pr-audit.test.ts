// -----------------------------------------------------------------------------
// Tests for the MUST-MOVE-A-GOLDEN wire-format gate (plan §0.1 #3 / §2 P9 / §3 F1).
// -----------------------------------------------------------------------------
//
// The gate under test exists because of one concrete 2026-08 incident: a change
// altered the state-section wire framing in ALL SEVEN SDK serializers and moved
// ZERO pinned bytes, because the encoder and the decoder were co-changed and
// every test was a round-trip. The headline test below (`#110 regression`) is
// that exact shape and must stay red-if-broken forever.
//
// The second load-bearing test is `glob liveness`: a gate whose globs match
// nothing is worse than no gate, because it reports green. Every wire glob must
// match at least one file that exists in the repo today.
// -----------------------------------------------------------------------------

import { describe, it, expect, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  auditChangedPaths,
  loadExceptions,
  runCli,
  globToRegExp,
  matchesAnyGlob,
  pinKindOf,
  pinDiffIsMaterial,
  WIRE_FORMAT_RULES,
  WIRE_FORMAT_GLOBS,
  WIRE_FORMAT_ANCHORS,
  BYTE_ARTIFACT_PIN_GLOBS,
  CONTENT_SENSITIVE_PIN_GLOBS,
  WEAK_PIN_GLOBS,
  TIER_LOCAL_PIN_TEST_ROOT_GLOBS,
  TIER_LOCAL_PIN_NAME_GLOBS,
  PIN_GLOBS_NOT_YET_CREATED,
  EXCEPTIONS_REL,
  type WireFormatException,
  type ContentAccess,
} from '../wire-format-pr-audit.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '../../..');

/**
 * Every file that exists in the repo today, repo-root-relative POSIX paths:
 * tracked files PLUS untracked-but-not-ignored ones. `--others
 * --exclude-standard` matters because a fixture directory added by in-flight
 * work (e.g. Phase C's `conformance/sdk-vertical/`) is real the moment it is
 * written, not when it is staged — while `.gitignore` still keeps
 * `node_modules/`, `dist/`, `target/` and the worktree cache out.
 */
function repoFiles(): string[] {
  const out = execFileSync(
    'git',
    ['-C', REPO_ROOT, 'ls-files', '--cached', '--others', '--exclude-standard'],
    { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
  );
  return [...new Set(out.split('\n').map((s) => s.trim()).filter(Boolean))];
}

/**
 * The wire-format implementation paths touched by the real 2026-08 state-framing
 * change (commit bd7ec284 "port #110 MINIMALDATA encode_push_data to the other 6
 * SDKs" plus the Rust cherry-pick), stripped to the implementation files only.
 * This is the changed set the gate must reject.
 */
const HISTORICAL_110_WIRE_PATHS = [
  'packages/runar-sdk/src/state.ts',
  'packages/runar-sdk/src/contract.ts',
  'packages/runar-go/sdk_state.go',
  'packages/runar-rs/src/sdk/state.rs',
  'packages/runar-py/runar/sdk/state.py',
  'packages/runar-zig/src/sdk_state.zig',
  'packages/runar-rb/lib/runar/sdk/state.rb',
  'packages/runar-java/src/main/java/runar/lang/sdk/ScriptUtils.java',
];

/**
 * The LITERAL changed set of `bd7ec284` ("fix(sdk): port #110 MINIMALDATA
 * encode_push_data to the other 6 SDKs"), verbatim from
 * `git show --name-only bd7ec284` — implementation files AND the test files the
 * same commit co-added. This is the incident the whole gate exists for: it
 * changed state-section framing in seven SDKs, moved zero pinned bytes, and its
 * own commit message reports "SDK-output conformance 46/46".
 *
 * Feeding it back through the gate MUST exit 1. It did not until 2026-08-06:
 * the co-added `encode-push-data-minimaldata.test.ts` matched the `*minimaldata*`
 * tier-local WEAK-pin glob, and a weak pin used to satisfy the rule with only a
 * `⚠` warning. See the `bd7ec284` describe block below.
 */
const BD7EC284_CHANGED_SET = [
  'packages/runar-go/sdk_state.go',
  'packages/runar-go/sdk_test.go',
  'packages/runar-java/src/main/java/runar/lang/sdk/ScriptUtils.java',
  'packages/runar-java/src/test/java/runar/lang/sdk/ScriptUtilsTest.java',
  'packages/runar-py/runar/sdk/state.py',
  'packages/runar-py/tests/test_sdk_state.py',
  'packages/runar-rb/lib/runar/sdk/state.rb',
  'packages/runar-rb/spec/sdk/state_spec.rb',
  'packages/runar-sdk/src/__tests__/encode-push-data-minimaldata.test.ts',
  'packages/runar-sdk/src/contract.ts',
  'packages/runar-sdk/src/state.ts',
  'packages/runar-zig/src/sdk_state.zig',
];

/**
 * P0-1 (2026-08 gate audit). The P2PKH / OP_RETURN output-framing constants
 * (`1976a914`, `88ac`, `6a`) are emitted one pass UPSTREAM of stack-lower, in
 * anf-lower, in all seven tiers — plus the Zig stateful templates that hold the
 * same byte constants. anf-lower also owns `addOutputRefs` ordering, which
 * `hash256(outputs)` binds. The reviewer changed all eight and the gate passed.
 */
const ANF_LOWER_FRAMING_PATHS = [
  'packages/runar-compiler/src/passes/04-anf-lower.ts',
  'compilers/go/frontend/anf_lower.go',
  'compilers/rust/src/frontend/anf_lower.rs',
  'compilers/python/runar_compiler/frontend/anf_lower.py',
  'compilers/zig/src/passes/anf_lower.zig',
  'compilers/ruby/lib/runar_compiler/frontend/anf_lower.rb',
  'compilers/java/src/main/java/runar/compiler/passes/AnfLower.java',
  'compilers/zig/src/passes/helpers/stateful_templates.zig',
];

/** P1-2. The SDK-side ANF interpreters compute post-state values + the ordered
 *  output sequence that `hash256(outputs)` binds — seven independent copies. */
const SDK_ANF_INTERPRETER_PATHS = [
  'packages/runar-sdk/src/anf-interpreter.ts',
  'packages/runar-go/anf_interpreter.go',
  'packages/runar-rs/src/sdk/anf_interpreter.rs',
  'packages/runar-py/runar/sdk/anf_interpreter.py',
  'packages/runar-zig/src/sdk_anf_interpreter.zig',
  'packages/runar-rb/lib/runar/sdk/anf_interpreter.rb',
  'packages/runar-java/src/main/java/runar/lang/sdk/AnfInterpreter.java',
];

/** P1-3. Hand-rolled BIP-143 signing-preimage serialization (TS/Go/Zig delegate
 *  to an upstream SDK or to the already-globbed contract module). */
const BIP143_PREIMAGE_PATHS = [
  'packages/runar-rs/src/sdk/signer.rs',
  'packages/runar-py/runar/sdk/local_signer.py',
  'packages/runar-rb/lib/runar/sdk/bip143.rb',
  'packages/runar-java/src/main/java/runar/lang/sdk/RawTx.java',
];

/** A real witness, used verbatim as the reviewer's laundering fixture. */
const WITNESS_REL = 'conformance/witnesses/real-crypto/stateful-counter.json';
const WITNESS_BEFORE = readFileSync(join(REPO_ROOT, WITNESS_REL), 'utf8');
/** The reviewer's bypass: edit ONE free-text `note` and nothing else. */
const WITNESS_NOTE_ONLY = WITNESS_BEFORE.replace(
  '"note": "count 5->6"',
  '"note": "count 5->6 (increment path)"',
);
/** The honest version of the same edit: the pinned post-state actually moved. */
const WITNESS_STATE_MOVED = WITNESS_BEFORE.replace('"count": "6n"', '"count": "7n"');

const NOW = new Date('2026-08-05T12:00:00Z');
const STATE_TS_SHA = 'a'.repeat(64);

/** A well-formed exception entry (P1-4 requires expires + sha256 + reviewer). */
function exception(over: Partial<WireFormatException> = {}): WireFormatException {
  return {
    path: 'packages/runar-sdk/src/state.ts',
    reason: 'comment-only touch; no byte change over the state value-class matrix',
    date: '2026-08-05',
    expires: '2026-09-05',
    sha256: STATE_TS_SHA,
    reviewer: 'gh:siggi',
    ...over,
  };
}

/** In-memory ContentAccess so the pure gate can be driven without a repo. */
function stubContent(opts: {
  sha?: Record<string, string>;
  pins?: Record<string, { before: string | null; after: string | null }>;
}): ContentAccess {
  return {
    sha256: (p) => opts.sha?.[p] ?? null,
    pinContent: (p) => opts.pins?.[p] ?? null,
  };
}

describe('wire-format-pr-audit — glob engine', () => {
  it('translates * to a single-segment wildcard', () => {
    expect(globToRegExp('packages/*/src/state.ts').test('packages/runar-sdk/src/state.ts')).toBe(true);
    expect(globToRegExp('packages/*/src/state.ts').test('packages/a/b/src/state.ts')).toBe(false);
  });

  it('translates **/ to zero-or-more path segments', () => {
    const re = globToRegExp('**/*codesep*');
    expect(re.test('packages/runar-rb/spec/sdk/codesep_offsets_spec.rb')).toBe(true);
    expect(re.test('codesep.ts')).toBe(true);
    expect(re.test('packages/runar-sdk/src/state.ts')).toBe(false);
  });

  it('translates a trailing ** to any suffix', () => {
    const re = globToRegExp('conformance/sdk-output/**');
    expect(re.test('conformance/sdk-output/tests/x/expected-locking.hex')).toBe(true);
    expect(re.test('conformance/sdk-outputs/tests/x.hex')).toBe(false);
  });

  it('anchors both ends (no accidental substring matches)', () => {
    const re = globToRegExp('packages/runar-sdk/src/state.ts');
    expect(re.test('packages/runar-sdk/src/state.ts')).toBe(true);
    expect(re.test('vendor/packages/runar-sdk/src/state.ts')).toBe(false);
    expect(re.test('packages/runar-sdk/src/state.tsx')).toBe(false);
  });

  it('escapes regex metacharacters in literal path segments', () => {
    // `06-emit.ts` — the `.` must not match an arbitrary character.
    const re = globToRegExp('packages/runar-compiler/src/passes/06-emit.ts');
    expect(re.test('packages/runar-compiler/src/passes/06-emit.ts')).toBe(true);
    expect(re.test('packages/runar-compiler/src/passes/06-emitXts')).toBe(false);
  });
});

describe('wire-format-pr-audit — auditChangedPaths', () => {
  it('#110 regression: all 7 SDK state serializers changed with ZERO pins ⇒ FAIL', () => {
    const res = auditChangedPaths(HISTORICAL_110_WIRE_PATHS);

    expect(res.ok).toBe(false);
    expect(res.pinHits).toEqual([]);
    // Every wire path must be named in the report — the author needs to know
    // exactly which files tripped the gate.
    for (const p of HISTORICAL_110_WIRE_PATHS) {
      expect(res.wireHits).toContain(p);
      expect(res.message).toContain(p);
    }
    // The message must tell the author what to do, not just that it failed.
    expect(res.message).toMatch(/must move a golden|MUST-MOVE-A-GOLDEN/i);
    expect(res.message).toContain('conformance/sdk-output/tests/');
    expect(res.message).toContain(EXCEPTIONS_REL);
  });

  it('the same wire change PLUS an sdk-output golden diff ⇒ pass', () => {
    const res = auditChangedPaths([
      ...HISTORICAL_110_WIRE_PATHS,
      'conformance/sdk-output/tests/stateful-bytestring-op-n-state/expected-locking.hex',
    ]);
    expect(res.ok).toBe(true);
    expect(res.pinHits).toContain(
      'conformance/sdk-output/tests/stateful-bytestring-op-n-state/expected-locking.hex',
    );
  });

  it('sdk-output TOOLING is not a pin — only its fixtures are', () => {
    // Editing the cross-SDK runner must not satisfy a must-move-a-golden gate.
    const res = auditChangedPaths([
      ...HISTORICAL_110_WIRE_PATHS,
      'conformance/sdk-output/runner/sdk-runner.ts',
      'conformance/sdk-output/generate-inputs.ts',
    ]);
    expect(res.ok).toBe(false);
    expect(res.pinHits).toEqual([]);
  });

  it('a wire change plus a conformance fixture golden ⇒ pass', () => {
    const res = auditChangedPaths([
      'packages/runar-compiler/src/passes/05-stack-lower.ts',
      'conformance/tests/stateful/expected-script.hex',
      'conformance/tests/stateful/expected-ir.json',
    ]);
    expect(res.ok).toBe(true);
    expect(res.pinHits).toHaveLength(2);
  });

  it('docs-only change ⇒ pass (no wire hits at all)', () => {
    const res = auditChangedPaths([
      'docs/testing-guide.md',
      'conformance/README.md',
      'docs/audit/2026-08-testing-gap-remediation-plan.md',
    ]);
    expect(res.ok).toBe(true);
    expect(res.wireHits).toEqual([]);
    expect(res.message).toMatch(/no wire-format/i);
  });

  it('non-wire source change ⇒ pass', () => {
    const res = auditChangedPaths([
      'packages/runar-cli/src/index.ts',
      'packages/runar-sdk/src/providers/mock.ts',
      'compilers/go/frontend/parser_ts.go',
    ]);
    expect(res.ok).toBe(true);
    expect(res.wireHits).toEqual([]);
  });

  it('empty changed set ⇒ pass', () => {
    expect(auditChangedPaths([]).ok).toBe(true);
  });

  it('wire change covered by an exception entry ⇒ pass, and the exception is reported', () => {
    const res = auditChangedPaths(['packages/runar-sdk/src/state.ts'], {
      exceptions: [exception({ reason: 'pure rename of a private helper; encoder output byte-identical over the C1 matrix' })],
      content: stubContent({ sha: { 'packages/runar-sdk/src/state.ts': STATE_TS_SHA } }),
      now: NOW,
    });

    expect(res.ok).toBe(true);
    expect(res.wireHits).toEqual([]);
    expect(res.exceptionsUsed).toHaveLength(1);
    expect(res.exceptionsUsed[0]?.path).toBe('packages/runar-sdk/src/state.ts');
    // Every exception used must be printed, with its reason and date.
    expect(res.message).toContain('packages/runar-sdk/src/state.ts');
    expect(res.message).toContain('pure rename of a private helper');
    expect(res.message).toContain('2026-08-05');
  });

  it('an exception covers only its exact path — peers still trip the gate', () => {
    const res = auditChangedPaths(HISTORICAL_110_WIRE_PATHS, {
      exceptions: [exception()],
      content: stubContent({ sha: { 'packages/runar-sdk/src/state.ts': STATE_TS_SHA } }),
      now: NOW,
    });

    expect(res.ok).toBe(false);
    expect(res.wireHits).not.toContain('packages/runar-sdk/src/state.ts');
    expect(res.wireHits).toContain('packages/runar-go/sdk_state.go');
    expect(res.exceptionsUsed).toHaveLength(1);
  });

  it('a malformed exception entry is a hard failure, never a free pass', () => {
    const res = auditChangedPaths(['packages/runar-sdk/src/state.ts'], {
      exceptions: [{ path: 'packages/runar-sdk/src/state.ts', reason: 'nope', date: 'yesterday' } as WireFormatException],
      now: NOW,
    });
    expect(res.ok).toBe(false);
    expect(res.problems.length).toBeGreaterThan(0);
    expect(res.message).toMatch(/malformed/i);
  });

  it('an unused exception entry does not silently mask anything', () => {
    const res = auditChangedPaths(['packages/runar-sdk/src/state.ts'], {
      exceptions: [exception({ path: 'packages/runar-go/sdk_state.go' })],
      content: stubContent({ sha: { 'packages/runar-go/sdk_state.go': STATE_TS_SHA } }),
      now: NOW,
    });
    expect(res.ok).toBe(false);
    expect(res.exceptionsUsed).toEqual([]);
  });

  it('reports the wire family for each hit so the author knows which register row moved', () => {
    const res = auditChangedPaths(['packages/runar-rb/lib/runar/sdk/state.rb']);
    expect(res.ok).toBe(false);
    expect(res.message).toContain('sdk-state-serialization');
  });

  it('a tier-local unit test is a WEAK pin and is NOT sufficient on its own ⇒ FAIL', () => {
    // FLIPPED 2026-08-06. This test used to assert the opposite — "flags a
    // tier-local unit test as a WEAK pin (round-trip class) WITHOUT failing" —
    // and its own comment said "if the pin list is ever tightened to require a
    // cross-component byte pin, this test goes red on purpose". It has been
    // tightened, for one measured reason: replaying the LITERAL changed set of
    // bd7ec284 (the incident this gate exists for) through the gate exited 0,
    // because that commit co-added exactly this file and a weak pin satisfied
    // the rule. The warn-only allowance was granted when
    // `conformance/sdk-vertical/**` did not exist; it does now (39 cases × 7
    // tiers of absolute pins), so a strong pin is available to any wire change
    // and there is nothing left to soften for. See the `bd7ec284` block below.
    const res = auditChangedPaths([
      ...HISTORICAL_110_WIRE_PATHS,
      'packages/runar-sdk/src/__tests__/encode-push-data-minimaldata.test.ts',
    ]);
    expect(res.ok).toBe(false);
    expect(res.weakPinOnly).toBe(true);
    // Still counted and still named as a pin — it is evidence, just not
    // sufficient evidence — and the report must say which pins were weak.
    expect(res.pinHits).toContain(
      'packages/runar-sdk/src/__tests__/encode-push-data-minimaldata.test.ts',
    );
    expect(res.message).toMatch(/WEAK/);
    expect(res.message).toContain('encode-push-data-minimaldata.test.ts');
  });

  it('a cross-component byte pin is not flagged weak', () => {
    const res = auditChangedPaths([
      ...HISTORICAL_110_WIRE_PATHS,
      'conformance/witnesses/real-crypto/stateful-counter.json',
    ]);
    expect(res.ok).toBe(true);
    expect(res.weakPinOnly).toBe(false);
  });

  it('ignores blank entries and normalises leading ./ in the changed set', () => {
    const res = auditChangedPaths(['', '   ', './packages/runar-sdk/src/state.ts']);
    expect(res.wireHits).toEqual(['packages/runar-sdk/src/state.ts']);
  });
});

// -----------------------------------------------------------------------------
// THE HEADLINE REGRESSION. Named after the commit on purpose: this gate exists
// because of `bd7ec284`, and until 2026-08-06 replaying that commit's literal
// changed set through it exited 0. If you are here because one of these tests
// went red, you are undoing the fix for the exact incident the gate was built
// for — say so out loud in the PR description before you weaken it.
// -----------------------------------------------------------------------------
describe('wire-format-pr-audit — bd7ec284 (the incident this gate exists for)', () => {
  it('bd7ec284: the literal changed set FAILS (a co-added weak pin is not evidence)', () => {
    const res = auditChangedPaths(BD7EC284_CHANGED_SET);

    expect(res.ok).toBe(false);
    // The only pin that commit moved was its own tier-local codec test.
    expect(res.pinHits).toEqual([
      'packages/runar-sdk/src/__tests__/encode-push-data-minimaldata.test.ts',
    ]);
    expect(res.weakPinOnly).toBe(true);
    // Seven implementation paths across three wire families tripped it.
    expect(res.wireHits).toContain('packages/runar-sdk/src/state.ts');
    expect(res.wireHits).toContain('packages/runar-go/sdk_state.go');
    expect(res.wireHits).toContain('packages/runar-py/runar/sdk/state.py');
    expect(res.wireHits).toContain('packages/runar-rb/lib/runar/sdk/state.rb');
    expect(res.wireHits).toContain('packages/runar-zig/src/sdk_state.zig');
    expect(res.wireHits).toContain(
      'packages/runar-java/src/main/java/runar/lang/sdk/ScriptUtils.java',
    );
    expect(res.wireHits).toContain('packages/runar-sdk/src/contract.ts');
    // The co-added tier tests that are NOT pins must not be reported as pins.
    expect(res.pinHits).not.toContain('packages/runar-go/sdk_test.go');
    expect(res.pinHits).not.toContain('packages/runar-py/tests/test_sdk_state.py');
  });

  it('bd7ec284: the failure names the weak pin AND the strong-pin families', () => {
    const { message } = auditChangedPaths(BD7EC284_CHANGED_SET);
    expect(message).toMatch(/MUST-MOVE-A-GOLDEN GATE FAILED/);
    expect(message).toContain(
      'packages/runar-sdk/src/__tests__/encode-push-data-minimaldata.test.ts',
    );
    // The three strong-pin families that were unavailable in 2026-07 and are
    // available now — an author who trips this must be told where to go.
    expect(message).toContain('conformance/sdk-vertical/cases/*/expected-*');
    expect(message).toContain('conformance/sdk-output/tests/*/expected-*.hex');
    expect(message).toContain('conformance/tests/**/expected-*');
  });

  it('bd7ec284: adding ONE strong pin turns the same changed set green (the gate stays passable)', () => {
    // The control run from the 2026-08-06 drill. Tightening weak pins must not
    // make the gate unpassable: the identical wire change with a real
    // cross-component byte pin is exactly what the author is being asked for.
    const res = auditChangedPaths([
      ...BD7EC284_CHANGED_SET,
      'conformance/sdk-output/tests/stateful-bytestring-op-n-state/expected-locking.hex',
    ]);
    expect(res.ok).toBe(true);
    expect(res.weakPinOnly).toBe(false);
    // The weak pin still counts as (insufficient) evidence and is still listed.
    expect(res.pinHits).toContain(
      'packages/runar-sdk/src/__tests__/encode-push-data-minimaldata.test.ts',
    );
  });
});

// -----------------------------------------------------------------------------
// 2026-08 adversarial audit of THIS GATE. Every changed-set below is a bypass an
// adversarial reviewer executed against the CLI and got a clean exit 0 from.
// Each one is reproduced verbatim and must now FAIL.
// -----------------------------------------------------------------------------
describe('wire-format-pr-audit — audit regressions: unglobbed wire paths', () => {
  it('P0-1: the eight anf-lower framing paths are wire paths (P2PKH/OP_RETURN consts live one pass upstream)', () => {
    const res = auditChangedPaths(ANF_LOWER_FRAMING_PATHS);
    expect(res.ok).toBe(false);
    for (const p of ANF_LOWER_FRAMING_PATHS) {
      expect(res.wireHits, `unglobbed wire path: ${p}`).toContain(p);
    }
    // Same register row as stack-lower: it is the same OP_RETURN / P2PKH framing.
    expect(res.message).toContain('state-framing-stack-lower');
  });

  it('P0-2: the shared state width table is a wire path (compiler AND SDK read it)', () => {
    // STATE_FIELD_WIDTHS decides every state field's byte width for the
    // assembler (artifact/assembler.ts) and for the SDK serializer
    // (sdk/state.ts, sdk/slot-layout.ts). Changing it moves deployed bytes in
    // both directions at once; the gate globbed only the sibling type file.
    const res = auditChangedPaths(['packages/runar-ir-schema/src/state-layout.ts']);
    expect(res.ok).toBe(false);
    expect(res.wireHits).toContain('packages/runar-ir-schema/src/state-layout.ts');
    expect(res.message).toContain('sdk-state-serialization');
  });

  it('P2-9: the artifact JSON schema is a wire path (it types the fields SDKs splice on)', () => {
    const res = auditChangedPaths(['packages/runar-ir-schema/src/schemas/artifact.schema.json']);
    expect(res.ok).toBe(false);
    expect(res.wireHits).toContain('packages/runar-ir-schema/src/schemas/artifact.schema.json');
  });

  it('P1-1: continuation-output assembly outside the contract module is a wire path', () => {
    // Java literally does `codePart + "6a" + stateHex`; Zig assembles the
    // contract-output list (and therefore the hash256(outputs) ordering).
    const recipe = [
      'packages/runar-java/src/main/java/runar/lang/sdk/TransactionBuilder.java',
      'packages/runar-zig/src/sdk_call.zig',
    ];
    const res = auditChangedPaths(recipe);
    expect(res.ok).toBe(false);
    for (const p of recipe) expect(res.wireHits).toContain(p);
  });

  it('P1-2: the seven SDK ANF interpreters are wire paths (post-state + output ordering)', () => {
    const res = auditChangedPaths(SDK_ANF_INTERPRETER_PATHS);
    expect(res.ok).toBe(false);
    for (const p of SDK_ANF_INTERPRETER_PATHS) expect(res.wireHits).toContain(p);
  });

  it('P1-2: the cross-tier ANF-interpreter expected outputs are a byte pin', () => {
    const res = auditChangedPaths([
      ...SDK_ANF_INTERPRETER_PATHS,
      'conformance/anf-interpreter/expected/stateful-counter-increment.json',
    ]);
    expect(res.ok).toBe(true);
    expect(res.weakPinOnly).toBe(false);
  });

  it('P1-3: hand-rolled BIP-143 preimage serialization is a wire path', () => {
    const res = auditChangedPaths(BIP143_PREIMAGE_PATHS);
    expect(res.ok).toBe(false);
    for (const p of BIP143_PREIMAGE_PATHS) expect(res.wireHits).toContain(p);
  });

  it('P1-3: the cross-tier BIP-143 fixture is a byte pin', () => {
    const res = auditChangedPaths([
      ...BIP143_PREIMAGE_PATHS,
      'conformance/sdk-bip143/fixtures.json',
    ]);
    expect(res.ok).toBe(true);
    expect(res.weakPinOnly).toBe(false);
  });

  it('P2-10: multi-contract unlocking-script assembly is a wire path', () => {
    const res = auditChangedPaths(['packages/runar-sdk/src/multi-contract.ts']);
    expect(res.ok).toBe(false);
    expect(res.wireHits).toContain('packages/runar-sdk/src/multi-contract.ts');
  });
});

describe('wire-format-pr-audit — audit regressions: pin inflation (P0-3)', () => {
  it('P0-3a: a brand-new doc file whose NAME contains "codesep" is not a pin', () => {
    // Verbatim reviewer bypass: `conformance/codesep-notes.md` matched the
    // unanchored `**/*codesep*` glob AND counted as a STRONG pin, so the whole
    // #110 changed set shipped with zero warnings.
    const res = auditChangedPaths([...HISTORICAL_110_WIRE_PATHS, 'conformance/codesep-notes.md']);
    expect(res.ok).toBe(false);
    expect(res.pinHits).toEqual([]);
  });

  it('P0-3a: the same trick from anywhere else in the tree is not a pin either', () => {
    const res = auditChangedPaths([
      ...HISTORICAL_110_WIRE_PATHS,
      'docs/state_push_framing.md',
      'notes/constructor-slots.txt',
      'packages/runar-sdk/README-codesep.md',
    ]);
    expect(res.ok).toBe(false);
    expect(res.pinHits).toEqual([]);
  });

  it('P0-3a: a REAL tier-local framing test is a pin (weak) in every tier — counted, not sufficient', () => {
    // FLIPPED 2026-08-06 alongside the `bd7ec284` block: a tier-local test is
    // still recognised as a pin in all seven tiers (that half of P0-3a is
    // unchanged — a doc named `*codesep*` must NOT be), but weak-only no longer
    // satisfies the gate. The distinction being asserted here is pin
    // CLASSIFICATION, which is what P0-3a was about; sufficiency moved.
    const realTierLocalPins = [
      'packages/runar-sdk/src/__tests__/codesep-offsets.test.ts',
      'packages/runar-go/sdk_state_push_framing_test.go',
      'packages/runar-rs/tests/state_push_framing.rs',
      'packages/runar-py/tests/test_codesep_offsets.py',
      'packages/runar-zig/src/sdk_c9_s1_minimaldata_roundtrip_test.zig',
      'packages/runar-rb/spec/sdk/state_push_framing_spec.rb',
      'packages/runar-java/src/test/java/runar/lang/sdk/StatePushFramingTest.java',
    ];
    for (const pin of realTierLocalPins) {
      const res = auditChangedPaths([...HISTORICAL_110_WIRE_PATHS, pin]);
      expect(res.pinHits, `${pin} should be a pin`).toContain(pin);
      expect(res.weakPinOnly, `${pin} is tier-local ⇒ weak`).toBe(true);
      expect(res.ok, `${pin} is weak ⇒ must not satisfy the gate alone`).toBe(false);
      // ... but it does satisfy it next to one cross-component byte pin.
      const withStrong = auditChangedPaths([
        ...HISTORICAL_110_WIRE_PATHS,
        pin,
        'conformance/sdk-vertical/cases/bigint-0/expected-locking.hex',
      ]);
      expect(withStrong.ok, `${pin} + a strong pin should pass`).toBe(true);
      expect(withStrong.weakPinOnly).toBe(false);
    }
  });

  it('P0-3c: sdk-output INPUTS are not goldens — only expected-*.hex is', () => {
    // Verbatim reviewer bypass: the pin glob was `sdk-output/tests/**`, which
    // swallowed all 48 `input.json` files. Touching an input moves no golden.
    const res = auditChangedPaths([
      ...HISTORICAL_110_WIRE_PATHS,
      'conformance/sdk-output/tests/arithmetic/input.json',
      'conformance/sdk-output/tests/auction/input.json',
    ]);
    expect(res.ok).toBe(false);
    expect(res.pinHits).toEqual([]);
  });

  it('P0-3c: the same fixture directory’s expected-locking.hex IS a pin', () => {
    const res = auditChangedPaths([
      ...HISTORICAL_110_WIRE_PATHS,
      'conformance/sdk-output/tests/arithmetic/expected-locking.hex',
    ]);
    expect(res.ok).toBe(true);
    expect(res.weakPinOnly).toBe(false);
  });

  it('P0-3c: sdk-vertical inputs/tooling are not pins; its expected-* files are', () => {
    const notPins = auditChangedPaths([
      ...HISTORICAL_110_WIRE_PATHS,
      'conformance/sdk-vertical/cases/bigint-0/input.json',
      'conformance/sdk-vertical/runner/vertical-runner.ts',
      'conformance/sdk-vertical/generate.ts',
      'conformance/sdk-vertical/contracts/SlotMatrix.runar.ts',
    ]);
    expect(notPins.ok).toBe(false);
    expect(notPins.pinHits).toEqual([]);

    const pins = auditChangedPaths([
      ...HISTORICAL_110_WIRE_PATHS,
      'conformance/sdk-vertical/cases/bigint-0/expected-locking.hex',
    ]);
    expect(pins.ok).toBe(true);
    expect(pins.weakPinOnly).toBe(false);
  });

  it('P0-3d: a strong pin means "is a byte artifact", not "lives under conformance/"', () => {
    // The construct ledger is prose evidence, not bytes. FLIPPED 2026-08-06:
    // it no longer satisfies the gate on its own either (same reason as the
    // `bd7ec284` block — a weak pin is a claim about bytes, not bytes).
    const res = auditChangedPaths([...HISTORICAL_110_WIRE_PATHS, 'conformance/construct-ledger.json']);
    expect(res.ok).toBe(false);
    expect(res.weakPinOnly).toBe(true);

    const bytes = auditChangedPaths([
      ...HISTORICAL_110_WIRE_PATHS,
      'conformance/tests/stateful/expected-script.hex',
    ]);
    expect(bytes.weakPinOnly).toBe(false);
  });
});

describe('wire-format-pr-audit — audit regressions: witness laundering (P0-3b)', () => {
  it('a witness diff that edits ONLY free text does not count as a pin', () => {
    // Verbatim reviewer bypass: edit one `"note"` string in
    // conformance/witnesses/real-crypto/stateful-counter.json and the entire
    // #110 wire changed set ships green, reported as a STRONG cross-component
    // byte pin. Prose is not evidence that a byte moved.
    expect(WITNESS_NOTE_ONLY).not.toBe(WITNESS_BEFORE);
    const res = auditChangedPaths([...HISTORICAL_110_WIRE_PATHS, WITNESS_REL], {
      content: stubContent({ pins: { [WITNESS_REL]: { before: WITNESS_BEFORE, after: WITNESS_NOTE_ONLY } } }),
    });
    expect(res.ok).toBe(false);
    expect(res.pinHits).toEqual([]);
    expect(res.immaterialPins).toContain(WITNESS_REL);
    expect(res.message).toMatch(/free text|free-text/i);
  });

  it('the same witness counts when the pinned post-state actually moves', () => {
    const res = auditChangedPaths([...HISTORICAL_110_WIRE_PATHS, WITNESS_REL], {
      content: stubContent({ pins: { [WITNESS_REL]: { before: WITNESS_BEFORE, after: WITNESS_STATE_MOVED } } }),
    });
    expect(res.ok).toBe(true);
    expect(res.pinHits).toContain(WITNESS_REL);
    expect(res.weakPinOnly).toBe(false);
  });

  it('a brand-new witness with no spends is not evidence either', () => {
    const res = auditChangedPaths([...HISTORICAL_110_WIRE_PATHS, WITNESS_REL], {
      content: stubContent({
        pins: { [WITNESS_REL]: { before: null, after: '{"fixture":"x","kind":"stateful","spends":[]}\n' } },
      }),
    });
    expect(res.ok).toBe(false);
    expect(res.immaterialPins).toContain(WITNESS_REL);
  });

  it('a brand-new witness that carries spends IS evidence', () => {
    const res = auditChangedPaths([...HISTORICAL_110_WIRE_PATHS, WITNESS_REL], {
      content: stubContent({ pins: { [WITNESS_REL]: { before: null, after: WITNESS_BEFORE } } }),
    });
    expect(res.ok).toBe(true);
    expect(res.pinHits).toContain(WITNESS_REL);
  });

  it('when the before/after content is unavailable the pin still counts, and the report says so', () => {
    // Fail-open on the PIN side only: never hard-fail a PR because git could
    // not produce the base blob. It is reported so it cannot pass unnoticed.
    const res = auditChangedPaths([...HISTORICAL_110_WIRE_PATHS, WITNESS_REL]);
    expect(res.ok).toBe(true);
    expect(res.unverifiedPins).toContain(WITNESS_REL);
    expect(res.message).toMatch(/could not be verified|unverified/i);
  });

  it('pinDiffIsMaterial ignores note/description/comment at any depth', () => {
    const base = JSON.stringify({
      fixture: 'x',
      note: 'top',
      spends: [{ method: 'increment', note: 'inner', expectedState: { count: '6n' } }],
    });
    const prose = JSON.stringify({
      fixture: 'x',
      note: 'top rewritten',
      spends: [{ method: 'increment', note: 'inner rewritten', expectedState: { count: '6n' } }],
    });
    const evidence = JSON.stringify({
      fixture: 'x',
      note: 'top',
      spends: [{ method: 'increment', note: 'inner', expectedState: { count: '7n' } }],
    });
    expect(pinDiffIsMaterial(base, prose)).toBe(false);
    expect(pinDiffIsMaterial(base, evidence)).toBe(true);
    // Deletion is always material; unparseable content is never assumed cosmetic.
    expect(pinDiffIsMaterial(base, null)).toBe(true);
    expect(pinDiffIsMaterial(base, '{ not json')).toBe(true);
  });
});

describe('wire-format-pr-audit — audit regressions: exception hardening (P1-4)', () => {
  it('an exception without an expiry is malformed (exceptions are never permanent)', () => {
    const res = auditChangedPaths(['packages/runar-sdk/src/state.ts'], {
      exceptions: [{ ...exception(), expires: undefined } as unknown as WireFormatException],
      content: stubContent({ sha: { 'packages/runar-sdk/src/state.ts': STATE_TS_SHA } }),
      now: NOW,
    });
    expect(res.ok).toBe(false);
    expect(res.problems.join('\n')).toMatch(/expires/);
  });

  it('an expired exception is a hard failure, not a silent pass', () => {
    const res = auditChangedPaths(['packages/runar-sdk/src/state.ts'], {
      exceptions: [exception({ date: '2026-01-01', expires: '2026-02-01' })],
      content: stubContent({ sha: { 'packages/runar-sdk/src/state.ts': STATE_TS_SHA } }),
      now: NOW,
    });
    expect(res.ok).toBe(false);
    expect(res.problems.join('\n')).toMatch(/expired/i);
  });

  it('an exception that outlives the cap is malformed', () => {
    const res = auditChangedPaths(['packages/runar-sdk/src/state.ts'], {
      exceptions: [exception({ expires: '2030-01-01' })],
      content: stubContent({ sha: { 'packages/runar-sdk/src/state.ts': STATE_TS_SHA } }),
      now: NOW,
    });
    expect(res.ok).toBe(false);
    expect(res.problems.join('\n')).toMatch(/180/);
  });

  it('an exception without a content pin or a reviewer is malformed', () => {
    const noSha = auditChangedPaths(['packages/runar-sdk/src/state.ts'], {
      exceptions: [{ ...exception(), sha256: undefined } as unknown as WireFormatException],
      now: NOW,
    });
    expect(noSha.problems.join('\n')).toMatch(/sha256/);

    const noReviewer = auditChangedPaths(['packages/runar-sdk/src/state.ts'], {
      exceptions: [{ ...exception(), reviewer: undefined } as unknown as WireFormatException],
      now: NOW,
    });
    expect(noReviewer.problems.join('\n')).toMatch(/reviewer/);
  });

  it('an exception whose sha256 does not match the file suppresses nothing', () => {
    // The content pin is what stops an entry granted for a comment-only touch
    // from covering every LATER change to the same file (P1-4).
    const res = auditChangedPaths(['packages/runar-sdk/src/state.ts'], {
      exceptions: [exception()],
      content: stubContent({ sha: { 'packages/runar-sdk/src/state.ts': 'b'.repeat(64) } }),
      now: NOW,
    });
    expect(res.ok).toBe(false);
    expect(res.exceptionsUsed).toEqual([]);
    expect(res.exceptionsRejected).toHaveLength(1);
    expect(res.message).toMatch(/sha256 mismatch|no longer matches/i);
  });

  it('an exception cannot apply at all when the content is unreadable (fail closed)', () => {
    const res = auditChangedPaths(['packages/runar-sdk/src/state.ts'], {
      exceptions: [exception()],
      now: NOW,
    });
    expect(res.ok).toBe(false);
    expect(res.exceptionsUsed).toEqual([]);
  });
});

describe('wire-format-pr-audit — glob liveness (a gate that matches nothing is worse than no gate)', () => {
  const files = repoFiles();

  it('every wire glob matches at least one file that exists in the repo today', () => {
    const dead: string[] = [];
    for (const rule of WIRE_FORMAT_RULES) {
      for (const glob of rule.globs) {
        const re = globToRegExp(glob);
        if (!files.some((f) => re.test(f))) dead.push(`${rule.family}: ${glob}`);
      }
    }
    expect(dead, `dead wire glob(s) — they can never fire:\n  ${dead.join('\n  ')}`).toEqual([]);
  });

  it('every pin glob either matches a real file or is declared not-yet-created', () => {
    const dead: string[] = [];
    for (const glob of [
      ...BYTE_ARTIFACT_PIN_GLOBS,
      ...WEAK_PIN_GLOBS,
      ...TIER_LOCAL_PIN_TEST_ROOT_GLOBS,
    ]) {
      if (PIN_GLOBS_NOT_YET_CREATED.includes(glob)) continue;
      const re = globToRegExp(glob);
      if (!files.some((f) => re.test(f))) dead.push(glob);
    }
    expect(dead, `dead pin glob(s):\n  ${dead.join('\n  ')}`).toEqual([]);
  });

  it('every tier-local pin NAME glob matches a real file inside a real tier test root', () => {
    // The name globs are the second half of the two-part tier-local match; a
    // dead one silently drops a whole framing family from the pin list.
    const dead = TIER_LOCAL_PIN_NAME_GLOBS.filter((nameGlob) => {
      const re = globToRegExp(nameGlob);
      return !files.some(
        (f) => pinKindOf(f) === 'weak' && re.test(f.slice(f.lastIndexOf('/') + 1)),
      );
    });
    expect(dead, `dead tier-local pin name glob(s):\n  ${dead.join('\n  ')}`).toEqual([]);
  });

  it('every content-sensitive pin glob is also a byte-artifact pin glob', () => {
    for (const g of CONTENT_SENSITIVE_PIN_GLOBS) {
      expect(BYTE_ARTIFACT_PIN_GLOBS, `${g} must be declared as a pin first`).toContain(g);
    }
  });

  it('every declared not-yet-created pin glob really does not exist yet', () => {
    // Once Phase C/D lands these paths, the entry must be removed from the
    // not-yet-created list so the liveness check starts guarding them.
    const landed = PIN_GLOBS_NOT_YET_CREATED.filter((g) => {
      const re = globToRegExp(g);
      return files.some((f) => re.test(f));
    });
    expect(
      landed,
      'These pin globs now match a real file, so the "not yet created" waiver is stale ' +
        'and is hiding them from the dead-glob check. Fix: delete the listed entr(y|ies) ' +
        'from PIN_GLOBS_NOT_YET_CREATED in conformance/scripts/wire-format-pr-audit.ts.',
    ).toEqual([]);
  });

  it('covers the SDK state serializer of all seven tiers', () => {
    const stateRule = WIRE_FORMAT_RULES.find((r) => r.family === 'sdk-state-serialization');
    expect(stateRule).toBeDefined();
    const tierMarkers = [
      'packages/runar-sdk/',
      'packages/runar-go/',
      'packages/runar-rs/',
      'packages/runar-py/',
      'packages/runar-zig/',
      'packages/runar-rb/',
      'packages/runar-java/',
    ];
    for (const marker of tierMarkers) {
      expect(
        stateRule!.globs.some((g) => g.startsWith(marker)),
        `no state-serialization glob for tier ${marker}`,
      ).toBe(true);
    }
  });

  it('WIRE_FORMAT_GLOBS is the flattened view of WIRE_FORMAT_RULES', () => {
    expect([...WIRE_FORMAT_GLOBS].sort()).toEqual(
      WIRE_FORMAT_RULES.flatMap((r) => r.globs).sort(),
    );
  });

  it('no glob appears in both the wire list and the pin list', () => {
    const pinGlobs = [
      ...BYTE_ARTIFACT_PIN_GLOBS,
      ...WEAK_PIN_GLOBS,
      ...TIER_LOCAL_PIN_TEST_ROOT_GLOBS,
    ];
    const overlap = WIRE_FORMAT_GLOBS.filter((g) => pinGlobs.includes(g));
    expect(overlap).toEqual([]);
  });

  it('no wire glob matches a pin file (a pin can never satisfy and trip the gate at once)', () => {
    const pinFiles = files.filter((f) => pinKindOf(f) !== null);
    const collisions = pinFiles.filter((f) => matchesAnyGlob(f, WIRE_FORMAT_GLOBS));
    expect(collisions).toEqual([]);
  });

  it('P2-8: every wire anchor token still lives in its globbed file', () => {
    // Glob liveness proves the PATH exists. This proves the ENCODING LOGIC is
    // still in it. Extracting the encoder into a new file (leaving a re-export
    // shim) would otherwise pay the pin cost exactly once and leave every later
    // edit of the new file ungated.
    const missing: string[] = [];
    for (const anchor of WIRE_FORMAT_ANCHORS) {
      expect(
        matchesAnyGlob(anchor.path, WIRE_FORMAT_GLOBS),
        `anchor ${anchor.path} is not covered by any wire glob`,
      ).toBe(true);
      const abs = join(REPO_ROOT, anchor.path);
      if (!existsSync(abs)) {
        missing.push(`${anchor.path}: file is gone`);
        continue;
      }
      const body = readFileSync(abs, 'utf8');
      for (const token of anchor.tokens) {
        if (!body.includes(token)) missing.push(`${anchor.path}: lost token '${token}' (${anchor.why})`);
      }
    }
    expect(
      missing,
      'A globbed wire file no longer contains the byte token it was globbed FOR. ' +
        'The logic moved: glob the file it moved to and update WIRE_FORMAT_ANCHORS.\n  ' +
        missing.join('\n  '),
    ).toEqual([]);
  });
});

describe('wire-format-pr-audit — CLI', () => {
  /** Run the CLI in-process, capturing stdout+stderr and the exit code. */
  function cli(argv: string[]): { code: number; out: string } {
    const chunks: string[] = [];
    const log = console.log;
    const err = console.error;
    console.log = (...a: unknown[]) => void chunks.push(a.join(' '));
    console.error = (...a: unknown[]) => void chunks.push(a.join(' '));
    try {
      return { code: runCli(argv), out: chunks.join('\n') };
    } finally {
      console.log = log;
      console.error = err;
    }
  }

  function changedFile(paths: string[]): string {
    const root = mkdtempSync(join(tmpdir(), 'wire-audit-cli-'));
    const file = join(root, 'changed.txt');
    writeFileSync(file, `${paths.join('\n')}\n`);
    return file;
  }

  it('--changed-file reproducing #110 exits 1', () => {
    const file = changedFile(HISTORICAL_110_WIRE_PATHS);
    const { code, out } = cli(['--changed-file', file, '--root', REPO_ROOT]);
    expect(code).toBe(1);
    expect(out).toContain('MUST-MOVE-A-GOLDEN GATE FAILED');
  });

  it('--changed-file with the literal bd7ec284 changed set exits 1', () => {
    // The drill's exact invocation, end to end through the CLI. Before
    // 2026-08-06 this printed a ✓ plus a ⚠ and returned 0.
    const file = changedFile(BD7EC284_CHANGED_SET);
    const { code, out } = cli(['--changed-file', file, '--root', REPO_ROOT]);
    expect(code).toBe(1);
    expect(out).toContain('MUST-MOVE-A-GOLDEN GATE FAILED');
    expect(out).toContain('encode-push-data-minimaldata.test.ts');
  });

  it('--warn-only reports the same failure but exits 0', () => {
    const file = changedFile(HISTORICAL_110_WIRE_PATHS);
    const { code, out } = cli(['--changed-file', file, '--root', REPO_ROOT, '--warn-only']);
    expect(code).toBe(0);
    expect(out).toContain('MUST-MOVE-A-GOLDEN GATE FAILED');
    expect(out).toContain('--warn-only');
  });

  it('exits 0 once a pin moves', () => {
    const file = changedFile([
      ...HISTORICAL_110_WIRE_PATHS,
      'conformance/sdk-output/tests/stateful/expected-locking.hex',
    ]);
    expect(cli(['--changed-file', file, '--root', REPO_ROOT]).code).toBe(0);
  });

  it('tolerates the bare `--` that `pnpm run <script> -- --flag` forwards', () => {
    const file = changedFile(['docs/testing-guide.md']);
    expect(cli(['--', '--changed-file', file, '--root', REPO_ROOT]).code).toBe(0);
  });

  it('--json emits the machine-readable result', () => {
    const file = changedFile(HISTORICAL_110_WIRE_PATHS);
    const { code, out } = cli(['--changed-file', file, '--root', REPO_ROOT, '--json']);
    expect(code).toBe(1);
    const parsed = JSON.parse(out) as {
      ok: boolean;
      wireHits: string[];
      exceptionsUsed: { path: string }[];
    };
    expect(parsed.ok).toBe(false);
    // The TOTAL stays pinned at the full historical set. Some of those paths
    // may be covered by a live, content-pinned entry in
    // wire-format-exceptions.json (2026-08-28: `packages/runar-sdk/src/contract.ts`
    // is, for the issue-#106 warning-scoping change), and such a path is
    // reported under `exceptionsUsed` rather than `wireHits`. Asserting
    // hits + excepted == the historical set keeps this a real regression test
    // for the #110 incident: an exception can MOVE a path between the two
    // buckets, but it can never make one disappear. Lowering the expected
    // count to match whatever is excepted today would delete exactly the
    // property this test exists to hold.
    expect(parsed.wireHits.length + parsed.exceptionsUsed.length).toBe(
      HISTORICAL_110_WIRE_PATHS.length,
    );
    const accounted = [...parsed.wireHits, ...parsed.exceptionsUsed.map((e) => e.path)].sort();
    expect(accounted).toEqual([...HISTORICAL_110_WIRE_PATHS].sort());
  });
});

describe('wire-format-pr-audit — CLI over a real git repo', () => {
  /** Run the CLI in-process, capturing stdout+stderr and the exit code. */
  function cli(argv: string[]): { code: number; out: string } {
    const chunks: string[] = [];
    const log = console.log;
    const err = console.error;
    console.log = (...a: unknown[]) => void chunks.push(a.join(' '));
    console.error = (...a: unknown[]) => void chunks.push(a.join(' '));
    try {
      return { code: runCli(argv), out: chunks.join('\n') };
    } finally {
      console.log = log;
      console.error = err;
    }
  }

  interface Repo {
    root: string;
    git: (...args: string[]) => string;
    write: (rel: string, body: string) => void;
    commit: (msg: string) => string;
  }

  const roots: string[] = [];

  function repo(): Repo {
    const root = mkdtempSync(join(tmpdir(), 'wire-audit-repo-'));
    roots.push(root);
    const git = (...args: string[]) =>
      execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' }).trim();
    git('init', '-q', '-b', 'main');
    git('config', 'user.email', 'gate@example.invalid');
    git('config', 'user.name', 'gate');
    git('config', 'commit.gpgsign', 'false');
    return {
      root,
      git,
      write(rel, body) {
        const abs = join(root, rel);
        mkdirSync(dirname(abs), { recursive: true });
        writeFileSync(abs, body);
      },
      commit(msg) {
        git('add', '-A');
        git('commit', '-q', '--no-verify', '-m', msg);
        return git('rev-parse', 'HEAD');
      },
    };
  }

  afterAll(() => {
    for (const r of roots) rmSync(r, { recursive: true, force: true });
  });

  it('P0-3b: a note-only witness edit no longer launders a wire change (end to end)', () => {
    const r = repo();
    r.write('packages/runar-sdk/src/state.ts', 'export const width = 8;\n');
    r.write(WITNESS_REL, WITNESS_BEFORE);
    r.commit('base');

    r.write('packages/runar-sdk/src/state.ts', 'export const width = 9;\n');
    r.write(WITNESS_REL, WITNESS_NOTE_ONLY);
    r.commit('wire change + a prose touch');

    const { code, out } = cli(['--root', r.root, '--base', 'HEAD~1']);
    expect(code).toBe(1);
    expect(out).toContain('MUST-MOVE-A-GOLDEN GATE FAILED');
    expect(out).toContain(WITNESS_REL);
  });

  it('P0-3b: the same edit passes once the witness evidence moves', () => {
    const r = repo();
    r.write('packages/runar-sdk/src/state.ts', 'export const width = 8;\n');
    r.write(WITNESS_REL, WITNESS_BEFORE);
    r.commit('base');

    r.write('packages/runar-sdk/src/state.ts', 'export const width = 9;\n');
    r.write(WITNESS_REL, WITNESS_STATE_MOVED);
    r.commit('wire change + moved expectedState');

    expect(cli(['--root', r.root, '--base', 'HEAD~1']).code).toBe(0);
  });

  it('P2-7: DELETING a wire file is a wire change', () => {
    const r = repo();
    r.write('packages/runar-rb/lib/runar/sdk/state.rb', "module Runar; end\n");
    r.write('README.md', 'x\n');
    r.commit('base');

    rmSync(join(r.root, 'packages/runar-rb/lib/runar/sdk/state.rb'));
    r.commit('drop the Ruby state serializer');

    const { code, out } = cli(['--root', r.root, '--base', 'HEAD~1']);
    expect(code).toBe(1);
    expect(out).toContain('packages/runar-rb/lib/runar/sdk/state.rb');
  });

  it('P1-5: the base is the merge-base resolved at run time, not a stale base tip', () => {
    // Reproduce the CI shape: HEAD is a PR merge ref (feature merged with the
    // CURRENT base tip), while `github.event.pull_request.base.sha` still names
    // the base tip from the last sync. Diffing from the stale sha drags in the
    // goldens another PR merged in between — and one of THOSE satisfies the
    // gate for a PR that moved nothing.
    const r = repo();
    r.write('packages/runar-sdk/src/state.ts', 'export const width = 8;\n');
    const staleBase = r.commit('base');

    r.git('checkout', '-q', '-b', 'feature');
    r.write('packages/runar-sdk/src/state.ts', 'export const width = 9;\n');
    r.commit('this PR: wire change, no pin moved');

    r.git('checkout', '-q', 'main');
    r.write('conformance/sdk-output/tests/arithmetic/expected-locking.hex', '52935387\n');
    r.commit('ANOTHER PR: regenerate a cross-SDK golden');

    r.git('checkout', '-q', 'feature');
    r.git('merge', '-q', '--no-edit', 'main');

    // Stale base.sha: the other PR's golden is inside the range ⇒ false green.
    expect(cli(['--root', r.root, '--base', staleBase]).code).toBe(0);
    // Resolved at run time against the base BRANCH ⇒ only this PR's changes.
    const { code, out } = cli(['--root', r.root, '--base', 'main']);
    expect(code).toBe(1);
    expect(out).toContain('packages/runar-sdk/src/state.ts');
    expect(out).not.toContain('expected-locking.hex');
  });
});

describe('wire-format-pr-audit — exceptions file loader', () => {
  function withTempRoot(write: (root: string) => void): string {
    const root = mkdtempSync(join(tmpdir(), 'wire-audit-'));
    mkdirSync(join(root, dirname(EXCEPTIONS_REL)), { recursive: true });
    write(root);
    return root;
  }

  it('returns no exceptions when the file is absent', () => {
    const root = mkdtempSync(join(tmpdir(), 'wire-audit-'));
    try {
      expect(loadExceptions(root)).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('reads entries from conformance/wire-format-exceptions.json', () => {
    const root = withTempRoot((r) => {
      writeFileSync(
        join(r, EXCEPTIONS_REL),
        JSON.stringify({
          entries: [
            {
              path: 'packages/runar-sdk/src/state.ts',
              reason: 'comment-only touch; no byte change over the state value-class matrix',
              date: '2026-08-05',
            },
          ],
        }),
      );
    });
    try {
      const entries = loadExceptions(root);
      expect(entries).toHaveLength(1);
      expect(entries[0]?.path).toBe('packages/runar-sdk/src/state.ts');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('throws on malformed JSON rather than silently returning an empty list', () => {
    const root = withTempRoot((r) => writeFileSync(join(r, EXCEPTIONS_REL), '{ not json'));
    try {
      expect(() => loadExceptions(root)).toThrow(/wire-format-exceptions\.json/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('every checked-in exception still matches its file — a DEAD entry is deleted, never left to rot', () => {
    // N-069. An entry is content-pinned to the sha256 of the file version it
    // was reviewed against, so the moment that file is edited again the entry
    // stops suppressing anything and the gate prints it as REJECTED. That
    // fail-closed behaviour is correct and is covered elsewhere; what is NOT
    // covered is what happens NEXT. A dead entry has no effect on the gate's
    // verdict, so nothing makes anyone remove it, and it sits in the file
    // being printed as REJECTED on every single run. The one signal the escape
    // hatch has — "look at this, it did not apply" — then fires on every run
    // for reasons nobody needs to act on, and reviewers learn to scroll past
    // the block that exists to be read.
    //
    // So: an exception is authorised for exactly one version of one file. Once
    // that version is gone the entry is spent. If the NEW version still needs
    // cover it gets a fresh, freshly-reviewed, freshly-dated entry; if it does
    // not (the usual case — it moved a golden like everything else), the entry
    // is deleted. Either way a stale sha256 is never the resting state.
    const entries = loadExceptions(REPO_ROOT);
    const dead = entries
      .filter((e) => existsSync(join(REPO_ROOT, e.path)))
      .map((e) => ({
        path: e.path,
        pinned: e.sha256,
        actual: createHash('sha256')
          .update(readFileSync(join(REPO_ROOT, e.path)))
          .digest('hex'),
      }))
      .filter((r) => r.pinned !== r.actual);

    expect(
      dead,
      'these exception entries are pinned to a file version that no longer exists — ' +
        'they suppress nothing and must be removed (or re-reviewed and re-pinned)',
    ).toEqual([]);
  });

  it('the checked-in exceptions file holds exactly the reviewed entries (P1-4: an exception is never routine)', () => {
    // The whole point of the gate is that a wire change moves bytes. Every
    // entry here is a wire change that shipped with NO byte evidence, so the
    // count is part of the gate's own audit trail: adding one must be a
    // deliberate, reviewed edit to THIS assertion, not a quiet JSON append.
    //
    // 2026-08-28 — three entries, one per SDK tier, covered the issue-#106
    // warning-scoping change on `contract.{ts,rs,py}` (PR #147): a read-only
    // OR-CHECKSIG probe feeding an INFORMATIONAL warn() call, in files listed
    // under constructor-slot-splicing.
    //
    // 2026-09-11 (N-069) — all three DELETED, spent. Each was pinned to the
    // sha256 of the file version it was reviewed against, and all three files
    // have since been edited by changes in the same warn-only family
    // (21fa4cbd, 0f81289a, 1805e635) plus one error-propagation fix (493cf3ce,
    // `)` -> `)?`). Every content pin therefore mismatched and the gate had
    // been printing all three as REJECTED on every run, suppressing nothing.
    // The changes that invalidated them did not need cover: replayed against
    // this branch the gate passes on 62 moved pins with the exceptions NOT
    // applied. An entry authorises exactly one version of one file; when that
    // version is gone the entry is spent and is deleted rather than
    // re-stamped. See the `DEAD entry` test above, which now keeps it that
    // way.
    const entries = loadExceptions(REPO_ROOT);
    expect(entries.map((e) => e.path).sort()).toEqual([]);
    // Pin the shape too: an entry that loses its expiry or sign-off is not an
    // exception, it is a permanent hole.
    for (const e of entries) {
      expect(e.expires).toBe('2026-11-26');
      expect(e.reviewer).toBe('gh:icellan');
      expect(e.sha256).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it('the checked-in exceptions file (if present) is well formed', () => {
    // Loading it must not throw, and every entry must pass validation — an
    // unreadable or malformed escape hatch is a gate outage.
    const entries = loadExceptions(REPO_ROOT);
    const res = auditChangedPaths([], { exceptions: entries });
    expect(res.problems).toEqual([]);
  });
});

describe('wire-format-pr-audit — CI wiring (P0-4: the audit must run on the path the incident took)', () => {
  const ci = readFileSync(join(REPO_ROOT, '.github/workflows/ci.yml'), 'utf8');

  /** The `wire-format-must-move-golden:` job block, up to the next job key. */
  function jobBlock(): string {
    const start = ci.indexOf('\n  wire-format-must-move-golden:');
    expect(start, 'job wire-format-must-move-golden not found in ci.yml').toBeGreaterThan(-1);
    const rest = ci.slice(start + 1);
    const next = rest.slice(1).search(/\n {2}[a-z][a-z0-9-]*:\n/);
    return next === -1 ? rest : rest.slice(0, next + 1);
  }

  it('the audit step is NOT gated on pull_request only', () => {
    // bd7ec284 — the commit this whole gate exists for — is on origin/main's
    // FIRST-PARENT chain: pushed directly, never a PR. Only 5 of the last 100
    // commits reachable from main are PR merges; the most recent 25 contain
    // none. A gate that only runs on `pull_request` would not have seen it.
    expect(jobBlock()).not.toMatch(/if:\s*github\.event_name\s*==\s*'pull_request'/);
  });

  it('the workflow also runs on merge_group (a queued merge is the last chance to block)', () => {
    const onBlock = ci.slice(0, ci.indexOf('\njobs:'));
    expect(onBlock).toMatch(/^ {2}merge_group:/m);
  });

  it('the PR base is a REF resolved at run time, never the stale base.sha (P1-5)', () => {
    // `github.event.pull_request.base.sha` is the base tip at the last sync,
    // while the checkout resolves refs/pull/N/merge against the CURRENT base —
    // so `base.sha...HEAD` drags in every golden other PRs merged in between,
    // and one of THOSE satisfies this gate. Resolve `origin/<base.ref>` instead.
    // Assert on the WIRING (the `${{ }}` interpolations), not on the prose —
    // the comment above the step is allowed to name the SHA it rejects.
    const wiring = jobBlock()
      .split('\n')
      .filter((l) => !/^\s*#/.test(l))
      .join('\n');
    expect(wiring).not.toContain('${{ github.event.pull_request.base.sha }}');
    expect(wiring).toContain('${{ github.event.pull_request.base.ref }}');
  });
});
