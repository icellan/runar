/**
 * R-082 — a non-default `@sighash` mode must survive into a nested context.
 *
 * `LoweringContext.subContext()` builds every `if` arm, `for` body and ternary
 * arm in a FRESH context, so each field is a hand-plumbing decision. One was
 * never plumbed: `sighashFlag`. A manual `checkPreimage(pre)` written inside a
 * branch arm therefore lowered with `sighashFlag: undefined` — the default
 * ALL|FORKID — while the same call at statement level lowered with the
 * method's declared mode.
 *
 * This is NOT cosmetic metadata. `05-stack-lower.ts::lowerCheckPreimage` feeds
 * `value.sighashFlag` straight into `emitCheckPreimageBindingRaw`, which
 * appends the flag byte to the OP_PUSH_TX binding blob. So the compiler
 * produced a SELF-INCONSISTENT artifact from a single run:
 *
 *     abi.methods[].sigHashType : 0x43   (SINGLE|FORKID — read by the SDK)
 *     locking script push       : 0x41   (ALL|FORKID   — enforced on-chain)
 *
 * The SDK signs the preimage under the mode the ABI declares; the script
 * derives its sighash under the mode the blob pins. They disagree, so
 * OP_CHECKSIGVERIFY aborts and the branch is unspendable. That makes this
 * funds-relevant, and the check below (case "artifact is self-consistent")
 * is an oracle that consults no reference tier: one compiler run must not
 * contradict itself.
 *
 * Measured on the pre-fix HEAD with `--disable-constant-folding`, on the
 * `then` probe:
 *
 *     ANF check_preimage.sighashFlag    go 67 · ts ABSENT
 *     script flag byte                  go 0x43 · ts 0x41
 *     byte 796 of the hex               go '6' · ts '1'   (the only difference)
 *
 * Same family as R-010 (`scriptLevelCodeSeparator`), #130 (`renamedParams`),
 * N-051 (`privateMethods`), R-072 (the three `MethodScope` fields) and N-079
 * (`paramAliasStack`) — the sixth field of this same sub-context missed one at
 * a time.
 *
 * Go already carried it (`anf_lower.go`, `subContext`: "#123: nested manual
 * checkPreimage inherits the method's mode"), so the (byteLength, sha256-of-hex)
 * table below is the REFERENCE-TIER output, captured from the checked-in
 * `compilers/go` binary. TS is pinned to it.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'crypto';
import { compile } from '../index.js';
import type { ANFValue } from '../ir/index.js';

const SIGHASH_SINGLE_FORKID = 0x43; // 67
const SIGHASH_ALL_FORKID = 0x41; // 65

/** Push of a 1-byte sighash flag, as it appears inside the binding blob. */
const PUSH_SINGLE_FORKID = '01437e';
const PUSH_ALL_FORKID = '01417e';

function contract(directive: string, body: string): string {
  return `class Manual extends SmartContract {
  readonly n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  ${directive}
  public go(pre: ByteString, f: bigint): void {
${body}
  }
}
`;
}

const SINGLE = '/** @sighash SINGLE|FORKID */';

/**
 * Every probe places exactly ONE manual `checkPreimage(pre)`. `stmt` is the
 * control (statement level — already correct before the fix); the rest place
 * it one or more `subContext()` frames deep.
 */
const BODIES: Record<string, string> = {
  stmt: `    assert(checkPreimage(pre));
    assert(f > 0n);`,
  then: `    if (f > 0n) {
      assert(checkPreimage(pre));
    } else {
      assert(f == 0n);
    }`,
  else: `    if (f > 0n) {
      assert(f > 0n);
    } else {
      assert(checkPreimage(pre));
    }`,
  nested: `    if (f > 0n) {
      if (f > 1n) {
        assert(checkPreimage(pre));
      } else {
        assert(f == 1n);
      }
    } else {
      assert(f == 0n);
    }`,
  loop: `    for (let i = 0n; i < 1n; i++) {
      assert(checkPreimage(pre));
    }
    assert(f > 0n);`,
};

/**
 * Seven-tier agreed output, captured from the Go reference compiler
 * (`compilers/go/runar-go --hex --disable-constant-folding`). Pre-fix, TS
 * matched only `stmt` and `dflt`.
 */
const GO_REFERENCE: Record<string, { bytes: number; sha256: string }> = {
  stmt: { bytes: 427, sha256: '536886b124e54533890929da2a44749a95c3bab0b7439a7920e856c3e684c93e' },
  then: { bytes: 433, sha256: '1219ca9f72bdf7c538f2372aa15ac26bc9f834a6e2e509a7c1166027ea15ad65' },
  else: { bytes: 434, sha256: '7cbf4663acc2d0065cfaf2fc43d49ddbb1538042ad2ffb89ecc46767d4768702' },
  nested: { bytes: 442, sha256: '8e5a9c553cd1a1340b8ed56b04b848ae84a5fd2a7ce0f8a7ef18ee2dbdbe9f93' },
  loop: { bytes: 429, sha256: '3827e6af85b3de666feb510d353c81139efdbe4270c715e3ab6aa41f56d466ff' },
  // Default mode in a then-arm: the fix must NOT start stamping a flag here.
  dflt: { bytes: 433, sha256: 'f03dd0af40bb1a8f59b766f72cd53a16313af726439b186a07b02bcbb6019f2a' },
};

interface Compiled {
  script: string;
  /** `sighashFlag` of every `check_preimage` node, in emission order. */
  anfFlags: (number | undefined)[];
  abiSigHashType: number | undefined;
}

function compileProbe(src: string): Compiled {
  const r = compile(src, { fileName: 'Manual.runar.ts', disableConstantFolding: true });
  const errs = (r.diagnostics ?? []).filter((d) => d.severity === 'error');
  expect(errs).toEqual([]);
  const anfFlags: (number | undefined)[] = [];
  const walk = (v: unknown): void => {
    if (Array.isArray(v)) {
      for (const x of v) walk(x);
      return;
    }
    if (v && typeof v === 'object') {
      const o = v as Record<string, unknown>;
      if (o.kind === 'check_preimage') anfFlags.push((o as unknown as ANFValue & { sighashFlag?: number }).sighashFlag);
      for (const x of Object.values(o)) walk(x);
    }
  };
  walk(r.anf);
  const method = r.artifact!.abi.methods.find((m) => m.name === 'go');
  return {
    script: r.artifact!.script,
    anfFlags,
    abiSigHashType: (method as unknown as { sigHashType?: number } | undefined)?.sigHashType,
  };
}

function sha256Hex(hex: string): string {
  return createHash('sha256').update(hex, 'utf8').digest('hex');
}

describe('R-082 — @sighash mode survives into nested lowering contexts', () => {
  describe.each(Object.keys(BODIES))('manual checkPreimage in position "%s"', (pos) => {
    const src = contract(SINGLE, BODIES[pos]!);

    it('the ANF check_preimage node carries the declared mode', () => {
      expect(compileProbe(src).anfFlags).toEqual([SIGHASH_SINGLE_FORKID]);
    });

    it('the OP_PUSH_TX binding blob pins the declared flag byte', () => {
      const script = compileProbe(src).script;
      expect(script.includes(PUSH_SINGLE_FORKID)).toBe(true);
      expect(script.includes(PUSH_ALL_FORKID)).toBe(false);
    });

    it('the artifact is self-consistent: ABI sigHashType == the byte the script enforces', () => {
      // Reference-tier-free oracle. The SDK builds the preimage from
      // abi.sigHashType; the script derives its sighash from the pushed flag.
      // If these ever disagree the covenant cannot be satisfied.
      const c = compileProbe(src);
      expect(c.abiSigHashType).toBe(SIGHASH_SINGLE_FORKID);
      const enforced = c.script.includes(PUSH_SINGLE_FORKID) ? SIGHASH_SINGLE_FORKID : SIGHASH_ALL_FORKID;
      expect(enforced).toBe(c.abiSigHashType);
    });

    it('matches the Go reference tier byte for byte', () => {
      const script = compileProbe(src).script;
      expect({ bytes: script.length / 2, sha256: sha256Hex(script) }).toEqual(GO_REFERENCE[pos]);
    });
  });

  // Over-copy guard: carrying the field must not start stamping a flag on
  // methods that never declared one. `sighashFlag` stays `undefined` for the
  // default mode by construction, and the pinned default hex proves it.
  it('a DEFAULT-mode method in a branch arm is untouched', () => {
    const c = compileProbe(contract('', BODIES.then!));
    expect(c.anfFlags).toEqual([undefined]);
    expect(c.abiSigHashType).toBeUndefined();
    expect(c.script.includes(PUSH_ALL_FORKID)).toBe(true);
    expect({ bytes: c.script.length / 2, sha256: sha256Hex(c.script) }).toEqual(GO_REFERENCE.dflt);
  });
});
