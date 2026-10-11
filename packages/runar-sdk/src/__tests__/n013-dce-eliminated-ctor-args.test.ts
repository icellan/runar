/**
 * N-013 / R84 — a constructor arg for a readonly property that the compiler's
 * DCE eliminates entirely (no method ever reads it) has no `constructorSlots`
 * entry at all once EVERY ctor-needed property is eliminated. `buildCodeScript`
 * used to treat that shape ("no constructorSlots on the artifact") as the
 * pre-slot legacy format and fall back to *appending* the raw constructor args
 * to the end of the compiled script — even though the modern compiler's
 * template has no placeholder expecting them. The deployed locking script was
 * therefore not the one the compiler produced, and a spend against it failed
 * the consensus clean-stack rule.
 *
 * R84 fixed this by dropping the fallback (matching the Java SDK, which never
 * had it): an arg with no constructor slot is simply never spliced or
 * appended anywhere, so the deployed script always equals the compiled
 * template.
 *
 * This test proves the fix against the real `@bsv/sdk` `Spend` oracle (the
 * acceptance oracle this remediation suite requires for any on-chain claim):
 * the compiled template validates on its own, and so does the SDK-deployed
 * script, because they are now byte-identical.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { LockingScript, UnlockingScript, Spend } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';

// Both `a` and `b` are readonly ctor-initialised properties that no method
// ever reads, so DCE eliminates both and the compiler emits no placeholder
// for either — `artifact.constructorSlots` ends up undefined, not `[]`.
const SRC = `
import { SmartContract, assert, ByteString } from 'runar-lang';

class Unused extends SmartContract {
  readonly a: ByteString;
  readonly b: ByteString;

  constructor(a: ByteString, b: ByteString) {
    super(a, b);
    this.a = a;
    this.b = b;
  }

  public unlock() {
    assert(true);
  }
}
`;

function compileArtifact(): RunarArtifact {
  const result = compile(SRC, { fileName: 'Unused.runar.ts' });
  if (!result.artifact) {
    const errs = result.diagnostics.filter(d => d.severity === 'error').map(d => d.message);
    throw new Error(`Compile failed: ${errs.join('; ')}`);
  }
  return result.artifact;
}

/** A minimal single-input strict (version-1) Spend with no funding inputs or
 *  outputs to worry about -- `unlock()` takes no params, so the unlocking
 *  script is empty and the whole surface under test is the locking script. */
function validate(lockingScriptHex: string): boolean {
  const spend = new Spend({
    sourceTXID: '00'.repeat(32),
    sourceOutputIndex: 0,
    sourceSatoshis: 1000,
    lockingScript: LockingScript.fromHex(lockingScriptHex),
    transactionVersion: 1,
    otherInputs: [],
    outputs: [],
    unlockingScript: UnlockingScript.fromHex(''),
    inputSequence: 0xffffffff,
    inputIndex: 0,
    lockTime: 0,
  });
  return spend.validate();
}

describe('N-013 — DCE-eliminated readonly ctor properties (stateless, all slots gone)', () => {
  it('both ctor params are dropped by DCE: no constructorSlots on the artifact', () => {
    const artifact = compileArtifact();
    expect(artifact.constructorSlots).toBeUndefined();
    // Compiled template is just the trivially-true body: no placeholder for
    // either eliminated property.
    expect(artifact.script).toBe('51');
  });

  it('the compiled template alone validates against the Spend oracle', () => {
    const artifact = compileArtifact();
    expect(validate(artifact.script)).toBe(true);
  });

  it('R84: the SDK-deployed script equals the compiled template', () => {
    const artifact = compileArtifact();
    const contract = new RunarContract(artifact, ['cafe', 'babe']);
    const deployed = contract.getLockingScript();

    // Fund-safety assertion: neither `a` nor `b` has a constructor slot
    // (both were eliminated), so NOTHING is spliced or appended -- the
    // deployed script is the compiled one. Before R84 the SDK appended the
    // two dropped args as raw pushdata instead.
    expect(deployed).toBe(artifact.script);
  });

  it('R84: consequently, the deployed script validates against the Spend ' +
     'oracle (clean-stack) exactly as the compiled template alone does', () => {
    const artifact = compileArtifact();
    const contract = new RunarContract(artifact, ['cafe', 'babe']);
    const deployed = contract.getLockingScript();

    // Before R84, the corrupted deploy left 3 stack items (OP_1's `01`,
    // then the two appended pushes) instead of 1, throwing a clean-stack
    // ScriptEvaluationError -- the exact failure the N-013 brief predicted
    // ("spends fail clean-stack"). Now `deployed === artifact.script`, so
    // both validate identically.
    expect(validate(artifact.script)).toBe(true);
    expect(validate(deployed)).toBe(true);
  });
});
