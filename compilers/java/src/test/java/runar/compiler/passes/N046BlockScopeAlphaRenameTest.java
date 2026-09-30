package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * N-046 (ScopeSnatcher) + N-047 (ShadowGoblin) — a block-scoped declaration,
 * or a local of an inlined private helper, that reuses a name already bound in
 * an enclosing scope gets its own ANF identity (user decision R24:
 * alpha-rename, {@code <name>@<n>}). Port of
 * packages/runar-compiler/src/__tests__/n046-block-scope-alpha-rename.test.ts.
 *
 * <p>{@code let authorized = checkSig(sig, this.owner); if (trigger) { let
 * authorized = true; } assert(authorized);} bound the inner {@code let} as
 * {@code authorized}, the if-arm reconciliation took it for a reassignment of
 * the outer local, and any signature unlocked the coins. An inlined
 * output-emitting helper's local overwrote the caller's the same way.
 *
 * <p>Oracle: alpha-equivalence, from the source language rather than compiler
 * output. Renaming the inner declaration cannot change the program's meaning,
 * so each template compiled with {@code $L} = the outer name must produce
 * exactly the bytes of {@code $L} = {@code fresh}, in both constant-folding
 * modes.
 *
 * <p>Proves: in the Java tier, an inner {@code let} in a no-else if-arm, in
 * both arms of an if/else, in a nested if (reassigned there), in a loop body,
 * a loop variable reusing an outer local, an inner {@code let} reusing a
 * parameter, and an inlined helper local reusing a caller local or parameter
 * all compile like their renamed spellings. Does NOT prove: on-chain behaviour
 * or cross-tier ANF naming (both in
 * packages/runar-testing/src/__tests__/n046-block-scope-spend.test.ts).
 */
class N046BlockScopeAlphaRenameTest {

    private record Shape(String name, String outer, String template) {}

    private static String vault(String body) {
        return "\nimport { SmartContract, assert, checkSig } from 'runar-lang';\n"
            + "import type { PubKey, Sig } from 'runar-lang';\n\n"
            + "class ShadowVault extends SmartContract {\n"
            + "  readonly owner: PubKey;\n\n"
            + "  constructor(owner: PubKey) {\n"
            + "    super(owner);\n"
            + "    this.owner = owner;\n"
            + "  }\n\n"
            + body
            + "}\n";
    }

    private static String payout(String body) {
        return "\nimport { StatefulSmartContract, ByteString, PubKey, Sig, assert, checkSig, len } from 'runar-lang';\n\n"
            + "class OwnerPayout extends StatefulSmartContract {\n"
            + "  nonce: bigint;\n"
            + "  readonly owner: PubKey;\n\n"
            + "  constructor(nonce: bigint, owner: PubKey) {\n"
            + "    super(nonce, owner);\n"
            + "    this.nonce = nonce;\n"
            + "    this.owner = owner;\n"
            + "  }\n\n"
            + body
            + "}\n";
    }

    private static final List<Shape> SHAPES = List.of(
        new Shape("ScopeSnatcher: inner let in a no-else if-arm", "authorized", vault("""
  public spend(sig: Sig, trigger: boolean) {
    let authorized = checkSig(sig, this.owner);
    if (trigger) {
      let $L = true;
    }
    assert(authorized);
  }
""")),
        new Shape("ScopeSnatcher: inner const in both arms of an if/else", "ok", vault("""
  public spend(sig: Sig, x: bigint) {
    let ok = checkSig(sig, this.owner);
    if (x > 0n) {
      const $L = true;
      assert($L);
    } else {
      const $L = x < 0n;
      assert(!$L);
    }
    assert(ok);
  }
""")),
        new Shape("inner let in a nested if, read and reassigned inside its scope", "ok", vault("""
  public spend(sig: Sig, x: bigint) {
    let ok = checkSig(sig, this.owner);
    if (x > 0n) {
      if (x > 1n) {
        let $L = x > 5n;
        $L = !$L;
        assert($L || x == 7n);
      }
    }
    assert(ok);
  }
""")),
        new Shape("inner let in a loop body", "ok", vault("""
  public spend(sig: Sig, x: bigint) {
    let ok = checkSig(sig, this.owner);
    for (let i = 0n; i < 2n; i++) {
      let $L = x > i;
      assert($L);
    }
    assert(ok);
  }
""")),
        new Shape("loop variable reusing an outer local name", "i", vault("""
  public spend(sig: Sig, x: bigint) {
    let i = x;
    let acc = 0n;
    for (let $L = 0n; $L < 3n; $L++) {
      acc = acc + $L;
    }
    assert(i == acc);
    assert(checkSig(sig, this.owner));
  }
""")),
        new Shape("inner let reusing a parameter name", "x", vault("""
  public spend(sig: Sig, x: bigint) {
    if (x > 0n) {
      let $L = 5n;
      assert($L == 5n);
    }
    assert(x == 7n);
    assert(checkSig(sig, this.owner));
  }
""")),
        new Shape("ShadowGoblin: inlined helper local reusing a caller local name", "valid", payout("""
  public withdraw(sig: Sig, destination: ByteString) {
    const valid = checkSig(sig, this.owner);
    this.pay(destination);
    assert(valid);
  }

  private pay(destination: ByteString) {
    const $L = len(destination) > 0n;
    assert($L);
    this.addRawOutput(50000n, destination);
  }
""")),
        new Shape("inlined helper local reusing a caller parameter name", "sig", payout("""
  public withdraw(sig: Sig, destination: ByteString) {
    this.pay(destination);
    assert(checkSig(sig, this.owner));
  }

  private pay(destination: ByteString) {
    const $L = len(destination);
    assert($L > 0n);
    this.addRawOutput(50000n, destination);
  }
"""))
    );

    @Test
    void shadowingDeclarationCompilesLikeRenamedSpelling() throws Exception {
        List<String> failures = new ArrayList<>();
        for (Shape s : SHAPES) {
            for (boolean disable : new boolean[] {true, false}) {
                String shadow;
                try {
                    shadow = PipelineTestSupport.hex(s.template().replace("$L", s.outer()), "Shadow.runar.ts", disable);
                } catch (Exception e) {
                    failures.add(s.name() + " (disableFold=" + disable + "): shadowing spelling failed: " + e.getMessage());
                    continue;
                }
                String control = PipelineTestSupport.hex(s.template().replace("$L", "fresh"), "Shadow.runar.ts", disable);
                if (!shadow.equals(control)) {
                    failures.add(s.name() + " (disableFold=" + disable + "): shadowing " + shadow + " != renamed " + control);
                }
            }
        }
        assertTrue(failures.isEmpty(), String.join("\n", failures));
    }
}
