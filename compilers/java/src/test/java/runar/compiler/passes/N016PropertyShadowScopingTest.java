package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * N-016 — a local that shares a contract property's name must never capture a
 * later {@code this.<prop>} read or write (user decision R8: correct scoping).
 * Port of {@code packages/runar-compiler/src/__tests__/n016-property-shadow-scoping.test.ts}.
 *
 * <p>{@code const target = n + 1n; assert(target == this.target);} compiled to
 * {@code 8b769c} (OP_1ADD OP_DUP OP_NUMEQUAL): the property read resolved by
 * name to the local's stack slot, an always-true self-comparison.
 *
 * <p>Oracle: alpha-equivalence, from the source language rather than compiler
 * output. Renaming a local / private-helper param / public param to a fresh
 * name cannot change the program's meaning, so each template compiled with
 * {@code $L} = the property's name must produce exactly the bytes of
 * {@code $L} = {@code lcl}, in both constant-folding modes.
 *
 * <p>Proves: in the Java tier, property-named locals (top level, if-arm, nested
 * block, loop variable, ++, byte-typed, inside a private helper), a private
 * helper's param and a public param never capture {@code this.<prop>}; stateful
 * property reads/writes and the continuation are unaffected by a same-named
 * local, including an if whose arms rebind the local and write the property.
 * Does NOT prove: on-chain behaviour (see
 * {@code packages/runar-testing/src/__tests__/n016-property-shadow-spend.test.ts})
 * or local-vs-compiler-temp collisions (a local literally named {@code t3}).
 */
class N016PropertyShadowScopingTest {

    private record Shape(String name, String prop, String template) {}

    private static String stateless(String body, String propType) {
        return "import { SmartContract, assert, cat, ByteString } from 'runar-lang';\n\n"
            + "class Shadow extends SmartContract {\n"
            + "  readonly target: " + propType + ";\n"
            + "  constructor(target: " + propType + ") {\n"
            + "    super(target);\n"
            + "    this.target = target;\n"
            + "  }\n\n"
            + body + "\n}\n";
    }

    private static String stateful(String body) {
        return "import { StatefulSmartContract, assert } from 'runar-lang';\n\n"
            + "class Shadow extends StatefulSmartContract {\n"
            + "  count: bigint;\n\n"
            + "  constructor(count: bigint) {\n"
            + "    super(count);\n"
            + "    this.count = count;\n"
            + "  }\n\n"
            + body + "\n}\n";
    }

    private static final List<Shape> SHAPES = List.of(
        new Shape("local at method top level", "target", stateless("""
  public unlock(n: bigint) {
    const $L = n + 1n;
    assert($L == this.target);
  }
""", "bigint")),
        new Shape("local inside an if-arm", "target", stateless("""
  public unlock(n: bigint) {
    if (n > 0n) {
      const $L = n + 1n;
      assert($L == this.target);
    } else {
      assert(n == this.target);
    }
  }
""", "bigint")),
        new Shape("local inside a nested block", "target", stateless("""
  public unlock(n: bigint) {
    if (n > 0n) {
      if (n > 1n) {
        const $L = n + 1n;
        assert($L == this.target);
      } else {
        assert(n + 2n == this.target);
      }
    } else {
      assert(false);
    }
  }
""", "bigint")),
        new Shape("loop variable", "target", stateless("""
  public unlock(n: bigint) {
    let acc = 0n;
    for (let $L = 0n; $L < 2n; $L++) {
      acc = acc + this.target - $L;
    }
    assert(acc == n);
  }
""", "bigint")),
        new Shape("local mutated with ++", "target", stateless("""
  public unlock(n: bigint) {
    let $L = n;
    $L++;
    assert($L == this.target);
  }
""", "bigint")),
        new Shape("byte-typed local", "target", stateless("""
  public unlock(a: ByteString) {
    const $L = cat(a, a);
    assert($L == this.target);
  }
""", "ByteString")),
        new Shape("local inside a private helper", "target", stateless("""
  private chk(n: bigint): boolean {
    const $L = n + 1n;
    return $L == this.target;
  }

  public unlock(n: bigint) {
    assert(this.chk(n));
  }
""", "bigint")),
        new Shape("private helper parameter", "target", stateless("""
  private chk($L: bigint): boolean {
    return this.target == $L + 1n;
  }

  public unlock(n: bigint) {
    assert(this.chk(n));
  }
""", "bigint")),
        new Shape("public parameter, property read first", "target", stateless("""
  public unlock($L: bigint) {
    assert(this.target == $L + 1n);
  }
""", "bigint")),
        new Shape("stateful: local, then property read + write", "count", stateful("""
  public bump(n: bigint) {
    const $L = n * 2n;
    this.count = this.count + $L;
    assert($L > 0n);
  }
""")),
        new Shape("stateful: local live across a property write", "count", stateful("""
  public bump(n: bigint) {
    let $L = n;
    this.count = this.count + 1n;
    assert(this.count > $L);
  }
""")),
        new Shape("stateful: if-arms rebind the local and write the property", "count", stateful("""
  public bump(n: bigint) {
    let $L = n;
    if (n > 3n) {
      $L = $L + 1n;
      this.count = this.count + $L;
    } else {
      this.count = this.count + 1n;
    }
  }
""")),
        new Shape("stateful: an if-arm writes the property, then rebinds the local read after the if", "count", stateful("""
  public bump(n: bigint) {
    let $L = n;
    if (n > 3n) {
      this.count = this.count + $L;
      $L = $L + 1n;
    } else {
      this.count = this.count + 1n;
    }
    assert($L > 0n);
  }
"""))
    );

    @Test
    void probeNoLongerSelfCompares() throws Exception {
        String src = SHAPES.get(0).template().replace("$L", "target");
        assertEquals("8b009c", PipelineTestSupport.hex(src, "Shadow.runar.ts", true));
    }

    @Test
    void shadowingCompilesLikeRenamedSpelling() throws Exception {
        List<String> failures = new ArrayList<>();
        for (Shape s : SHAPES) {
            for (boolean disable : new boolean[] {true, false}) {
                String shadow;
                try {
                    shadow = PipelineTestSupport.hex(s.template().replace("$L", s.prop()), "Shadow.runar.ts", disable);
                } catch (Exception e) {
                    failures.add(s.name() + " (disableFold=" + disable + "): shadowing spelling failed: " + e.getMessage());
                    continue;
                }
                String control = PipelineTestSupport.hex(s.template().replace("$L", "lcl"), "Shadow.runar.ts", disable);
                if (!shadow.equals(control)) {
                    failures.add(s.name() + " (disableFold=" + disable + "): shadowing " + shadow + " != renamed " + control);
                }
            }
        }
        assertTrue(failures.isEmpty(), String.join("\n", failures));
    }
}
