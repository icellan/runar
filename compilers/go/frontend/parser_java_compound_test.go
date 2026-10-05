package frontend

import (
	"strings"
	"testing"
)

// N-134: the .runar.java parser accepts exactly TS's ten compound assignment
// operators (+ - * / % & | ^ << >>) as an expression statement and lowers
// `t op= e` to `t = t op e`, as TS finishExpressionStatement does. Before
// N-134 it knew only the arithmetic five, so `<<= >>= &= |= ^=` were parse
// errors in Go while TS and Java compiled them.
//
// Proves: each of the ten operators, on a local, a bigint property and a
// ByteString property, parses to AssignmentStmt{t, BinaryExpr{op, t, e}}, and
// the five new ones also do so in a for-header update slot (where the loop
// rule, not the parser, refuses them).
// Does not prove: byte parity with the other tiers (conformance/negatives/
// java-compound-assign-parity.test.ts pins that), or the N-023 bare-property
// refusal for the new operators (also pinned there, and by the generic
// AssignmentStmt walk in parser_java_bare_assign_test.go).

const javaCompoundSrc = `
package p;
import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import static runar.lang.Builtins.assertThat;

class Compound extends StatefulSmartContract {
    Bigint count;
    ByteString tag;

    Compound(Bigint count, ByteString tag) {
        super(count, tag);
        this.count = count;
        this.tag = tag;
    }

    @Public
    void step(Bigint d, ByteString m) {
        Bigint t = d;
        t += 3;
        this.count += t;
        this.count -= 1;
        this.count *= 2;
        this.count /= 3;
        this.count %= 1000;
        this.count <<= 2;
        this.count >>= 1;
        this.count &= 255;
        this.count |= 16;
        this.count ^= 5;
        this.tag &= m;
        this.tag |= m;
        this.tag ^= m;
        assertThat(this.count > 0);
    }
}
`

func TestParseJava_N134_CompoundAssignAllTenOperators(t *testing.T) {
	r := ParseJava([]byte(javaCompoundSrc), "Compound.runar.java")
	if len(r.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(r.ErrorStrings(), "; "))
	}
	var body []Statement
	for _, m := range r.Contract.Methods {
		if m.Name == "step" {
			body = m.Body
		}
	}
	// body[0] is the `Bigint t = d;` declaration, the last is the assert.
	want := []struct{ target, op string }{
		{"t", "+"}, {"count", "+"}, {"count", "-"}, {"count", "*"}, {"count", "/"},
		{"count", "%"}, {"count", "<<"}, {"count", ">>"}, {"count", "&"}, {"count", "|"},
		{"count", "^"}, {"tag", "&"}, {"tag", "|"}, {"tag", "^"},
	}
	if len(body) != len(want)+2 {
		t.Fatalf("expected %d statements, got %d", len(want)+2, len(body))
	}
	for i, w := range want {
		as, ok := body[i+1].(AssignmentStmt)
		if !ok {
			t.Fatalf("stmt %d: expected AssignmentStmt, got %T", i+1, body[i+1])
		}
		be, ok := as.Value.(BinaryExpr)
		if !ok || be.Op != w.op {
			t.Fatalf("stmt %d: expected BinaryExpr %q, got %#v", i+1, w.op, as.Value)
		}
		if javaCompoundTargetName(as.Target) != w.target || javaCompoundTargetName(be.Left) != w.target {
			t.Fatalf("stmt %d: expected target and left operand %q, got %#v / %#v", i+1, w.target, as.Target, be.Left)
		}
	}
}

func TestParseJava_N134_CompoundAssignInForUpdate(t *testing.T) {
	for _, op := range []string{"<<", ">>", "&", "|", "^"} {
		t.Run(op+"=", func(t *testing.T) {
			src := bareJavaCounter("for (Bigint i = Bigint.ZERO; i < 2; i "+op+"= 1) { assertThat(true); }", "", "count", bareJavaDefaultCtor)
			r := ParseJava([]byte(src), "BareCounter.runar.java")
			if len(r.Errors) > 0 {
				t.Fatalf("parse errors: %s", strings.Join(r.ErrorStrings(), "; "))
			}
			f, ok := r.Contract.Methods[0].Body[0].(ForStmt)
			if !ok {
				t.Fatalf("expected ForStmt, got %T", r.Contract.Methods[0].Body[0])
			}
			as, ok := f.Update.(AssignmentStmt)
			if !ok {
				t.Fatalf("expected AssignmentStmt update, got %#v", f.Update)
			}
			if be, ok := as.Value.(BinaryExpr); !ok || be.Op != op {
				t.Fatalf("expected BinaryExpr %q, got %#v", op, as.Value)
			}
		})
	}
}

func javaCompoundTargetName(e Expression) string {
	switch v := e.(type) {
	case Identifier:
		return v.Name
	case PropertyAccessExpr:
		return v.Property
	}
	return ""
}
