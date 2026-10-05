package frontend

import (
	"strings"
	"testing"
)

// N-023 (R49): on the .runar.java surface a bare name that no local or
// parameter shadows IS the field, so `count = ...` writes state in Java. The
// parser used to lower it as a local rebind: a stateful contract compiled with
// no update_prop and its state never changed. Every tier refuses the bare form
// with the TS reference's diagnostic.
//
// Proves: the Go Java parser refuses each assignment spelling (=, op=, ++/--,
// statement or nested, any method incl. the constructor) on an unshadowed
// property, and accepts this.x writes plus local / parameter / for-variable
// shadowing, honouring Java block scope.
// Does not prove: other tiers (conformance/negatives N166 covers them), or
// anything about bare reads, which R49 leaves alone.

const bareJavaMsg = "bare assignment to property 'count' is not allowed; write `this.count = ...`"

func bareJavaCounter(body, params, ctorParam, ctorBody string) string {
	return `
package p;
import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import static runar.lang.Builtins.assertThat;

class BareCounter extends StatefulSmartContract {
    Bigint count;

    BareCounter(Bigint ` + ctorParam + `) {
        ` + ctorBody + `
    }

    @Public
    void increment(` + params + `) {
        ` + body + `
    }
}
`
}

func bareJavaErrors(src string) []string {
	r := ParseJava([]byte(src), "BareCounter.runar.java")
	var out []string
	for _, e := range r.Errors {
		if e.Severity == SeverityError {
			out = append(out, e.Message)
		}
	}
	return out
}

const bareJavaDefaultCtor = "super(count);\n        this.count = count;"

func TestParseJava_N023_BarePropertyAssignRefused(t *testing.T) {
	cases := map[string]string{
		"plain =":                 "count = count.plus(Bigint.ONE);",
		"compound +=":             "count += Bigint.ONE;",
		"postfix ++":              "count++;",
		"prefix --":               "--count;",
		"inside an if arm":        "if (this.count.gt(Bigint.ZERO)) { count = Bigint.ONE; }",
		"in a for update":         "for (Bigint i = Bigint.ZERO; i.lt(Bigint.TWO); count++) { assertThat(true); }",
		"nested in an expression": "assertThat((count++).gt(Bigint.ZERO));",
		"after an if-scoped local": "if (this.count.gt(Bigint.ZERO)) { Bigint count = Bigint.ONE; this.count = count; }\n" +
			"        count = Bigint.TWO;",
		"before the shadowing local": "count = Bigint.ONE;\n        Bigint count = Bigint.TWO;\n        this.count = count;",
	}
	for label, body := range cases {
		t.Run(label, func(t *testing.T) {
			errs := bareJavaErrors(bareJavaCounter(body, "", "count", bareJavaDefaultCtor))
			if !bareJavaContains(errs, bareJavaMsg) {
				t.Fatalf("expected %q, got %v", bareJavaMsg, errs)
			}
		})
	}
	t.Run("constructor", func(t *testing.T) {
		errs := bareJavaErrors(bareJavaCounter("this.count = this.count.plus(Bigint.ONE);", "", "c", "super(c);\n        count = c;"))
		if !bareJavaContains(errs, bareJavaMsg) {
			t.Fatalf("expected %q, got %v", bareJavaMsg, errs)
		}
	})
}

func TestParseJava_N023_ShadowedOrExplicitAccepted(t *testing.T) {
	type tc struct{ body, params string }
	cases := map[string]tc{
		"this.count = ...": {"this.count = this.count.plus(Bigint.ONE);", ""},
		"local shadow":     {"Bigint count = this.count;\n        count = count.plus(Bigint.ONE);\n        this.count = count;", ""},
		"parameter shadow": {"count = count.plus(Bigint.ONE);\n        this.count = count;", "Bigint count"},
		"for-variable shadow": {"for (Bigint count = Bigint.ZERO; count.lt(Bigint.TWO); count++) { assertThat(true); }\n" +
			"        this.count = this.count.plus(Bigint.ONE);", ""},
		"bare read": {"this.count = count.plus(Bigint.ONE);", ""},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			if errs := bareJavaErrors(bareJavaCounter(c.body, c.params, "count", bareJavaDefaultCtor)); len(errs) != 0 {
				t.Fatalf("expected no errors, got %v", errs)
			}
		})
	}
}

func bareJavaContains(xs []string, want string) bool {
	for _, x := range xs {
		if strings.Contains(x, want) {
			return true
		}
	}
	return false
}
