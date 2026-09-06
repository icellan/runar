package frontend

import (
	"strings"
	"testing"
)

// NEW-012 — `return` in a PUBLIC method.
//
// spec/grammar.md:161 makes public methods void, :162 makes their trailing
// assert the spending condition, and spec/semantics.md gives `return` no
// early-exit meaning at all (§4.6 defines only "the value of this method is
// v"; §4.7 sequences statements unconditionally).
//
// Lowering it as if it were the tail of an inlined helper produced two broken
// scripts: `return;` left the enclosing arm with no result, so it yielded OP_0
// and the whole script evaluated FALSE (unspendable, from source that compiled
// clean — in THIS tier it surfaced as an internal stack-lowering panic, "index
// out of range [-1]"); `return expr;` made the returned value the branch result
// and hence the script's final truthiness, so any truthy expr spent the
// contract WITHOUT reaching the guarding assert (fail-OPEN).
const publicReturnDiag = "must not use `return`"

func validateTsSource(t *testing.T, source string) *ValidationResult {
	t.Helper()
	parsed := ParseSource([]byte(source), "Guard.runar.ts")
	if len(parsed.Errors) != 0 {
		t.Fatalf("unexpected parse errors: %v", parsed.Errors)
	}
	if parsed.Contract == nil {
		t.Fatal("expected a contract from parsing")
	}
	return Validate(parsed.Contract)
}

func countDiag(result *ValidationResult, substr string) int {
	n := 0
	for _, e := range result.Errors {
		if strings.Contains(e.Message, substr) {
			n++
		}
	}
	return n
}

func TestValidate_RejectsBareReturnInPublicMethod(t *testing.T) {
	result := validateTsSource(t, `
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  public unlock(x: bigint) {
    if (x > 0n) { return; }
    assert(x === this.secret);
  }
}
`)
	if got := countDiag(result, publicReturnDiag); got != 1 {
		t.Fatalf("expected 1 public-return error, got %d: %v", got, result.Errors)
	}
}

func TestValidate_RejectsValuedReturnInPublicMethod(t *testing.T) {
	result := validateTsSource(t, `
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  public unlock(x: bigint) {
    if (x > 0n) { return x; }
    assert(x === this.secret);
  }
}
`)
	if got := countDiag(result, publicReturnDiag); got != 1 {
		t.Fatalf("expected 1 public-return error, got %d: %v", got, result.Errors)
	}
}

func TestValidate_RejectsReturnNestedInLoopInPublicMethod(t *testing.T) {
	result := validateTsSource(t, `
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  public unlock(x: bigint) {
    for (let i: bigint = 0n; i < 4n; i++) {
      if (x > i) { return; }
    }
    assert(x === this.secret);
  }
}
`)
	if got := countDiag(result, publicReturnDiag); got != 1 {
		t.Fatalf("expected 1 public-return error, got %d: %v", got, result.Errors)
	}
}

// spec/grammar.md:168 — "Private methods may return a value." The rejection
// must not spill onto the inlined-helper form, which is how ~340 in-repo
// contracts legitimately use `return`.
func TestValidate_AllowsReturnInPrivateHelper(t *testing.T) {
	result := validateTsSource(t, `
class Guard extends SmartContract {
  readonly secret: bigint;
  constructor(secret: bigint) { super(secret); this.secret = secret; }

  private doubled(v: bigint): bigint { return v + v; }

  public unlock(x: bigint) {
    assert(this.doubled(x) === this.secret);
  }
}
`)
	if got := countDiag(result, publicReturnDiag); got != 0 {
		t.Fatalf("private helper must keep its return, got %d errors: %v", got, result.Errors)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("expected a clean validation, got: %v", result.Errors)
	}
}
