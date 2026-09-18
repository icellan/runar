package frontend

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Audit C3 — property initializers are restricted to literal values.
//
// Mirrors packages/runar-compiler/src/__tests__/property-initializer-literal.test.ts
// ---------------------------------------------------------------------------

// nonLiteralInitMsg is the cross-tier diagnostic substring.
const nonLiteralInitMsg = "initializer must be a literal value"

func TestValidate_NonLiteralInitializer_ArithmeticRejected(t *testing.T) {
	source := `
import { StatefulSmartContract, Addr } from 'runar-lang';

class Bad extends StatefulSmartContract {
  count: bigint = 1n + 2n;
  readonly owner: Addr;

  constructor(owner: Addr) {
    super(owner);
    this.owner = owner;
  }

  public bump(): void {
    this.count = this.count + 1n;
  }
}
`
	contract := mustParseTS(t, source)
	result := Validate(contract)

	if !hasErrorContaining(result.ErrorStrings(), nonLiteralInitMsg) {
		t.Errorf("expected a non-literal-initializer error, got: %s", strings.Join(result.ErrorStrings(), "; "))
	}
}

func TestValidate_NonLiteralInitializer_CallRejected(t *testing.T) {
	source := `
import { StatefulSmartContract, Addr, abs } from 'runar-lang';

class Bad2 extends StatefulSmartContract {
  count: bigint = abs(-3n);
  readonly owner: Addr;

  constructor(owner: Addr) {
    super(owner);
    this.owner = owner;
  }

  public bump(): void {
    this.count = this.count + 1n;
  }
}
`
	contract := mustParseTS(t, source)
	result := Validate(contract)

	if !hasErrorContaining(result.ErrorStrings(), nonLiteralInitMsg) {
		t.Errorf("expected a non-literal-initializer error, got: %s", strings.Join(result.ErrorStrings(), "; "))
	}
}

func TestValidate_LiteralInitializers_Accepted(t *testing.T) {
	source := `
import { StatefulSmartContract, Addr, ByteString } from 'runar-lang';

class Good extends StatefulSmartContract {
  count: bigint = 7n;
  flag: boolean = true;
  tag: ByteString = 'deadbeef';
  offset: bigint = -3n;
  readonly owner: Addr;

  constructor(owner: Addr) {
    super(owner);
    this.owner = owner;
  }

  public bump(): void {
    this.count = this.count + 1n;
  }
}
`
	contract := mustParseTS(t, source)
	result := Validate(contract)

	if len(result.Errors) > 0 {
		t.Errorf("expected no validation errors, got: %s", strings.Join(result.ErrorStrings(), "; "))
	}
}

// ---------------------------------------------------------------------------
// `toByteString('<hex>')` IS the ByteStringLiteral production — see
// spec/grammar.md section 11:
//
//	ByteStringLiteral = 'toByteString' '(' StringLiteral ')' ;
//
// 0e192af6 folded it in ANF lowering, which covers every EXPRESSION position.
// A property INITIALIZER is not one: this validator runs on the AST, BEFORE
// ANF lowering, and still saw a call node. The `.runar.rs` surface needs
// exactly this spelling in exactly this position — the Rust DSL writes
// initializers as assignments inside `init()` that the parser LIFTS into
// PropertyNode.Initializer, and a bare `"1976a914"` is a `&str` that cannot be
// assigned to a `ByteString` (`Vec<u8>`).
//
// Both halves are asserted: accepting it in the validator alone yields a
// property that validates and then loses its default, because
// extractLiteralValue returns nil for a call node.
// ---------------------------------------------------------------------------

const toByteStringInitSource = `
import { SmartContract, Addr, ByteString, toByteString, assert } from 'runar-lang';

class Wrapped extends SmartContract {
  readonly prefix: ByteString = toByteString('1976a914');
  readonly owner: Addr;

  constructor(owner: Addr) {
    super(owner);
    this.owner = owner;
  }

  public unlock(x: ByteString): void {
    assert(x === this.prefix);
  }
}
`

func TestValidate_ToByteStringLiteralInitializer_Accepted(t *testing.T) {
	contract := mustParseTS(t, toByteStringInitSource)
	result := Validate(contract)

	if len(result.Errors) > 0 {
		t.Errorf("expected no validation errors, got: %s", strings.Join(result.ErrorStrings(), "; "))
	}
}

func TestAnfLower_ToByteStringLiteralInitializer_Unwrapped(t *testing.T) {
	wrapped := LowerToANF(mustParseTS(t, toByteStringInitSource))

	bareSource := strings.Replace(
		toByteStringInitSource, `toByteString('1976a914')`, `'1976a914'`, 1)
	bare := LowerToANF(mustParseTS(t, bareSource))

	// Half two: a bare value, not a call node and not a dropped default.
	got, ok := wrapped.Properties[0].InitialValue.(string)
	if !ok || got != "1976a914" {
		t.Fatalf("expected initialValue %q, got %#v", "1976a914", wrapped.Properties[0].InitialValue)
	}

	// ...and the whole program is indistinguishable from the bare spelling,
	// which is what keeps expected-ir.json from moving.
	wrappedJSON, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatalf("marshal wrapped: %v", err)
	}
	bareJSON, err := json.Marshal(bare)
	if err != nil {
		t.Fatalf("marshal bare: %v", err)
	}
	if string(wrappedJSON) != string(bareJSON) {
		t.Errorf("wrapped ANF differs from bare ANF:\n wrapped=%s\n    bare=%s", wrappedJSON, bareJSON)
	}
}

func TestValidate_ToByteStringNonLiteralInitializer_Rejected(t *testing.T) {
	// Not the ByteStringLiteral production — a real call, and a call is not a
	// literal. Guards the accept from widening into "any toByteString call".
	source := `
import { SmartContract, Addr, ByteString, toByteString, assert } from 'runar-lang';

class Bad3 extends SmartContract {
  readonly prefix: ByteString = toByteString(someIdent);
  readonly owner: Addr;

  constructor(owner: Addr) {
    super(owner);
    this.owner = owner;
  }

  public unlock(x: ByteString): void {
    assert(x === this.prefix);
  }
}
`
	contract := mustParseTS(t, source)
	result := Validate(contract)

	if !hasErrorContaining(result.ErrorStrings(), nonLiteralInitMsg) {
		t.Errorf("expected a non-literal-initializer error, got: %s", strings.Join(result.ErrorStrings(), "; "))
	}
}
