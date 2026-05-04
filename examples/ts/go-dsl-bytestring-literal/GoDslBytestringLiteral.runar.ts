// Mirrors examples/go/go-dsl-bytestring-literal/GoDslBytestringLiteral.runar.go.
//
// The Go-DSL fixture exercises two Go-specific surface features
// (`runar.BigintBig` declared as a property type, and
// `runar.ByteString("\x00\x6a")` as an inline byte-string literal). In
// every other format, both lower to the same primitives — `bigint` /
// `ByteString` — so the parser-layer port is a straightforward translation
// of the Check method.
import { SmartContract, ByteString, assert } from 'runar-lang';

export class GoDslBytestringLiteral extends SmartContract {
  readonly target: bigint;
  readonly expected: ByteString;

  constructor(target: bigint, expected: ByteString) {
    super(target, expected);
    this.target = target;
    this.expected = expected;
  }

  public check(a: bigint, b: bigint): void {
    assert(a + b === this.target);
    assert("006a" === this.expected);
  }
}
