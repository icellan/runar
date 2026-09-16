// W5 / LoopYoink, first site — a declaration list in statement position.
//
// `01-parse.ts` read `decls[0]` and discarded the rest, after pushing a
// diagnostic at severity `warning`. `compile()` stops only on
// `severity === 'error'`, so the warning stopped nothing: the contract compiled,
// `b` was gone, and the caller got `success === true`.
//
// The other tiers were not even that loud. The Go tier's TypeScript surface
// resolves the declaration with
// `findChildByType(node, "variable_declarator")`, which returns the FIRST
// declarator and ignores every later one with no diagnostic at all.
//
// The language subset is one declarator per statement -- `spec/grammar.md`'s
// VariableDeclaration production says so -- so the fix is to fail closed rather
// than to start lowering declaration lists, which is a language feature with no
// golden behind it.
//
// `b` is deliberately NOT read below. The first draft of this fixture asserted
// on `a + b`, and all seven tiers refused it before any fix -- not because they
// enforce the declaration-list rule, but because dropping `b` makes the later
// reference an undeclared variable. That version would have passed with the bug
// fully reinjected, which is the failure mode this branch exists to find. With
// `b` unread, the drop is silent, and the fixture measures the rule it names.
//
// Measured on that corrected shape before the fix: ts / go / rust ACCEPTED it
// (ts with a warning, go and rust with no diagnostic at all); python, zig, ruby
// and java refused it, because their hand-written parsers stop at the stray
// comma. Four tiers refusing a program three tiers compile is the frontend
// parity break, independently of the dropped code.

import { SmartContract, assert } from 'runar-lang';

class MultiDeclStatement extends SmartContract {
  readonly tag: bigint;

  constructor(tag: bigint) {
    super(tag);
    this.tag = tag;
  }

  public verify(x: bigint) {
    let a: bigint = 1n, b: bigint = 2n;
    assert(x === a + this.tag);
  }
}
