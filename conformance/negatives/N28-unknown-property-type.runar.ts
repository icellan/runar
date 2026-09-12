// N-109: an unrecognised type name in a PROPERTY declaration.
//
// All seven tiers refuse this, so nothing unsafe ever compiled — but they did
// not refuse it in the same PASS, and that is what this fixture pins.
//
// Six tiers reject `Foobarium` in the VALIDATOR, naming the type and the line:
//
//   go/python/ruby   Unknown.runar.ts:4:2: unsupported type 'Foobarium' in
//                    property declaration at Unknown.runar.ts:4
//   ts/rust/java     Unsupported type 'Foobarium' in property declaration...
//
// The Zig tier reached STACK LOWERING and died there with a bare
// `UnsupportedOperation` / `error: StackLowerFailed` — no type name, no source
// location, three passes after its peers, and in a pass whose diagnostics are
// written for compiler developers rather than contract authors. Its validator
// did carry an unsupported-type arm, but the arm was guarded with
// `and prop.type_info != .unknown`, and `.unknown` is exactly what an
// unrecognised type name lowers to, so it could never fire.
//
// That is not only prose. A frontend-only entry point — `--parse-only`, a
// `stop_after = .validate` library call, the tier's answer to "is this valid
// Rúnar?" — green-lit the contract, because nothing before stack lowering
// objected. Six tiers answered no at that same question.
//
// The shape stays invalid under any future change: `Foobarium` is not a Rúnar
// type on any of the nine surfaces and is not a runar-lang alias, so there is
// no resolution under which this becomes a legal property declaration.
import { StatefulSmartContract, assert } from 'runar-lang';

export class UnknownProp extends StatefulSmartContract {
  count: Foobarium;

  constructor(count: Foobarium) {
    super(count);
    this.count = count;
  }

  public go(v: bigint) {
    assert(v >= 0n);
  }
}
