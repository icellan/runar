import RunarVerification.ANF.Json
import RunarVerification.Pipeline
import RunarVerification.Stack.SighashFlagGuard

/-!
# `@bindingVariant` (#187, ports #170): the `all` OP_PUSH_TX binding blob

A method annotated `/** @bindingVariant all */` gets `"bindingVariant":"all"`
on its `check_preimage` ANF node, and every compiler tier then emits the
376-byte `CHECK_PREIMAGE_BINDING_ALL_HEX` blob in place of the 422-byte
low-S one.

What these guards check, all against bytes captured from the TS reference
(`npx tsx`, `packages/runar-compiler`, constant folding off):

* whole-program byte parity: the ANF of `conformance/preimage-binding/
  StatefulBinding.runar.ts` and `StatefulBindingAll.runar.ts`, loaded through
  the real JSON loader and compiled by `Pipeline.compileHex`, equals the TS
  script hex (699 and 653 bytes);
* the pinned 376-byte blob equals `CHECK_PREIMAGE_BINDING_ALL_HEX`, with the
  sighash flag at byte 339, and the `0x43` patch equals TS
  `checkPreimageBindingBytes(0x43, 'all')`;
* the loader: absent / `null` / `"lowS"` give the default blob, `"all"` the
  compact one, anything else is a load error.

What they do NOT check: execution. No runtime fact is stated for the `all`
blob (see `AgreesStateful` Part 7 for why).
-/

namespace RunarVerification.Stack.BindingVariantGuard

open RunarVerification.ANF
open RunarVerification.Stack.SighashFlagGuard (hasBytes probeHex probeJson)

def fixtureHex (json : String) : String :=
  match ANFProgram.fromString json with
  | .ok p    => Pipeline.compileHex p
  | .error e => s!"LOAD-ERROR: {e}"

def statefulBindingAnf : String :=
  "{\"contractName\":\"StatefulBinding\",\"methods\":[{\"body\":[{\"name\":\"t0\",\"sourceLoc\":{\"column\":31,\"file\":\"StatefulBinding.runar.ts\",\"line\":12},\"value\":{\"kind\":\"load_prop\",\"name\":\"count\"}},{\"name\":\"t1\",\"sourceLoc\":{\"column\":31,\"file\":\"StatefulBinding.runar.ts\",\"line\":12},\"value\":{\"args\":[\"t0\"],\"func\":\"super\",\"kind\":\"call\"}},{\"name\":\"t2\",\"sourceLoc\":{\"column\":45,\"file\":\"StatefulBinding.runar.ts\",\"line\":12},\"value\":{\"kind\":\"load_prop\",\"name\":\"count\"}},{\"name\":\"t3\",\"sourceLoc\":{\"column\":45,\"file\":\"StatefulBinding.runar.ts\",\"line\":12},\"value\":{\"kind\":\"update_prop\",\"name\":\"count\",\"value\":\"t2\"}}],\"isPublic\":false,\"name\":\"constructor\",\"params\":[{\"name\":\"count\",\"type\":\"bigint\"}]},{\"body\":[{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"txPreimage\"}},{\"name\":\"t1\",\"value\":{\"kind\":\"check_preimage\",\"preimage\":\"t0\"}},{\"name\":\"t2\",\"value\":{\"kind\":\"assert\",\"value\":\"t1\"}},{\"name\":\"t3\",\"value\":{\"kind\":\"load_param\",\"name\":\"txPreimage\"}},{\"name\":\"t4\",\"value\":{\"args\":[\"t3\"],\"func\":\"extractSigHashType\",\"kind\":\"call\"}},{\"name\":\"t5\",\"value\":{\"kind\":\"load_const\",\"value\":65}},{\"name\":\"t6\",\"value\":{\"kind\":\"bin_op\",\"left\":\"t4\",\"op\":\"===\",\"right\":\"t5\"}},{\"name\":\"t7\",\"value\":{\"kind\":\"assert\",\"value\":\"t6\"}},{\"name\":\"t8\",\"value\":{\"kind\":\"load_param\",\"name\":\"txPreimage\"}},{\"name\":\"t9\",\"value\":{\"kind\":\"deserialize_state\",\"preimage\":\"t8\"}},{\"name\":\"t10\",\"sourceLoc\":{\"column\":4,\"file\":\"StatefulBinding.runar.ts\",\"line\":14},\"value\":{\"kind\":\"load_prop\",\"name\":\"count\"}},{\"name\":\"t11\",\"sourceLoc\":{\"column\":4,\"file\":\"StatefulBinding.runar.ts\",\"line\":14},\"value\":{\"kind\":\"load_const\",\"value\":1}},{\"name\":\"t12\",\"sourceLoc\":{\"column\":4,\"file\":\"StatefulBinding.runar.ts\",\"line\":14},\"value\":{\"kind\":\"bin_op\",\"left\":\"t10\",\"op\":\"+\",\"right\":\"t11\"}},{\"name\":\"t13\",\"sourceLoc\":{\"column\":4,\"file\":\"StatefulBinding.runar.ts\",\"line\":14},\"value\":{\"kind\":\"update_prop\",\"name\":\"count\",\"value\":\"t12\"}},{\"name\":\"old\",\"sourceLoc\":{\"column\":4,\"file\":\"StatefulBinding.runar.ts\",\"line\":14},\"value\":{\"kind\":\"load_const\",\"value\":\"@ref:t10\"}},{\"name\":\"t14\",\"sourceLoc\":{\"column\":4,\"file\":\"StatefulBinding.runar.ts\",\"line\":15},\"value\":{\"kind\":\"load_const\",\"value\":0}},{\"name\":\"t15\",\"sourceLoc\":{\"column\":4,\"file\":\"StatefulBinding.runar.ts\",\"line\":15},\"value\":{\"kind\":\"bin_op\",\"left\":\"old\",\"op\":\">=\",\"right\":\"t14\"}},{\"name\":\"t16\",\"sourceLoc\":{\"column\":4,\"file\":\"StatefulBinding.runar.ts\",\"line\":15},\"value\":{\"kind\":\"assert\",\"value\":\"t15\"}},{\"name\":\"t17\",\"value\":{\"kind\":\"load_param\",\"name\":\"txPreimage\"}},{\"name\":\"t18\",\"value\":{\"args\":[\"t17\"],\"func\":\"extractAmount\",\"kind\":\"call\"}},{\"name\":\"t19\",\"value\":{\"kind\":\"load_param\",\"name\":\"_newAmount\"}},{\"name\":\"t20\",\"value\":{\"kind\":\"bin_op\",\"left\":\"t19\",\"op\":\">=\",\"right\":\"t18\"}},{\"name\":\"t21\",\"value\":{\"kind\":\"assert\",\"value\":\"t20\"}},{\"name\":\"t22\",\"value\":{\"kind\":\"load_param\",\"name\":\"_changePKH\"}},{\"name\":\"t23\",\"value\":{\"kind\":\"load_param\",\"name\":\"_changeAmount\"}},{\"name\":\"t24\",\"value\":{\"kind\":\"load_const\",\"value\":0}},{\"name\":\"t25\",\"value\":{\"kind\":\"bin_op\",\"left\":\"t23\",\"op\":\"!==\",\"right\":\"t24\"}},{\"name\":\"t28\",\"value\":{\"cond\":\"t25\",\"else\":[{\"name\":\"t27\",\"value\":{\"kind\":\"load_const\",\"value\":\"\"}}],\"kind\":\"if\",\"then\":[{\"name\":\"t26\",\"value\":{\"args\":[\"t22\",\"t23\"],\"func\":\"buildChangeOutput\",\"kind\":\"call\"}}]}},{\"name\":\"t29\",\"value\":{\"kind\":\"get_state_script\"}},{\"name\":\"t30\",\"value\":{\"kind\":\"load_param\",\"name\":\"txPreimage\"}},{\"name\":\"t31\",\"value\":{\"kind\":\"load_param\",\"name\":\"_newAmount\"}},{\"name\":\"t32\",\"value\":{\"args\":[\"t30\",\"t29\",\"t31\"],\"func\":\"computeStateOutput\",\"kind\":\"call\"}},{\"name\":\"t33\",\"value\":{\"args\":[\"t32\",\"t28\"],\"func\":\"cat\",\"kind\":\"call\"}},{\"name\":\"t34\",\"value\":{\"args\":[\"t33\"],\"func\":\"hash256\",\"kind\":\"call\"}},{\"name\":\"t35\",\"value\":{\"kind\":\"load_param\",\"name\":\"txPreimage\"}},{\"name\":\"t36\",\"value\":{\"args\":[\"t35\"],\"func\":\"extractOutputHash\",\"kind\":\"call\"}},{\"name\":\"t37\",\"value\":{\"kind\":\"bin_op\",\"left\":\"t34\",\"op\":\"===\",\"result_type\":\"bytes\",\"right\":\"t36\"}},{\"name\":\"t38\",\"value\":{\"isAutoInjectedStateCheck\":true,\"kind\":\"assert\",\"value\":\"t37\"}}],\"isPublic\":true,\"name\":\"bump\",\"params\":[{\"name\":\"_changePKH\",\"type\":\"Ripemd160\"},{\"name\":\"_changeAmount\",\"type\":\"bigint\"},{\"name\":\"_newAmount\",\"type\":\"bigint\"},{\"name\":\"txPreimage\",\"type\":\"SigHashPreimage\"}]}],\"parentClass\":\"StatefulSmartContract\",\"properties\":[{\"name\":\"count\",\"readonly\":false,\"type\":\"bigint\"}]}"

def tsStatefulBindingHex : String :=
  "61ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686856798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f77817651787c937b757c00a26978820134947f77587f758153797ca269547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f758777"

def statefulBindingAllAnf : String :=
  "{\"contractName\":\"StatefulBindingAll\",\"methods\":[{\"body\":[{\"name\":\"t0\",\"sourceLoc\":{\"column\":31,\"file\":\"StatefulBindingAll.runar.ts\",\"line\":8},\"value\":{\"kind\":\"load_prop\",\"name\":\"count\"}},{\"name\":\"t1\",\"sourceLoc\":{\"column\":31,\"file\":\"StatefulBindingAll.runar.ts\",\"line\":8},\"value\":{\"args\":[\"t0\"],\"func\":\"super\",\"kind\":\"call\"}},{\"name\":\"t2\",\"sourceLoc\":{\"column\":45,\"file\":\"StatefulBindingAll.runar.ts\",\"line\":8},\"value\":{\"kind\":\"load_prop\",\"name\":\"count\"}},{\"name\":\"t3\",\"sourceLoc\":{\"column\":45,\"file\":\"StatefulBindingAll.runar.ts\",\"line\":8},\"value\":{\"kind\":\"update_prop\",\"name\":\"count\",\"value\":\"t2\"}}],\"isPublic\":false,\"name\":\"constructor\",\"params\":[{\"name\":\"count\",\"type\":\"bigint\"}]},{\"body\":[{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"txPreimage\"}},{\"name\":\"t1\",\"value\":{\"bindingVariant\":\"all\",\"kind\":\"check_preimage\",\"preimage\":\"t0\"}},{\"name\":\"t2\",\"value\":{\"kind\":\"assert\",\"value\":\"t1\"}},{\"name\":\"t3\",\"value\":{\"kind\":\"load_param\",\"name\":\"txPreimage\"}},{\"name\":\"t4\",\"value\":{\"args\":[\"t3\"],\"func\":\"extractSigHashType\",\"kind\":\"call\"}},{\"name\":\"t5\",\"value\":{\"kind\":\"load_const\",\"value\":65}},{\"name\":\"t6\",\"value\":{\"kind\":\"bin_op\",\"left\":\"t4\",\"op\":\"===\",\"right\":\"t5\"}},{\"name\":\"t7\",\"value\":{\"kind\":\"assert\",\"value\":\"t6\"}},{\"name\":\"t8\",\"value\":{\"kind\":\"load_param\",\"name\":\"txPreimage\"}},{\"name\":\"t9\",\"value\":{\"kind\":\"deserialize_state\",\"preimage\":\"t8\"}},{\"name\":\"t10\",\"sourceLoc\":{\"column\":4,\"file\":\"StatefulBindingAll.runar.ts\",\"line\":11},\"value\":{\"kind\":\"load_prop\",\"name\":\"count\"}},{\"name\":\"t11\",\"sourceLoc\":{\"column\":4,\"file\":\"StatefulBindingAll.runar.ts\",\"line\":11},\"value\":{\"kind\":\"load_const\",\"value\":1}},{\"name\":\"t12\",\"sourceLoc\":{\"column\":4,\"file\":\"StatefulBindingAll.runar.ts\",\"line\":11},\"value\":{\"kind\":\"bin_op\",\"left\":\"t10\",\"op\":\"+\",\"right\":\"t11\"}},{\"name\":\"t13\",\"sourceLoc\":{\"column\":4,\"file\":\"StatefulBindingAll.runar.ts\",\"line\":11},\"value\":{\"kind\":\"update_prop\",\"name\":\"count\",\"value\":\"t12\"}},{\"name\":\"old\",\"sourceLoc\":{\"column\":4,\"file\":\"StatefulBindingAll.runar.ts\",\"line\":11},\"value\":{\"kind\":\"load_const\",\"value\":\"@ref:t10\"}},{\"name\":\"t14\",\"sourceLoc\":{\"column\":4,\"file\":\"StatefulBindingAll.runar.ts\",\"line\":12},\"value\":{\"kind\":\"load_const\",\"value\":0}},{\"name\":\"t15\",\"sourceLoc\":{\"column\":4,\"file\":\"StatefulBindingAll.runar.ts\",\"line\":12},\"value\":{\"kind\":\"bin_op\",\"left\":\"old\",\"op\":\">=\",\"right\":\"t14\"}},{\"name\":\"t16\",\"sourceLoc\":{\"column\":4,\"file\":\"StatefulBindingAll.runar.ts\",\"line\":12},\"value\":{\"kind\":\"assert\",\"value\":\"t15\"}},{\"name\":\"t17\",\"value\":{\"kind\":\"load_param\",\"name\":\"txPreimage\"}},{\"name\":\"t18\",\"value\":{\"args\":[\"t17\"],\"func\":\"extractAmount\",\"kind\":\"call\"}},{\"name\":\"t19\",\"value\":{\"kind\":\"load_param\",\"name\":\"_newAmount\"}},{\"name\":\"t20\",\"value\":{\"kind\":\"bin_op\",\"left\":\"t19\",\"op\":\">=\",\"right\":\"t18\"}},{\"name\":\"t21\",\"value\":{\"kind\":\"assert\",\"value\":\"t20\"}},{\"name\":\"t22\",\"value\":{\"kind\":\"load_param\",\"name\":\"_changePKH\"}},{\"name\":\"t23\",\"value\":{\"kind\":\"load_param\",\"name\":\"_changeAmount\"}},{\"name\":\"t24\",\"value\":{\"kind\":\"load_const\",\"value\":0}},{\"name\":\"t25\",\"value\":{\"kind\":\"bin_op\",\"left\":\"t23\",\"op\":\"!==\",\"right\":\"t24\"}},{\"name\":\"t28\",\"value\":{\"cond\":\"t25\",\"else\":[{\"name\":\"t27\",\"value\":{\"kind\":\"load_const\",\"value\":\"\"}}],\"kind\":\"if\",\"then\":[{\"name\":\"t26\",\"value\":{\"args\":[\"t22\",\"t23\"],\"func\":\"buildChangeOutput\",\"kind\":\"call\"}}]}},{\"name\":\"t29\",\"value\":{\"kind\":\"get_state_script\"}},{\"name\":\"t30\",\"value\":{\"kind\":\"load_param\",\"name\":\"txPreimage\"}},{\"name\":\"t31\",\"value\":{\"kind\":\"load_param\",\"name\":\"_newAmount\"}},{\"name\":\"t32\",\"value\":{\"args\":[\"t30\",\"t29\",\"t31\"],\"func\":\"computeStateOutput\",\"kind\":\"call\"}},{\"name\":\"t33\",\"value\":{\"args\":[\"t32\",\"t28\"],\"func\":\"cat\",\"kind\":\"call\"}},{\"name\":\"t34\",\"value\":{\"args\":[\"t33\"],\"func\":\"hash256\",\"kind\":\"call\"}},{\"name\":\"t35\",\"value\":{\"kind\":\"load_param\",\"name\":\"txPreimage\"}},{\"name\":\"t36\",\"value\":{\"args\":[\"t35\"],\"func\":\"extractOutputHash\",\"kind\":\"call\"}},{\"name\":\"t37\",\"value\":{\"kind\":\"bin_op\",\"left\":\"t34\",\"op\":\"===\",\"result_type\":\"bytes\",\"right\":\"t36\"}},{\"name\":\"t38\",\"value\":{\"isAutoInjectedStateCheck\":true,\"kind\":\"assert\",\"value\":\"t37\"}}],\"isPublic\":true,\"name\":\"bump\",\"params\":[{\"name\":\"_changePKH\",\"type\":\"Ripemd160\"},{\"name\":\"_changeAmount\",\"type\":\"bigint\"},{\"name\":\"_newAmount\",\"type\":\"bigint\"},{\"name\":\"txPreimage\",\"type\":\"SigHashPreimage\"}]}],\"parentClass\":\"StatefulSmartContract\",\"properties\":[{\"name\":\"count\",\"readonly\":false,\"type\":\"bigint\"}]}"

def tsStatefulBindingAllHex : String :=
  "61ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8b82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686856798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f77817651787c937b757c00a26978820134947f77587f758153797ca269547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f758777"

-- Control: the default (lowS) fixture is byte-exact.
#guard fixtureHex statefulBindingAnf == tsStatefulBindingHex
-- The `@bindingVariant all` fixture is byte-exact.
#guard fixtureHex statefulBindingAllAnf == tsStatefulBindingAllHex

/-! ### The blob itself, tied to the TS reference -/

/-- TS `CHECK_PREIMAGE_BINDING_ALL_HEX` (`oppushtx-codegen.ts`). -/
def tsBindingAllHex : String :=
  "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8b82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad"

/-- TS `checkPreimageBindingBytes(0x43, 'all')`. -/
def tsBindingAllHexSingleForkId : String :=
  "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8b82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01437e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad"

#guard Lower.checkPreimageBindingAllBytes.size == 376
#guard SighashFlagGuard.toHex Lower.checkPreimageBindingAllBytes == tsBindingAllHex
#guard SighashFlagGuard.toHex (Lower.checkPreimageBindingBytesFor none .all) == tsBindingAllHex
-- The flag site: bytes 338/339/340 are `01 41 7e`.
#guard Lower.checkPreimageBindingAllBytes.get! (Lower.checkPreimageBindingAllFlagIndex - 1) == 0x01
#guard Lower.checkPreimageBindingAllBytes.get! Lower.checkPreimageBindingAllFlagIndex == 0x41
#guard Lower.checkPreimageBindingAllBytes.get! (Lower.checkPreimageBindingAllFlagIndex + 1) == 0x7e
#guard SighashFlagGuard.toHex (Lower.checkPreimageBindingBytesFor (some 0x43) .all) == tsBindingAllHexSingleForkId
#guard (Lower.checkPreimageBindingBytesFor (some 0x41) .all).toList ==
  Lower.checkPreimageBindingAllBytes.toList

/-! ### The JSON loader and the lowering -/

-- Absent, `null` and `"lowS"` all emit the default blob (and never the `all` one).
#guard hasBytes (probeHex "") (Lower.checkPreimageBindingBytes.toList.map fun b => (SighashFlagGuard.toHex (ByteArray.mk #[b])))
#guard probeHex ",\"bindingVariant\":\"lowS\"" == probeHex ""
#guard probeHex ",\"bindingVariant\":null" == probeHex ""
-- `"all"` emits the `all` blob and not the default one.
#guard hasBytes (probeHex ",\"bindingVariant\":\"all\"")
  (Lower.checkPreimageBindingAllBytes.toList.map fun b => (SighashFlagGuard.toHex (ByteArray.mk #[b])))
#guard !hasBytes (probeHex ",\"bindingVariant\":\"all\"")
  (Lower.checkPreimageBindingBytes.toList.map fun b => (SighashFlagGuard.toHex (ByteArray.mk #[b])))
-- The two knobs compose: `all` + SINGLE|FORKID patches the `all` blob's flag.
#guard hasBytes (probeHex ",\"sighashFlag\":67,\"bindingVariant\":\"all\"")
  ((Lower.checkPreimageBindingBytesFor (some 0x43) .all).toList.map fun b => (SighashFlagGuard.toHex (ByteArray.mk #[b])))
-- Anything else is a load error (TS `anf-required-fields.ts`), never a blob.
#guard (probeHex ",\"bindingVariant\":\"ALL\"").startsWith "LOAD-ERROR"
#guard (probeHex ",\"bindingVariant\":1").startsWith "LOAD-ERROR"
-- Serialisation writes the field for `all` only, and re-loads to the same node.
#guard match ANFProgram.fromString (probeJson ",\"bindingVariant\":\"all\"") with
  | .ok p => (ANFProgram.fromString (ANFProgram.toJsonString p)).toOption.map
              (fun q => Pipeline.compileHex q) == some (Pipeline.compileHex p)
            && ((ANFProgram.toJsonString p).splitOn "\"bindingVariant\":\"all\"").length == 2
  | .error _ => false
#guard match ANFProgram.fromString (probeJson ",\"bindingVariant\":\"lowS\"") with
  | .ok p => ((ANFProgram.toJsonString p).splitOn "bindingVariant").length == 1
  | .error _ => false

-- The plain `lowerValue` arm (not reached by `Pipeline.compile`) honours it too.
#guard (Lower.lowerValue [some "pre"] "cp" (.checkPreimage "pre" none .all)).1.any
  (fun op => match op with
    | .rawBytes b => b.toList == Lower.checkPreimageBindingAllBytes.toList
    | _           => false)

end RunarVerification.Stack.BindingVariantGuard
