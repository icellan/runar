import RunarVerification.ANF.Json
import RunarVerification.Pipeline

/-!
# N-178 — `check_preimage.sighashFlag` reaches the OP_PUSH_TX binding blob

The TS reference (`oppushtx-codegen.ts` `anySBindingBytes`) appends
`sighashFlag & 0xff` to the on-chain-derived signature: byte 385 of the
422-byte binding blob, pushed as `01 <flag>` then `OP_CAT` (`7e`). Absent
means the default `ALL|FORKID` (`0x41`).

What these guards prove: an ANF program whose `check_preimage` carries
`"sighashFlag": 67` (`SINGLE|FORKID`), loaded through the real JSON loader
and compiled by `Pipeline.compileHex`, emits the flag byte `0x43` and no
`0x41` flag push; the default (absent) still emits `0x41`.

What they do NOT prove: anything about execution. The proofs in
`AgreesStateful` (and the `runOps_checkPreimageBindingRaw_eq` axiom) are
stated for the default flag only; a non-default flag is a codegen-shape
fact checked here, not a verified acceptance claim.
-/

namespace RunarVerification.Stack.SighashFlagGuard

open RunarVerification.ANF

/-- Minimal stateless contract: one public method that checks its preimage
under the given `check_preimage` JSON fragment and asserts the result. -/
def probeJson (flagField : String) : String :=
  "{\"contractName\":\"SighashProbe\",\"properties\":[],\"methods\":[" ++
  "{\"name\":\"unlock\",\"isPublic\":true," ++
  "\"params\":[{\"name\":\"txPreimage\",\"type\":\"SigHashPreimage\"}]," ++
  "\"body\":[" ++
  "{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"txPreimage\"}}," ++
  "{\"name\":\"t1\",\"value\":{\"kind\":\"check_preimage\",\"preimage\":\"t0\"" ++
    flagField ++ "}}," ++
  "{\"name\":\"t2\",\"value\":{\"kind\":\"assert\",\"value\":\"t1\"}}" ++
  "]}]}"

def probeHex (flagField : String) : String :=
  match ANFProgram.fromString (probeJson flagField) with
  | .ok p    => Pipeline.compileHex p
  | .error e => s!"LOAD-ERROR: {e}"

/-- Byte-aligned split of a hex string into its two-nibble bytes. -/
def hexBytes : List Char → List String
  | a :: b :: rest => String.ofList [a, b] :: hexBytes rest
  | _              => []

/-- Byte-aligned search: does `needle` occur as consecutive bytes of `hex`? -/
def hasBytes (hex : String) (needle : List String) : Bool :=
  go (hexBytes hex.toList)
where
  go : List String → Bool
    | []        => false
    | l@(_ :: t) => (needle.isPrefixOf l) || go t

/-- `01 <flag> 7e`: push-1 flag byte then `OP_CAT`, the blob's flag-append
site (bytes 390–392). -/
def flagPush (flag : String) : List String := ["01", flag, "7e"]

-- Default (absent) keeps the pinned ALL|FORKID byte.
#guard hasBytes (probeHex "") (flagPush "41")
-- SINGLE|FORKID (0x43 = 67) reaches the blob ...
#guard hasBytes (probeHex ",\"sighashFlag\":67") (flagPush "43")
-- ... and replaces, not adds to, the default byte.
#guard !hasBytes (probeHex ",\"sighashFlag\":67") (flagPush "41")


/-! ### The blob itself, tied to the TS reference -/

open RunarVerification.Stack.Lower in
/-- Lowercase hex of a byte array. -/
def toHex (b : ByteArray) : String :=
  String.join (b.toList.map fun x =>
    let h := (Nat.toDigits 16 x.toNat)
    String.ofList (if h.length < 2 then '0' :: h else h))

-- The flag site: bytes 384/385/386 are `01 41 7e` in the pinned default blob.
#guard Lower.checkPreimageBindingBytes.size == 422
#guard Lower.checkPreimageBindingBytes.get! (Lower.checkPreimageBindingFlagIndex - 1) == 0x01
#guard Lower.checkPreimageBindingBytes.get! Lower.checkPreimageBindingFlagIndex == 0x41
#guard Lower.checkPreimageBindingBytes.get! (Lower.checkPreimageBindingFlagIndex + 1) == 0x7e
-- An explicit 0x41 is byte-identical to the absent default (TS: same bytes).
#guard (Lower.checkPreimageBindingBytesFor (some 0x41)).toList ==
  Lower.checkPreimageBindingBytes.toList

/-- `checkPreimageBindingBytes(0x43)` from the TS reference
(`packages/runar-compiler/src/passes/oppushtx-codegen.ts`), captured with
`npx tsx -e` for N-178. -/
def tsBindingHexSingleForkId : String :=
  "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01437e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad"

#guard toHex (Lower.checkPreimageBindingBytesFor (some 0x43)) == tsBindingHexSingleForkId

/-! ### The plain `lowerValue` arm (not reached by `Pipeline.compile`) -/

-- `lowerValue` on `check_preimage` with flag 0x43 emits the 0x43 blob.
#guard (Lower.lowerValue [some "pre"] "cp" (.checkPreimage "pre" (some 0x43))).1.any
  (fun op => match op with
    | .rawBytes b => b.toList == (Lower.checkPreimageBindingBytesFor (some 0x43)).toList
    | _           => false)

end RunarVerification.Stack.SighashFlagGuard
