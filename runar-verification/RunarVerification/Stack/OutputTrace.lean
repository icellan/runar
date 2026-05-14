import RunarVerification.Stack.Agrees

/-!
# Stack output traces

This file is a proof-facing extension point for the `addOutput` family.
Legacy `Stack.Eval.runOps` intentionally keeps `StackState.outputs`
stable for the existing peephole/simulation surface. The definitions here
model the output-record side effect separately as an explicit trace event,
then prove the bridge shape consumed by `Stack.Agrees`.
-/

namespace RunarVerification.Stack
namespace OutputTrace

open RunarVerification.ANF.Eval (Output State Value)
open RunarVerification.Stack.Eval (StackState)

/-- A proof-level event corresponding to one ANF output intrinsic. -/
inductive OutputEvent where
  | state (satoshis : Int) (stateValues : List Value) : OutputEvent
  | rawScript (satoshis : Int) (scriptBytes : ByteArray) : OutputEvent
  | dataOnly (satoshis : Int) (scriptBytes : ByteArray) : OutputEvent

namespace OutputEvent

/-- Forget the event tag to the ANF evaluator's canonical output record. -/
def toOutput : OutputEvent → Output
  | .state satoshis stateValues => .state satoshis stateValues
  | .rawScript satoshis scriptBytes => .rawScript satoshis scriptBytes
  | .dataOnly satoshis scriptBytes => .dataOnly satoshis scriptBytes

end OutputEvent

/--
The conditional bridge shape expected by
`Agrees.agrees_preserved_addOutput`: outputs append, props are unchanged,
and the intrinsic leaves the opaque ANF result on top of the stack.
-/
def OutputBridge (stkSt resSt : StackState) (output : Output) : Prop :=
  resSt.outputs = stkSt.outputs ++ [output] ∧
  resSt.props = stkSt.props ∧
  resSt.stack = (.vOpaque ByteArray.empty) :: stkSt.stack

/--
Apply one output event to the Stack state. This is deliberately separate
from `runOps`: it models the output-record effect that the legacy VM does
not mutate while preserving all other StackState fields.
-/
def applyEvent (event : OutputEvent) (stkSt : StackState) : StackState :=
  { stkSt with
    outputs := stkSt.outputs ++ [event.toOutput],
    stack := (.vOpaque ByteArray.empty) :: stkSt.stack }

/-- A serialized-output trace is a list of output events in emission order. -/
abbrev Trace := List OutputEvent

/-- A serialized-output trace annotated with the ANF binding each event names. -/
abbrev NamedTrace := List (String × OutputEvent)

/-- Execute a proof-level output trace, appending each emitted output record. -/
def applyTrace : Trace → StackState → StackState
  | [], stkSt => stkSt
  | event :: rest, stkSt => applyTrace rest (applyEvent event stkSt)

/--
Apply one named output event to the ANF state: append the output record and
bind the intrinsic's opaque result.
-/
def applyNamedEvent (named : String × OutputEvent) (anfSt : State) : State :=
  State.addBinding
    { anfSt with outputs := anfSt.outputs ++ [named.2.toOutput] }
    named.1 (.vOpaque ByteArray.empty)

/-- Execute a named output trace on the ANF state in emission order. -/
def applyNamedTrace : NamedTrace → State → State
  | [], anfSt => anfSt
  | named :: rest, anfSt => applyNamedTrace rest (applyNamedEvent named anfSt)

/-- Extend the tagged stack map with the bindings introduced by a named trace. -/
def taggedTraceMap : NamedTrace → Agrees.TaggedStackMap → Agrees.TaggedStackMap
  | [], tsm => tsm
  | named :: rest, tsm =>
      taggedTraceMap rest ((named.1, Agrees.SlotKind.binding) :: tsm)

/-- Freshness side condition threaded through a named output trace. -/
def freshForNamedTrace : NamedTrace → Agrees.TaggedStackMap → Prop
  | [], _ => True
  | named :: rest, tsm =>
      Agrees.freshIn named.1 (Agrees.untagSm tsm) ∧
      freshForNamedTrace rest ((named.1, Agrees.SlotKind.binding) :: tsm)

/-- A single output event supplies exactly the bridge hypothesis used by `Agrees`. -/
theorem applyEvent_outputBridge (event : OutputEvent) (stkSt : StackState) :
    OutputBridge stkSt (applyEvent event stkSt) event.toOutput := by
  simp [OutputBridge, applyEvent]

/-- Output traces append their output records in event order. -/
theorem applyTrace_outputs (trace : Trace) (stkSt : StackState) :
    (applyTrace trace stkSt).outputs =
      stkSt.outputs ++ trace.map OutputEvent.toOutput := by
  induction trace generalizing stkSt with
  | nil =>
      simp [applyTrace]
  | cons event rest ih =>
      simp [applyTrace, applyEvent, ih, List.append_assoc]

/--
Output-aware preservation theorem for callers that can produce an
`OutputEvent`. It discharges the conditional bridge in
`Agrees.agrees_preserved_addOutput` using `applyEvent_outputBridge`.
-/
theorem agreesTagged_applyEvent
    (tsm : Agrees.TaggedStackMap) (bn : String)
    (anfSt : State) (stkSt : StackState) (event : OutputEvent)
    (hAgrees : Agrees.agreesTagged tsm anfSt stkSt)
    (hFresh : Agrees.freshIn bn (Agrees.untagSm tsm)) :
    Agrees.agreesTagged ((bn, Agrees.SlotKind.binding) :: tsm)
      (({ anfSt with outputs := anfSt.outputs ++ [event.toOutput] }
          |>.addBinding bn (.vOpaque ByteArray.empty)))
      (applyEvent event stkSt) := by
  exact Agrees.agrees_preserved_addOutput tsm bn anfSt stkSt
    (applyEvent event stkSt) event.toOutput hAgrees hFresh
    (applyEvent_outputBridge event stkSt)

/--
Repeated output events preserve tagged agreement when each event is paired
with the binding name introduced by the lowered wrapper.
-/
theorem agreesTagged_applyNamedTrace
    (namedTrace : NamedTrace)
    (tsm : Agrees.TaggedStackMap) (anfSt : State) (stkSt : StackState)
    (hAgrees : Agrees.agreesTagged tsm anfSt stkSt)
    (hFresh : freshForNamedTrace namedTrace tsm) :
    Agrees.agreesTagged (taggedTraceMap namedTrace tsm)
      (applyNamedTrace namedTrace anfSt)
      (applyTrace (namedTrace.map Prod.snd) stkSt) := by
  induction namedTrace generalizing tsm anfSt stkSt with
  | nil =>
      simpa [applyNamedTrace, taggedTraceMap, applyTrace] using hAgrees
  | cons named rest ih =>
      cases named with
      | mk bn event =>
          have hStep :
              Agrees.agreesTagged ((bn, Agrees.SlotKind.binding) :: tsm)
                (applyNamedEvent (bn, event) anfSt)
                (applyEvent event stkSt) := by
            simpa [applyNamedEvent] using
              (agreesTagged_applyEvent tsm bn anfSt stkSt event hAgrees hFresh.1)
          simpa [applyNamedTrace, taggedTraceMap, applyTrace,
            applyNamedEvent, freshForNamedTrace] using
            (ih ((bn, Agrees.SlotKind.binding) :: tsm)
              (applyNamedEvent (bn, event) anfSt)
              (applyEvent event stkSt) hStep hFresh.2)

/-- State-output specialization for ANF `.addOutput`. -/
theorem agreesTagged_applyStateOutputEvent
    (tsm : Agrees.TaggedStackMap) (bn : String)
    (anfSt : State) (stkSt : StackState)
    (satoshis : Int) (stateValues : List Value)
    (hAgrees : Agrees.agreesTagged tsm anfSt stkSt)
    (hFresh : Agrees.freshIn bn (Agrees.untagSm tsm)) :
    Agrees.agreesTagged ((bn, Agrees.SlotKind.binding) :: tsm)
      (State.addBinding
        { anfSt with outputs := anfSt.outputs ++ [Output.state satoshis stateValues] }
        bn (.vOpaque ByteArray.empty))
      (applyEvent (.state satoshis stateValues) stkSt) :=
  agreesTagged_applyEvent tsm bn anfSt stkSt
    (.state satoshis stateValues) hAgrees hFresh

/-- Raw-script-output specialization for ANF `.addRawOutput`. -/
theorem agreesTagged_applyRawScriptOutputEvent
    (tsm : Agrees.TaggedStackMap) (bn : String)
    (anfSt : State) (stkSt : StackState)
    (satoshis : Int) (scriptBytes : ByteArray)
    (hAgrees : Agrees.agreesTagged tsm anfSt stkSt)
    (hFresh : Agrees.freshIn bn (Agrees.untagSm tsm)) :
    Agrees.agreesTagged ((bn, Agrees.SlotKind.binding) :: tsm)
      (State.addBinding
        { anfSt with outputs := anfSt.outputs ++ [Output.rawScript satoshis scriptBytes] }
        bn (.vOpaque ByteArray.empty))
      (applyEvent (.rawScript satoshis scriptBytes) stkSt) :=
  agreesTagged_applyEvent tsm bn anfSt stkSt
    (.rawScript satoshis scriptBytes) hAgrees hFresh

/-- Data-output specialization for ANF `.addDataOutput`. -/
theorem agreesTagged_applyDataOnlyOutputEvent
    (tsm : Agrees.TaggedStackMap) (bn : String)
    (anfSt : State) (stkSt : StackState)
    (satoshis : Int) (scriptBytes : ByteArray)
    (hAgrees : Agrees.agreesTagged tsm anfSt stkSt)
    (hFresh : Agrees.freshIn bn (Agrees.untagSm tsm)) :
    Agrees.agreesTagged ((bn, Agrees.SlotKind.binding) :: tsm)
      (State.addBinding
        { anfSt with outputs := anfSt.outputs ++ [Output.dataOnly satoshis scriptBytes] }
        bn (.vOpaque ByteArray.empty))
      (applyEvent (.dataOnly satoshis scriptBytes) stkSt) :=
  agreesTagged_applyEvent tsm bn anfSt stkSt
    (.dataOnly satoshis scriptBytes) hAgrees hFresh

/-! ## Lowered output-construction wrapper bridges

The following lemmas connect the concrete output-construction lowering
helpers to the proof-level trace event consumed above. They do not claim
that `Stack.Eval.runOps` mutates `StackState.outputs`; instead they pin
down the wrapper shape that remains after lowering (the binding is named
on top of the tracked stack) and package the corresponding abstract
output event as the step that satisfies `Agrees`' output bridge.
-/

/-- `lowerAddOutputOps` names the state-output wrapper binding on top,
and the matching state-output trace event preserves tagged agreement. -/
theorem lowerAddOutputOps_applyStateOutputEvent
    (tsm : Agrees.TaggedStackMap) (bn : String)
    (anfSt : State) (stkSt : StackState)
    (satoshisRef : String) (stateValueRefs : List String)
    (props : List ANF.ANFProperty)
    (satoshis : Int) (stateValues : List Value)
    (hAgrees : Agrees.agreesTagged tsm anfSt stkSt)
    (hFresh : Agrees.freshIn bn (Agrees.untagSm tsm)) :
    (Lower.lowerAddOutputOps (Agrees.untagSm tsm) bn
        satoshisRef stateValueRefs props).2 = bn :: Agrees.untagSm tsm ∧
    Agrees.agreesTagged ((bn, Agrees.SlotKind.binding) :: tsm)
      (State.addBinding
        { anfSt with outputs := anfSt.outputs ++ [Output.state satoshis stateValues] }
        bn (.vOpaque ByteArray.empty))
      (applyEvent (.state satoshis stateValues) stkSt) := by
  constructor
  · simp [Lower.lowerAddOutputOps, Lower.StackMap.push]
  · exact agreesTagged_applyStateOutputEvent tsm bn anfSt stkSt
      satoshis stateValues hAgrees hFresh

/-- `lowerValue`'s `.addRawOutput` wrapper names the binding on top,
and the matching raw-output trace event preserves tagged agreement. -/
theorem lowerValue_addRawOutput_applyRawScriptOutputEvent
    (tsm : Agrees.TaggedStackMap) (bn : String)
    (anfSt : State) (stkSt : StackState)
    (satoshisRef scriptBytesRef : String)
    (satoshis : Int) (scriptBytes : ByteArray)
    (hAgrees : Agrees.agreesTagged tsm anfSt stkSt)
    (hFresh : Agrees.freshIn bn (Agrees.untagSm tsm)) :
    (Lower.lowerValue (Agrees.untagSm tsm) bn
        (.addRawOutput satoshisRef scriptBytesRef)).2 =
          bn :: Agrees.untagSm tsm ∧
    Agrees.agreesTagged ((bn, Agrees.SlotKind.binding) :: tsm)
      (State.addBinding
        { anfSt with outputs := anfSt.outputs ++ [Output.rawScript satoshis scriptBytes] }
        bn (.vOpaque ByteArray.empty))
      (applyEvent (.rawScript satoshis scriptBytes) stkSt) := by
  constructor
  · simp [Lower.lowerValue, Lower.lowerAddRawOutputOps, Lower.StackMap.push]
  · exact agreesTagged_applyRawScriptOutputEvent tsm bn anfSt stkSt
      satoshis scriptBytes hAgrees hFresh

/-- `lowerValue`'s `.addDataOutput` wrapper shares the raw-output
lowering shape, with a distinct data-output trace event. -/
theorem lowerValue_addDataOutput_applyDataOnlyOutputEvent
    (tsm : Agrees.TaggedStackMap) (bn : String)
    (anfSt : State) (stkSt : StackState)
    (satoshisRef scriptBytesRef : String)
    (satoshis : Int) (scriptBytes : ByteArray)
    (hAgrees : Agrees.agreesTagged tsm anfSt stkSt)
    (hFresh : Agrees.freshIn bn (Agrees.untagSm tsm)) :
    (Lower.lowerValue (Agrees.untagSm tsm) bn
        (.addDataOutput satoshisRef scriptBytesRef)).2 =
          bn :: Agrees.untagSm tsm ∧
    Agrees.agreesTagged ((bn, Agrees.SlotKind.binding) :: tsm)
      (State.addBinding
        { anfSt with outputs := anfSt.outputs ++ [Output.dataOnly satoshis scriptBytes] }
        bn (.vOpaque ByteArray.empty))
      (applyEvent (.dataOnly satoshis scriptBytes) stkSt) := by
  constructor
  · simp [Lower.lowerValue, Lower.lowerAddRawOutputOps, Lower.StackMap.push]
  · exact agreesTagged_applyDataOnlyOutputEvent tsm bn anfSt stkSt
      satoshis scriptBytes hAgrees hFresh

end OutputTrace
end RunarVerification.Stack
