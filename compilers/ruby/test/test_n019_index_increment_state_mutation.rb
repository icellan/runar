# frozen_string_literal: true

require_relative "test_helper"
require "runar_compiler/frontend/parser_ts"
require "runar_compiler/frontend/expand_fixed_arrays"
require "runar_compiler/frontend/anf_lower"

# N-019 (port of R-018, Rust): +this.arr[i]++ must be recognised as a state
# mutation.
#
# Two blind spots, both keyed on the operand of an increment/decrement being a
# bare +PropertyAccessExpr+:
#
#   1. Lowering -- +lower_increment_expr+ / +lower_decrement_expr+ in
#      +anf_lower.rb+ emit an +update_prop+ ONLY when the operand is a
#      +PropertyAccessExpr+.  After +expand_fixed_arrays+ has run,
#      +this.board[i]+ (runtime index) is a ternary read chain over the expanded
#      slots, so the new value is computed and DISCARDED -- the mutation
#      vanishes.
#
#   2. Mutates-state recursion -- +_expr_mutates_state+ in +anf_lower.rb+ has
#      the identical guard, so the method is classified terminal and NO
#      continuation assertion is injected at all: a method that mutates state
#      emits nothing binding that mutation (no +get_state_script+, no output
#      covenant, no continuation params).
#
# The root cause is neither site: pass 3b rewrites only the increment's OPERAND,
# leaving a +TernaryExpr+ where both sites expect a property access.
#
# The control below (+this.count++, a plain scalar property) is the shape that
# already works and must stay unchanged -- it discriminates the two paths.
class TestN019IndexIncrementStateMutation < Minitest::Test
  include RunarCompiler::Frontend

  # Runtime index (+i+ is a parameter), so expand-fixed-arrays cannot fold
  # +this.board[i]+ to a single slot -- it becomes a dispatch/ternary chain.
  INDEX_INCREMENT = <<~TS
    class BumpIncr extends StatefulSmartContract {
      board: FixedArray<bigint, 3> = [0n, 0n, 0n];

      constructor() {
        super();
      }

      public bump(i: bigint) {
        this.board[i]++;
      }
    }
  TS

  INDEX_DECREMENT = <<~TS
    class BumpDecr extends StatefulSmartContract {
      board: FixedArray<bigint, 3> = [0n, 0n, 0n];

      constructor() {
        super();
      }

      public bump(i: bigint) {
        this.board[i]--;
      }
    }
  TS

  # The hand-written form +this.board[i]++ must be equivalent to.
  INDEX_EXPLICIT_ADD = <<~TS
    class BumpIncr extends StatefulSmartContract {
      board: FixedArray<bigint, 3> = [0n, 0n, 0n];

      constructor() {
        super();
      }

      public bump(i: bigint) {
        this.board[i] = this.board[i] + 1n;
      }
    }
  TS

  # Literal index -- already folds to +this.board__0+; must be byte-identical.
  LITERAL_INDEX_INCREMENT = <<~TS
    class BumpLit extends StatefulSmartContract {
      board: FixedArray<bigint, 3> = [0n, 0n, 0n];

      constructor() {
        super();
      }

      public bump(i: bigint) {
        this.board[0]++;
      }
    }
  TS

  LITERAL_INDEX_EXPLICIT = <<~TS
    class BumpLit extends StatefulSmartContract {
      board: FixedArray<bigint, 3> = [0n, 0n, 0n];

      constructor() {
        super();
      }

      public bump(i: bigint) {
        this.board[0] = this.board[0] + 1n;
      }
    }
  TS

  # The most plausible real-world shape: a histogram bump inside a loop.
  INDEX_INCREMENT_IN_LOOP = <<~TS
    class BumpLoop extends StatefulSmartContract {
      board: FixedArray<bigint, 3> = [0n, 0n, 0n];

      constructor() {
        super();
      }

      public bumpAll() {
        for (let i: bigint = 0n; i < 3n; i++) {
          this.board[i]++;
        }
      }
    }
  TS

  # Control: the already-working shape.  A plain mutable scalar property.
  PLAIN_PROP_INCREMENT = <<~TS
    class BumpProp extends StatefulSmartContract {
      count: bigint = 0n;

      constructor() {
        super();
      }

      public bump(i: bigint) {
        this.count++;
      }
    }
  TS

  # -------------------------------------------------------------------
  # Helpers
  # -------------------------------------------------------------------

  def parse_contract(src)
    result = RunarCompiler::Frontend.parse_ts(src, "Test.runar.ts")
    assert_empty result.errors, "parse errors: #{result.errors.inspect}"
    refute_nil result.contract
    result.contract
  end

  # Parse + run pass 3b, exactly as the compiler does before ANF lowering.
  def expanded(src)
    result = RunarCompiler::Frontend.expand_fixed_arrays(parse_contract(src))
    assert_empty result.errors, "expand-fixed-arrays errors: #{result.errors.inspect}"
    result.contract
  end

  def anf_method(src, method)
    program = RunarCompiler::Frontend.lower_to_anf(expanded(src))
    m = program.methods.find { |mm| mm.name == method }
    refute_nil m, "method #{method} not found"
    m
  end

  # Every +update_prop+ name anywhere, including inside +if+ arms and loops.
  def update_prop_names(bindings, out)
    bindings.each do |b|
      case b.value.kind
      when "update_prop" then out << b.value.name
      when "if"
        update_prop_names(b.value.then || [], out)
        update_prop_names(b.value.else_ || [], out)
      when "loop"
        update_prop_names(b.value.body || [], out)
      end
    end
    out
  end

  def updated_props(src, method)
    update_prop_names(anf_method(src, method).body, [])
  end

  def param_names(src, method)
    anf_method(src, method).params.map(&:name)
  end

  # The continuation covenant itself: the state script the spend is bound to.
  def kinds(bindings, out)
    bindings.each do |b|
      out << b.value.kind
      kinds(b.value.then || [], out) if b.value.kind == "if"
      kinds(b.value.else_ || [], out) if b.value.kind == "if"
      kinds(b.value.body || [], out) if b.value.kind == "loop"
    end
    out
  end

  def has_state_continuation?(src, method)
    kinds(anf_method(src, method).body, []).include?("get_state_script")
  end

  # Structural, address-free rendering of an ANF tree.  +inspect+ on the raw
  # structs embeds object ids, which differ between two equivalent programs.
  def structural(obj)
    case obj
    when Struct then obj.to_h.transform_values { |v| structural(v) }
    when Array then obj.map { |v| structural(v) }
    when Hash then obj.transform_values { |v| structural(v) }
    when RunarCompiler::IR::ANFValue
      obj.instance_variables.to_h { |iv| [iv.to_s, structural(obj.instance_variable_get(iv))] }
    else obj
    end
  end

  def anf_json(src)
    structural(RunarCompiler::Frontend.lower_to_anf(expanded(src))).inspect
  end

  # -------------------------------------------------------------------
  # Control -- the shape that already works.  Passes before AND after.
  # -------------------------------------------------------------------

  def test_control_plain_property_increment_updates_state
    props = updated_props(PLAIN_PROP_INCREMENT, "bump")
    assert_includes props, "count",
                    "control regressed: `this.count++` produced no update_prop; got #{props.inspect}"
    assert has_state_continuation?(PLAIN_PROP_INCREMENT, "bump"),
           "control regressed: `this.count++` emitted no get_state_script"
  end

  # -------------------------------------------------------------------
  # Half 1 -- lowering: the increment through an index must update_prop.
  # -------------------------------------------------------------------

  def test_index_increment_emits_update_prop
    props = updated_props(INDEX_INCREMENT, "bump")
    refute_empty props,
                 "`this.board[i]++` produced NO update_prop at all -- the mutation was computed and discarded"
    assert props.any? { |p| p.start_with?("board") },
           "`this.board[i]++` produced no update_prop for a board slot; got #{props.inspect}"
  end

  def test_index_decrement_emits_update_prop
    props = updated_props(INDEX_DECREMENT, "bump")
    assert props.any? { |p| p.start_with?("board") },
           "`this.board[i]--` produced no update_prop for a board slot; got #{props.inspect}"
  end

  # -------------------------------------------------------------------
  # Half 2 -- the method is NOT terminal: a continuation covenant exists.
  # -------------------------------------------------------------------

  def test_index_increment_is_a_state_mutation
    assert has_state_continuation?(INDEX_INCREMENT, "bump"),
           "`this.board[i]++` emitted no get_state_script: NOTHING binds the spending path"
  end

  def test_index_decrement_is_a_state_mutation
    assert has_state_continuation?(INDEX_DECREMENT, "bump"),
           "`this.board[i]--` emitted no get_state_script"
  end

  def test_index_increment_inside_a_loop_is_a_state_mutation
    props = updated_props(INDEX_INCREMENT_IN_LOOP, "bumpAll")
    assert props.any? { |p| p.start_with?("board") },
           "`this.board[i]++` inside a for-loop produced no update_prop; got #{props.inspect}"
    assert has_state_continuation?(INDEX_INCREMENT_IN_LOOP, "bumpAll"),
           "loop-bumping method emitted no get_state_script"
  end

  # -------------------------------------------------------------------
  # The desugar must be FAITHFUL, not merely present.
  # -------------------------------------------------------------------

  def test_index_increment_lowers_identically_to_the_explicit_add
    assert_equal anf_json(INDEX_EXPLICIT_ADD), anf_json(INDEX_INCREMENT),
                 "`this.board[i]++` must lower identically to `this.board[i] = this.board[i] + 1n`"
  end

  def test_literal_index_increment_is_unchanged
    assert_equal anf_json(LITERAL_INDEX_EXPLICIT), anf_json(LITERAL_INDEX_INCREMENT),
                 "literal-index `this.board[0]++` must stay byte-identical to the explicit form"
  end

  def test_index_increment_method_gets_continuation_params
    assert_equal param_names(PLAIN_PROP_INCREMENT, "bump"), param_names(INDEX_INCREMENT, "bump"),
                 "`this.board[i]++` must receive the same continuation params as `this.count++`"
  end

  # -------------------------------------------------------------------
  # Expression position cannot write back through the dispatch chain.
  # -------------------------------------------------------------------

  def test_index_increment_in_expression_position_is_rejected
    # The TS surface parser rejects an assignment whose value is a postfix
    # increment, so drive the AST directly: an assignment whose value is an
    # IncrementExpr over an IndexAccessExpr.
    contract = parse_contract(INDEX_INCREMENT)
    method = contract.methods.find { |m| m.name == "bump" }
    incr = method.body[0].expr
    method.body = [
      AssignmentStmt.new(
        target: PropertyAccessExpr.new(property: "board__0"),
        value: incr,
        source_location: method.body[0].source_location
      )
    ]
    result = RunarCompiler::Frontend.expand_fixed_arrays(contract)
    refute_empty result.errors,
                 "`x = this.board[i]++` was accepted; the array write is silently dropped"
  end
end
