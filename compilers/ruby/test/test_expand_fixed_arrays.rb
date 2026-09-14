# frozen_string_literal: true

require_relative "test_helper"
require "runar_compiler/frontend/parser_ts"
require "runar_compiler/frontend/expand_fixed_arrays"

# Unit tests for the FixedArray expansion pass.  Mirrors the TypeScript
# reference suite at
# +packages/runar-compiler/src/__tests__/03b-expand-fixed-arrays.test.ts+.
class TestExpandFixedArrays < Minitest::Test
  include RunarCompiler::Frontend

  BASIC_ARRAY = <<~TS
    class Boardy extends StatefulSmartContract {
      board: FixedArray<bigint, 3> = [0n, 0n, 0n];

      constructor() {
        super();
      }

      public setZero(v: bigint) {
        this.board[0] = v;
        assert(true);
      }

      public setRuntime(idx: bigint, v: bigint) {
        this.board[idx] = v;
        assert(true);
      }
    }
  TS

  NESTED_ARRAY = <<~TS
    class Grid extends StatefulSmartContract {
      g: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];

      constructor() {
        super();
      }

      public tick() {
        this.g[0][1] = 7n;
        assert(true);
      }
    }
  TS

  OUT_OF_RANGE_LIT = <<~TS
    class Oor extends StatefulSmartContract {
      board: FixedArray<bigint, 3> = [0n, 0n, 0n];

      constructor() {
        super();
      }

      public bad() {
        this.board[5] = 9n;
        assert(true);
      }
    }
  TS

  BAD_LENGTH_INIT = <<~TS
    class BadInit extends StatefulSmartContract {
      board: FixedArray<bigint, 3> = [0n, 0n];

      constructor() {
        super();
      }

      public m() {
        assert(true);
      }
    }
  TS

  SIDE_EFFECT_INDEX = <<~TS
    class SE extends StatefulSmartContract {
      board: FixedArray<bigint, 3> = [0n, 0n, 0n];

      constructor() {
        super();
      }

      public doStuff(base: bigint) {
        this.board[base + 1n] = 5n;
        assert(true);
      }
    }
  TS

  # -----------------------------------------------------------------------
  # Helpers
  # -----------------------------------------------------------------------

  def parse_contract(source, file_name = "Test.runar.ts")
    result = RunarCompiler::Frontend.parse_ts(source, file_name)
    assert_empty result.errors.map(&:format_message), "parse failed"
    refute_nil result.contract, "no contract returned"
    result.contract
  end

  def expand(source)
    contract = parse_contract(source)
    RunarCompiler::Frontend.expand_fixed_arrays(contract)
  end

  def property_names(contract)
    contract.properties.map(&:name)
  end

  def method_body(contract, name)
    m = contract.methods.find { |mm| mm.name == name }
    refute_nil m, "method #{name} not found"
    m.body
  end

  # -----------------------------------------------------------------------
  # Property expansion
  # -----------------------------------------------------------------------

  def test_expands_flat_fixed_array_into_scalar_siblings
    result = expand(BASIC_ARRAY)
    assert_empty result.errors.map(&:format_message), "expand errored"
    assert_equal %w[board__0 board__1 board__2], property_names(result.contract)
    result.contract.properties.each do |p|
      assert_kind_of PrimitiveType, p.type
      assert_equal "bigint", p.type.name
    end
  end

  def test_distributes_array_literal_initializers
    source = <<~TS
      class Init extends StatefulSmartContract {
        board: FixedArray<bigint, 3> = [1n, 2n, 3n];
        constructor() { super(); }
        public m() { assert(true); }
      }
    TS
    result = expand(source)
    assert_empty result.errors.map(&:format_message)
    inits = result.contract.properties.map { |p| p.initializer&.value }
    assert_equal [1, 2, 3], inits
  end

  def test_rejects_initializer_length_mismatch
    result = expand(BAD_LENGTH_INIT)
    assert(result.errors.any? { |e| e.message.include?("does not match") })
  end

  def test_expands_nested_fixed_array_recursively
    result = expand(NESTED_ARRAY)
    assert_empty result.errors.map(&:format_message)
    assert_equal %w[g__0__0 g__0__1 g__1__0 g__1__1], property_names(result.contract)
  end

  # -----------------------------------------------------------------------
  # Literal index access
  # -----------------------------------------------------------------------

  def test_rewrites_literal_index_write_to_direct_property
    result = expand(BASIC_ARRAY)
    assert_empty result.errors.map(&:format_message)
    body = method_body(result.contract, "setZero")
    assign = body.find { |s| s.is_a?(AssignmentStmt) }
    refute_nil assign
    assert_kind_of PropertyAccessExpr, assign.target
    assert_equal "board__0", assign.target.property
  end

  def test_errors_on_out_of_range_literal_index
    result = expand(OUT_OF_RANGE_LIT)
    assert(result.errors.any? { |e| e.message.include?("out of range") })
  end

  # -----------------------------------------------------------------------
  # Runtime index write
  # -----------------------------------------------------------------------

  def test_rewrites_runtime_index_write_to_if_chain
    result = expand(BASIC_ARRAY)
    assert_empty result.errors.map(&:format_message)
    body = method_body(result.contract, "setRuntime")
    first = body[0]
    assert_kind_of IfStmt, first

    # Walk the else chain; should bottom out in an assert(false).
    node = first
    branches = 0
    while node.is_a?(IfStmt)
      branches += 1
      else_list = node.else_ || []
      node = else_list[0]
    end
    assert_equal 3, branches
  end

  def test_hoists_impure_index_expressions
    result = expand(SIDE_EFFECT_INDEX)
    assert_empty result.errors.map(&:format_message)
    body = method_body(result.contract, "doStuff")
    first = body[0]
    assert_kind_of VariableDeclStmt, first
    assert first.name.start_with?("__idx_"), "expected hoisted __idx_*, got #{first.name.inspect}"
  end

  # -----------------------------------------------------------------------
  # Runtime index read
  # -----------------------------------------------------------------------

  def test_rewrites_statement_form_runtime_read_as_fallback_plus_if_chain
    source = <<~TS
      class R extends StatefulSmartContract {
        board: FixedArray<bigint, 3> = [0n, 0n, 0n];
        constructor() { super(); }
        public m(idx: bigint) {
          const v = this.board[idx];
          assert(v == 0n);
        }
      }
    TS
    result = expand(source)
    assert_empty result.errors.map(&:format_message)
    body = method_body(result.contract, "m")

    decl = body[0]
    assert_kind_of VariableDeclStmt, decl
    assert_equal "v", decl.name
    init = decl.init
    assert_kind_of PropertyAccessExpr, init
    assert_equal "board__2", init.property

    if_stmt = body[1]
    assert_kind_of IfStmt, if_stmt
    node = if_stmt
    branches = 0
    while node.is_a?(IfStmt)
      branches += 1
      then0 = node.then[0]
      assert_kind_of AssignmentStmt, then0
      assert_kind_of Identifier, then0.target
      assert_equal "v", then0.target.name
      else_list = node.else_ || []
      node = else_list[0]
    end
    assert_equal 2, branches
  end

  def test_attaches_single_element_synthetic_array_chain_on_flat_leaves
    result = expand(BASIC_ARRAY)
    assert_empty result.errors.map(&:format_message)
    chains = result.contract.properties.map(&:synthetic_array_chain)
    expected = [
      [{ base: "board", index: 0, length: 3 }],
      [{ base: "board", index: 1, length: 3 }],
      [{ base: "board", index: 2, length: 3 }]
    ]
    assert_equal expected, chains
  end

  def test_attaches_two_element_chain_on_2d_fixed_array_leaves
    result = expand(NESTED_ARRAY)
    assert_empty result.errors.map(&:format_message)
    chains = result.contract.properties.map { |p| [p.name, p.synthetic_array_chain] }
    expected = [
      ["g__0__0", [
        { base: "g", index: 0, length: 2 },
        { base: "g__0", index: 0, length: 2 }
      ]],
      ["g__0__1", [
        { base: "g", index: 0, length: 2 },
        { base: "g__0", index: 1, length: 2 }
      ]],
      ["g__1__0", [
        { base: "g", index: 1, length: 2 },
        { base: "g__1", index: 0, length: 2 }
      ]],
      ["g__1__1", [
        { base: "g", index: 1, length: 2 },
        { base: "g__1", index: 1, length: 2 }
      ]]
    ]
    assert_equal expected, chains
  end

  def test_attaches_three_element_chain_on_3d_fixed_array_leaves
    source = <<~TS
      class Cube extends StatefulSmartContract {
        c: FixedArray<FixedArray<FixedArray<bigint, 2>, 2>, 2> = [
          [[0n, 0n], [0n, 0n]],
          [[0n, 0n], [0n, 0n]],
        ];
        constructor() { super(); }
        public m() { assert(true); }
      }
    TS
    result = expand(source)
    assert_empty result.errors.map(&:format_message)
    assert_equal 8, result.contract.properties.length
    leaf = result.contract.properties.find { |p| p.name == "c__1__0__1" }
    refute_nil leaf
    expected = [
      { base: "c", index: 1, length: 2 },
      { base: "c__1", index: 0, length: 2 },
      { base: "c__1__0", index: 1, length: 2 }
    ]
    assert_equal expected, leaf.synthetic_array_chain
  end

  # -----------------------------------------------------------------------
  # End-to-end: TicTacToe v1 and v2 must compile to byte-identical scripts
  # -----------------------------------------------------------------------

  def test_tictactoe_v1_and_v2_compile_to_identical_bytes
    require "runar_compiler/compiler"
    root = File.expand_path("../../..", __dir__)
    v1_path = File.join(root, "examples/ts/tic-tac-toe/TicTacToe.runar.ts")
    v2_path = File.join(root, "examples/ts/tic-tac-toe/TicTacToe.v2.runar.ts")

    v1 = RunarCompiler.compile_from_source(v1_path)
    v2 = RunarCompiler.compile_from_source(v2_path)

    # Byte equality is the acceptance criterion for the FixedArray port —
    # v2 uses FixedArray<bigint, 9> which the expand pass must desugar into
    # the same hand-rolled 9 scalar fields + 9-way dispatch as v1.
    # Byte count updated for #116 (change-output guard adds an OP_IF/ELSE/ENDIF
    # wrapper, +24 bytes). Re-updated for the C20 fix: the 9-way move dispatch
    # ends in `assert(false)`, which the flattening pass previously dropped; the
    # fix re-emits it as `assert(cond0 || ... || cond8)` (+27 bytes). Matches the
    # fixed TS reference fold-ON output. Re-updated for the C17 fix: `not-not-elim`
    # is now guarded on a canonical-bool producer, so the 9 `if (this.cN != 0n)`
    # tests each keep their OP_NOT OP_NOT normalisation (+18 bytes, 9476 -> 9494).
    # Re-updated for NEW-014 (`&&` / `||` now SHORT-CIRCUIT on-chain, 9494 ->
    # 9616): checkWinAfterMove is eight `v_a == player && v_b == player &&
    # v_c == player` chains and `&&` is left-associative, so each stops being a
    # pair of OP_BOOLANDs and becomes nested OP_IF / OP_ELSE branching. The
    # growth IS the fix — OP_BOOLAND is a binary stack op, so both operands had
    # to be evaluated, and an operand the source meant to skip can abort the
    # script. Executed before this number moved, not merely agreed on by seven
    # tiers: audits/v1-review/claude/repro/NEW-014-tictactoe-spends-at-9616.mts
    # plays a full game on the real @bsv/sdk Spend engine and proves moveAndWin
    # on a board with NO line is still REJECTED.
    # Then the Any-S OP_PUSH_TX construction took it 9616 -> 7624: TicTacToe
    # is stateful with six covenant methods, each carrying one
    # preimage-binding blob, so 6 x (760 - 428) = 1992 bytes come off.
    # Then R-010 took it 7624 -> 7778: each of the six methods now
    # authenticates its `_codePart` witness against the preimage's scriptCode,
    # and the six per-method OP_CODESEPARATORs collapse into one at offset 1.
    # Then R-187 took it 7778 -> 7776: the `if` reconcile's `roll` metadata now
    # matches the depth it pushes, so the peephole folds `push 1|2 + roll` into
    # OP_SWAP / OP_ROT.
    assert_equal 7776, v1.script.length / 2, "v1 script must be 7776 bytes"
    assert_equal 7776, v2.script.length / 2, "v2 script must be 7776 bytes"
    assert_equal v1.script, v2.script, "TicTacToe v1 and v2 scripts must be byte-identical"
  end

  def test_still_uses_nested_ternary_chain_for_expression_form_runtime_reads
    source = <<~TS
      class R extends StatefulSmartContract {
        board: FixedArray<bigint, 3> = [0n, 0n, 0n];
        constructor() { super(); }
        public m(idx: bigint): bigint {
          return this.board[idx] + 1n;
        }
      }
    TS
    result = expand(source)
    assert_empty result.errors.map(&:format_message)
    body = method_body(result.contract, "m")
    ret = body.find { |s| s.is_a?(ReturnStmt) }
    refute_nil ret
    assert_kind_of BinaryExpr, ret.value
    assert_kind_of TernaryExpr, ret.value.left
  end

  # R-229 (GK-GAP-008): the expansion pass must not drop a method's `@sighash`
  # directive.
  #
  # The pass rebuilds method nodes while rewriting `this.arr[i]` reads, and a
  # rebuild that lists fields explicitly loses whatever it forgets to list.
  # +sighash_type+ is the field that costs money when it goes: validate has
  # already ACCEPTED the directive by the time this pass runs, so losing it
  # silently reverts the method to ALL|FORKID and commits a different signature
  # hash than the author declared. R-025/R-026 fixed exactly that class of drop,
  # and N-086 found four more fields going the same way in the Zig port.
  #
  # The TS, Python and Zig tiers assert this; ruby, go, rust and java did not.
  def test_preserves_sighash_type_through_expansion
    source = <<~TS
      class Boardy extends StatefulSmartContract {
        board: FixedArray<bigint, 3> = [0n, 0n, 0n];
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash SINGLE|FORKID */
        public bump(): void {
          this.addOutput(1000n, this.board[0], this.board[1], this.board[2], this.n);
        }
      }
    TS

    before = parse_contract(source)
    bump_before = before.methods.find { |m| m.name == "bump" }
    refute_nil bump_before, "no bump method parsed"
    assert_equal 0x43, bump_before.sighash_type,
                 "the directive did not reach the AST -- this test would be vacuous"

    result = expand(source)
    assert_empty result.errors.map(&:format_message)
    # The pass must actually have expanded something, or the assertion below is
    # about a method nothing touched.
    assert_operator result.contract.properties.length, :>=, 3,
                    "expansion did not expand: #{property_names(result.contract).inspect}"

    bump_after = result.contract.methods.find { |m| m.name == "bump" }
    refute_nil bump_after, "bump vanished during expansion"
    assert_equal 0x43, bump_after.sighash_type,
                 "expansion dropped sighash_type -- the method silently reverts to ALL|FORKID"
  end
end
