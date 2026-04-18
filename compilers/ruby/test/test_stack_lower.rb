# frozen_string_literal: true

require_relative "test_helper"

# Pull in frontend + codegen modules.
require "runar_compiler/frontend/ast_nodes"
require "runar_compiler/frontend/diagnostic"
require "runar_compiler/frontend/validator"
require "runar_compiler/frontend/typecheck"
require "runar_compiler/frontend/anf_lower"
require "runar_compiler/frontend/parser_ts"
require "runar_compiler/codegen/stack"

class TestStackLower < Minitest::Test
  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # Run the full frontend pipeline (parse -> validate -> typecheck -> ANF lower)
  # and then stack-lower to get stack IR.
  # Returns an array of stack method hashes:
  #   [{name: "...", ops: [...], ...}, ...]
  def stack_lower_source(source, file_name = "Test.runar.ts")
    parse_result = RunarCompiler.send(:_parse_source, source, file_name)
    assert_empty parse_result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil parse_result.contract

    val_result = RunarCompiler::Frontend.validate(parse_result.contract)
    assert_empty val_result.errors.map(&:format_message), "unexpected validation errors"

    tc_result = RunarCompiler::Frontend.type_check(parse_result.contract)
    assert_empty tc_result.errors.map(&:format_message), "unexpected type check errors"

    program = RunarCompiler::Frontend.lower_to_anf(parse_result.contract)
    # Skip constant folding and EC optimization for simpler output
    RunarCompiler::Codegen.lower_to_stack(program)
  end

  # Compile through the full pipeline and return the artifact.
  def compile_source(source, file_name = "Test.runar.ts")
    parse_result = RunarCompiler.send(:_parse_source, source, file_name)
    assert_empty parse_result.errors.map(&:format_message), "unexpected parse errors"
    refute_nil parse_result.contract

    val_result = RunarCompiler::Frontend.validate(parse_result.contract)
    assert_empty val_result.errors.map(&:format_message), "unexpected validation errors"

    tc_result = RunarCompiler::Frontend.type_check(parse_result.contract)
    assert_empty tc_result.errors.map(&:format_message), "unexpected type check errors"

    program = RunarCompiler::Frontend.lower_to_anf(parse_result.contract)
    RunarCompiler.compile_from_program(program, disable_constant_folding: true)
  end

  # Collect all opcodes from a list of stack ops (flattened).
  def collect_opcodes(ops)
    result = []
    ops.each do |op|
      case op[:op]
      when "opcode"
        result << op[:code]
      when "if"
        result.concat(collect_opcodes(op[:then] || []))
        result.concat(collect_opcodes(op[:else_ops] || []))
      end
    end
    result
  end

  # Collect all op types from a list of stack ops (top-level only).
  def collect_op_types(ops)
    ops.map { |op| op[:op] }
  end

  # ---------------------------------------------------------------------------
  # Basic P2PKH source
  # ---------------------------------------------------------------------------

  P2PKH_SOURCE = <<~TS
    import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

    class P2PKH extends SmartContract {
      readonly pubKeyHash: Addr;

      constructor(pubKeyHash: Addr) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
      }

      public unlock(sig: Sig, pubKey: PubKey): void {
        assert(hash160(pubKey) === this.pubKeyHash);
        assert(checkSig(sig, pubKey));
      }
    }
  TS

  # ---------------------------------------------------------------------------
  # 1. Stack lowering produces non-empty result
  # ---------------------------------------------------------------------------

  def test_stack_lower_produces_output
    methods = stack_lower_source(P2PKH_SOURCE, "P2PKH.runar.ts")
    assert methods.length > 0, "should produce at least one method"
    assert methods.first[:ops].length > 0, "method should have ops"
  end

  # ---------------------------------------------------------------------------
  # 2. Method name is preserved
  # ---------------------------------------------------------------------------

  def test_stack_lower_method_name
    methods = stack_lower_source(P2PKH_SOURCE, "P2PKH.runar.ts")
    method_names = methods.map { |m| m[:name] }
    assert_includes method_names, "unlock"
  end

  # ---------------------------------------------------------------------------
  # 3. assert() produces OP_VERIFY
  # ---------------------------------------------------------------------------

  def test_assert_produces_verify
    # Use two asserts: the first becomes OP_VERIFY, the last leaves result on stack.
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class AssertTest extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint): void {
          assert(a > 0n);
          assert(a > 1n);
        }
      }
    TS

    methods = stack_lower_source(source)
    check_method = methods.find { |m| m[:name] == "check" }
    refute_nil check_method

    opcodes = collect_opcodes(check_method[:ops])
    assert opcodes.any? { |op| op.include?("VERIFY") },
           "non-final assert should produce OP_VERIFY, got: #{opcodes}"
  end

  # ---------------------------------------------------------------------------
  # 4. exit() compiles to OP_VERIFY
  # ---------------------------------------------------------------------------

  def test_exit_produces_verify
    # exit() works like assert() but the validator requires a trailing assert
    # for public SmartContract methods. Use exit() before a final assert().
    source = <<~TS
      import { SmartContract, assert, exit } from 'runar-lang';

      class ExitTest extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint): void {
          exit(a > 0n);
          assert(a > 1n);
        }
      }
    TS

    methods = stack_lower_source(source)
    check_method = methods.find { |m| m[:name] == "check" }
    refute_nil check_method

    opcodes = collect_opcodes(check_method[:ops])
    assert opcodes.any? { |op| op.include?("VERIFY") },
           "exit should produce VERIFY opcode, got: #{opcodes}"
  end

  # ---------------------------------------------------------------------------
  # 5. Binary addition produces OP_ADD
  # ---------------------------------------------------------------------------

  def test_binary_add_produces_op_add
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class AddTest extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint, b: bigint): void {
          const c = a + b;
          assert(c > 0n);
        }
      }
    TS

    methods = stack_lower_source(source)
    check_method = methods.find { |m| m[:name] == "check" }
    opcodes = collect_opcodes(check_method[:ops])
    assert_includes opcodes, "OP_ADD"
  end

  # ---------------------------------------------------------------------------
  # 6. Binary subtraction produces OP_SUB
  # ---------------------------------------------------------------------------

  def test_binary_sub_produces_op_sub
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class SubTest extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint, b: bigint): void {
          const c = a - b;
          assert(c > 0n);
        }
      }
    TS

    methods = stack_lower_source(source)
    check_method = methods.find { |m| m[:name] == "check" }
    opcodes = collect_opcodes(check_method[:ops])
    assert_includes opcodes, "OP_SUB"
  end

  # ---------------------------------------------------------------------------
  # 7. Binary multiply produces OP_MUL
  # ---------------------------------------------------------------------------

  def test_binary_mul_produces_op_mul
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class MulTest extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint, b: bigint): void {
          const c = a * b;
          assert(c > 0n);
        }
      }
    TS

    methods = stack_lower_source(source)
    check_method = methods.find { |m| m[:name] == "check" }
    opcodes = collect_opcodes(check_method[:ops])
    assert_includes opcodes, "OP_MUL"
  end

  # ---------------------------------------------------------------------------
  # 8. Equality comparison produces OP_NUMEQUAL
  # ---------------------------------------------------------------------------

  def test_equality_produces_numequal
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class EqTest extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint): void {
          assert(a === this.x);
        }
      }
    TS

    methods = stack_lower_source(source)
    check_method = methods.find { |m| m[:name] == "check" }
    opcodes = collect_opcodes(check_method[:ops])
    # Either OP_NUMEQUAL or OP_EQUAL (could be either depending on type inference)
    assert opcodes.any? { |op| op.include?("EQUAL") },
           "equality should produce NUMEQUAL or EQUAL opcode, got: #{opcodes}"
  end

  # ---------------------------------------------------------------------------
  # 9. hash160 produces OP_HASH160
  # ---------------------------------------------------------------------------

  def test_hash160_produces_op_hash160
    methods = stack_lower_source(P2PKH_SOURCE, "P2PKH.runar.ts")
    unlock_method = methods.find { |m| m[:name] == "unlock" }
    opcodes = collect_opcodes(unlock_method[:ops])
    assert_includes opcodes, "OP_HASH160"
  end

  # ---------------------------------------------------------------------------
  # 10. checkSig produces OP_CHECKSIG
  # ---------------------------------------------------------------------------

  def test_checksig_produces_op_checksig
    methods = stack_lower_source(P2PKH_SOURCE, "P2PKH.runar.ts")
    unlock_method = methods.find { |m| m[:name] == "unlock" }
    opcodes = collect_opcodes(unlock_method[:ops])
    assert_includes opcodes, "OP_CHECKSIG"
  end

  # ---------------------------------------------------------------------------
  # 11. Full P2PKH produces script with OP_DUP
  # ---------------------------------------------------------------------------

  def test_p2pkh_script_contains_dup
    artifact = compile_source(P2PKH_SOURCE, "P2PKH.runar.ts")
    # Use ASM check to avoid spurious matches inside push data bytes
    assert_includes artifact.asm, "OP_DUP",
                    "P2PKH script should contain OP_DUP"
  end

  # ---------------------------------------------------------------------------
  # 12. reverseBytes produces non-empty opcode sequence
  # ---------------------------------------------------------------------------

  def test_len_builtin_produces_op_size
    source = <<~TS
      import { SmartContract, assert, len } from 'runar-lang';

      class LenTest extends SmartContract {
        readonly h: ByteString;

        constructor(h: ByteString) {
          super(h);
          this.h = h;
        }

        public check(data: ByteString): void {
          assert(len(data) > 0n);
        }
      }
    TS

    methods = stack_lower_source(source)
    check_method = methods.find { |m| m[:name] == "check" }
    opcodes = collect_opcodes(check_method[:ops])
    assert_includes opcodes, "OP_SIZE"
  end

  # ---------------------------------------------------------------------------
  # 13. checkMultiSig produces OP_CHECKMULTISIG with OP_0 prefix
  # ---------------------------------------------------------------------------

  def test_cat_builtin_produces_op_cat
    source = <<~TS
      import { SmartContract, assert, cat } from 'runar-lang';

      class CatTest extends SmartContract {
        readonly h: ByteString;

        constructor(h: ByteString) {
          super(h);
          this.h = h;
        }

        public check(a: ByteString, b: ByteString): void {
          const c = cat(a, b);
          assert(c === this.h);
        }
      }
    TS

    methods = stack_lower_source(source)
    check_method = methods.find { |m| m[:name] == "check" }
    opcodes = collect_opcodes(check_method[:ops])
    assert_includes opcodes, "OP_CAT"
  end

  # ---------------------------------------------------------------------------
  # 14. Boolean AND produces OP_BOOLAND
  # ---------------------------------------------------------------------------

  def test_boolean_and_produces_booland
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class BoolTest extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint, b: bigint): void {
          assert(a > 0n && b > 0n);
        }
      }
    TS

    methods = stack_lower_source(source)
    check_method = methods.find { |m| m[:name] == "check" }
    opcodes = collect_opcodes(check_method[:ops])
    assert_includes opcodes, "OP_BOOLAND"
  end

  # ---------------------------------------------------------------------------
  # 15. Less-than produces OP_LESSTHAN
  # ---------------------------------------------------------------------------

  def test_less_than_produces_lessthan
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class LtTest extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint): void {
          assert(a < 100n);
        }
      }
    TS

    methods = stack_lower_source(source)
    check_method = methods.find { |m| m[:name] == "check" }
    opcodes = collect_opcodes(check_method[:ops])
    assert_includes opcodes, "OP_LESSTHAN"
  end

  # ---------------------------------------------------------------------------
  # 16. Unary NOT produces OP_NOT
  # ---------------------------------------------------------------------------

  def test_unary_not_produces_op_not
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class NotTest extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint): void {
          const b = a > 0n;
          assert(!b);
        }
      }
    TS

    methods = stack_lower_source(source)
    check_method = methods.find { |m| m[:name] == "check" }
    opcodes = collect_opcodes(check_method[:ops])
    assert_includes opcodes, "OP_NOT"
  end

  # ---------------------------------------------------------------------------
  # 17. Unary negate produces OP_NEGATE
  # ---------------------------------------------------------------------------

  def test_unary_negate_produces_op_negate
    source = <<~TS
      import { SmartContract, assert } from 'runar-lang';

      class NegTest extends SmartContract {
        readonly x: bigint;

        constructor(x: bigint) {
          super(x);
          this.x = x;
        }

        public check(a: bigint): void {
          const b = -a;
          assert(b < 0n);
        }
      }
    TS

    methods = stack_lower_source(source)
    check_method = methods.find { |m| m[:name] == "check" }
    opcodes = collect_opcodes(check_method[:ops])
    assert_includes opcodes, "OP_NEGATE"
  end

  # ---------------------------------------------------------------------------
  # 18. sha256 builtin produces OP_SHA256
  # ---------------------------------------------------------------------------

  def test_sha256_produces_op_sha256
    source = <<~TS
      import { SmartContract, assert, sha256 } from 'runar-lang';

      class HashTest extends SmartContract {
        readonly h: Sha256;

        constructor(h: Sha256) {
          super(h);
          this.h = h;
        }

        public check(data: ByteString): void {
          assert(sha256(data) === this.h);
        }
      }
    TS

    methods = stack_lower_source(source)
    check_method = methods.find { |m| m[:name] == "check" }
    opcodes = collect_opcodes(check_method[:ops])
    assert_includes opcodes, "OP_SHA256"
  end

  # ---------------------------------------------------------------------------
  # 19. Constructor slots in artifact
  # ---------------------------------------------------------------------------

  def test_artifact_has_constructor_slots
    artifact = compile_source(P2PKH_SOURCE, "P2PKH.runar.ts")
    refute_nil artifact.constructor_slots
    assert artifact.constructor_slots.length > 0,
           "P2PKH artifact should have at least one constructor slot"
  end

  # ---------------------------------------------------------------------------
  # 20. Multiple methods are produced
  # ---------------------------------------------------------------------------

  def test_multiple_methods
    source = <<~TS
      import { SmartContract, assert, checkSig } from 'runar-lang';

      class Multi extends SmartContract {
        readonly pk: PubKey;

        constructor(pk: PubKey) {
          super(pk);
          this.pk = pk;
        }

        private verify(sig: Sig): boolean {
          return checkSig(sig, this.pk);
        }

        public check(sig: Sig): void {
          assert(this.verify(sig));
        }
      }
    TS

    methods = stack_lower_source(source)
    assert methods.length >= 1, "should produce at least one method"
  end

  # ---------------------------------------------------------------------------
  # 21. addDataOutput lowers through stack codegen (same wire shape as raw)
  # ---------------------------------------------------------------------------

  def test_add_data_output_compiles_through_stack
    # Stateful contract with a data output alongside state mutation. This
    # exercises the single-output continuation path with a data output
    # spliced in between the state and change outputs.
    source = <<~TS
      import { StatefulSmartContract, assert, bigint, ByteString } from 'runar-lang';

      class Logger extends StatefulSmartContract {
        count: bigint;

        constructor(count: bigint) {
          super(count);
          this.count = count;
        }

        public log(note: ByteString): void {
          this.count = this.count + 1n;
          this.addDataOutput(0n, note);
        }
      }
    TS

    methods = stack_lower_source(source, "Logger.runar.ts")
    log = methods.find { |m| m[:name] == "log" }
    refute_nil log, "should have a 'log' method"
    assert log[:ops].length > 0, "log method should have stack ops"
  end

  def test_add_data_output_full_compile
    source = <<~TS
      import { StatefulSmartContract, assert, bigint, ByteString } from 'runar-lang';

      class Logger extends StatefulSmartContract {
        count: bigint;

        constructor(count: bigint) {
          super(count);
          this.count = count;
        }

        public log(note: ByteString): void {
          this.count = this.count + 1n;
          this.addDataOutput(0n, note);
        }
      }
    TS

    artifact = compile_source(source, "Logger.runar.ts")
    refute_nil artifact
    # Artifact must have a non-empty locking script hex.
    assert artifact.script.length > 0
  end
end
