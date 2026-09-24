# frozen_string_literal: true

require_relative 'test_helper'

# The Go surface parser is required LAZILY, by
# RunarCompiler::Compiler#_parse_source, only once a `.runar.go` source is
# actually parsed. Tests that read its constants rather than parsing something
# therefore depend on some earlier test having triggered that require — and
# Minitest randomises order, so `test_cast_types_and_builtin_map_are_disjoint`
# errored with `uninitialized constant GO_CAST_TYPES` on some seeds and passed
# on others. It is the guard for a fund bug (a hash spelling resolving as a
# cast, so its opcode vanishes), so it has to run every time.
require 'runar_compiler/frontend/parser_go'

class TestParserGo < Minitest::Test
  def parse(source, file_name = 'Test.runar.go')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  def test_bigint_big_maps_to_bigint
    # runar.BigintBig is the big.Int-backed alias used by Go-mock helpers for
    # arbitrary-precision arithmetic. Script semantics are identical to
    # runar.Bigint, so the DSL parser must map both to the bigint primitive.
    source = <<~GO
      package contract

      import "github.com/icellan/runar/packages/runar-go"

      type BigMath struct {
        runar.SmartContract
        Target runar.BigintBig `runar:"readonly"`
      }

      func (c *BigMath) Check(a runar.Bigint, b runar.BigintBig) {
        runar.Assert(a + b == c.Target)
      }
    GO

    result = parse(source, 'BigMath.runar.go')
    assert_empty result.errors.map(&:format_message), "should parse without errors"
    refute_nil result.contract

    target = result.contract.properties.find { |p| p.name == 'target' }
    refute_nil target, "expected 'target' property"
    assert_instance_of RunarCompiler::Frontend::PrimitiveType, target.type
    assert_equal 'bigint', target.type.name

    method = result.contract.methods.first
    param_b = method.params[1]
    assert_instance_of RunarCompiler::Frontend::PrimitiveType, param_b.type
    assert_equal 'bigint', param_b.type.name
  end

  def test_bytestring_literal_hex_encodes_raw_bytes
    # runar.ByteString("\x00\x6a") emits a ByteStringLiteral whose value is the
    # hex encoding of the two raw literal bytes.
    source = <<~GO
      package contract

      import "github.com/icellan/runar/packages/runar-go"

      type LitDemo struct {
        runar.SmartContract
        Expected runar.ByteString `runar:"readonly"`
      }

      func (c *LitDemo) Check() {
        runar.Assert(runar.ByteString("\\x00\\x6a") == c.Expected)
      }
    GO

    result = parse(source, 'LitDemo.runar.go')
    assert_empty result.errors.map(&:format_message), "should parse without errors"
    refute_nil result.contract
    method = result.contract.methods.first

    lit = find_bytestring_literal(method.body)
    refute_nil lit, "expected a ByteStringLiteral in method body"
    assert_equal '006a', lit.value
  end

  def test_bytestring_of_variable_unwraps
    # runar.ByteString(variable) is a no-op type conversion; the inner
    # identifier must flow through unchanged.
    source = <<~GO
      package contract

      import "github.com/icellan/runar/packages/runar-go"

      type VarDemo struct {
        runar.SmartContract
        Expected runar.ByteString `runar:"readonly"`
      }

      func (c *VarDemo) Check(data runar.ByteString) {
        runar.Assert(runar.ByteString(data) == c.Expected)
      }
    GO

    result = parse(source, 'VarDemo.runar.go')
    assert_empty result.errors.map(&:format_message), "should parse without errors"
    refute_nil result.contract

    assert contains_plain_data_ident?(result.contract.methods.first.body),
           "runar.ByteString(data) should unwrap to identifier 'data'"
  end

  # ---------------------------------------------------------------------------
  # F1 -- the Go surface spells a type conversion and a builtin call
  # identically, so a name in BOTH tables silently becomes whichever branch runs
  # first. `Sha256` and `Ripemd160` were in both, the cast branch ran first, and
  # `runar.Sha256(preimage)` unwrapped to its own argument: the hash opcode was
  # never emitted and `assert(sha256(x) == digest)` shipped as
  # `assert(x == digest)`.
  #
  # Resolution: in CALL position the FUNCTION wins. These tests hold the two
  # tables disjoint and pin the resolution for each hash spelling, so the next
  # name that is both a type and a function fails here instead of on chain.
  # ---------------------------------------------------------------------------

  def test_cast_types_and_builtin_map_are_disjoint
    cast = RunarCompiler::Frontend::GO_CAST_TYPES
    builtins = RunarCompiler::Frontend::GO_BUILTIN_MAP
    both = cast.select { |n| builtins.key?(n) }.sort
    assert_empty both,
                 "these names are BOTH a Go-surface cast type and a Go-surface builtin: " \
                 "#{both.join(', ')}. The cast branch runs first, so every call to them " \
                 "compiles to an identity binding and its opcode disappears. Remove them " \
                 "from GO_CAST_TYPES -- a cast to a ByteString subtype is a no-op, a " \
                 "vanished hash is a fund bug."
  end

  def test_hash_spellings_parse_as_calls_not_casts
    %w[Sha256 Ripemd160 Sha256Hash Hash160 Hash256].each do |spelling|
      source = <<~GO
        package contract

        import "github.com/icellan/runar/packages/runar-go"

        type HashSpelling struct {
          runar.SmartContract
          Expected runar.ByteString `runar:"readonly"`
        }

        func (c *HashSpelling) Unlock(data runar.ByteString) {
          h := runar.#{spelling}(data)
          runar.Assert(h == c.Expected)
        }
      GO

      result = parse(source, 'HashSpelling.runar.go')
      assert_empty result.errors.map(&:format_message), "runar.#{spelling} should parse"

      decl = result.contract.methods[0].body[0]
      assert_instance_of RunarCompiler::Frontend::CallExpr, decl.init,
                         "runar.#{spelling}(data) parsed as a #{decl.init.class}, not a " \
                         "CallExpr -- the call was unwrapped to its own argument and the " \
                         "opcode will never be emitted."
      assert_equal RunarCompiler::Frontend::GO_BUILTIN_MAP[spelling], decl.init.callee.name
    end
  end

  # ---------------------------------------------------------------------------
  # F-010: a method is a contract method only if its receiver IS the contract.
  # This tier ignored the receiver type (an exported method on ANY type became
  # a PUBLIC entry point) and took the LAST struct as the contract, replacing
  # its properties. The rule (user decision R9), diagnostics verbatim in all
  # seven tiers:
  #   - the contract is THE struct embedding a runar base; others are ignored;
  #   - zero or several such structs refuse the file;
  #   - a method whose receiver (value or pointer) is another type refuses it;
  #   - a free function, exported or not, is a private helper.
  # Proves: this tier's .runar.go diagnostics and method set per shape.
  # Does NOT prove: the other tiers, or anything on chain.
  # ---------------------------------------------------------------------------

  F010_PRELUDE = "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n"
  F010_GUARDED = "\ntype Guarded struct {\n\trunar.SmartContract\n\tPubKey runar.PubKey `runar:\"readonly\"`\n}\n" \
                 "\nfunc (c *Guarded) Unlock(sig runar.Sig) {\n\trunar.Assert(runar.CheckSig(sig, c.PubKey))\n}\n"
  F010_RECEIVER_ERROR = "method 'Drain' has receiver type 'Unrelated', not the contract type 'Guarded'; " \
                        'methods on other types are not allowed'

  def f010_unrelated(recv)
    "\ntype Unrelated struct{}\n\nfunc (#{recv}) Drain(amount runar.Bigint) {\n\trunar.Assert(true)\n}\n"
  end

  def f010_errors(src)
    parse(src, 'Guarded.runar.go').errors.select { |e| e.severity == 'error' }.map(&:message)
  end

  def f010_methods(src)
    parse(src, 'Guarded.runar.go').contract.methods.map { |m| "#{m.name}(#{m.visibility})" }
  end

  def test_f010_foreign_receiver_refused
    [
      F010_PRELUDE + F010_GUARDED + f010_unrelated('u Unrelated'),
      F010_PRELUDE + F010_GUARDED + f010_unrelated('u *Unrelated'),
      F010_PRELUDE + f010_unrelated('u Unrelated') + F010_GUARDED,
      F010_PRELUDE + f010_unrelated('u *Unrelated') + F010_GUARDED,
      F010_PRELUDE + F010_GUARDED + "\nfunc (u Unrelated) Drain(amount runar.Bigint) {\n\trunar.Assert(true)\n}\n"
    ].each_with_index do |src, i|
      assert_equal [F010_RECEIVER_ERROR], f010_errors(src), "case #{i}"
    end
  end

  def test_f010_contract_receivers_kept
    src = F010_PRELUDE + F010_GUARDED + "\nfunc (c Guarded) Drain(amount runar.Bigint) {\n\trunar.Assert(amount > 0)\n}\n"
    assert_equal [], f010_errors(src)
    assert_equal ['unlock(public)', 'drain(public)'], f010_methods(src)
  end

  def test_f010_exported_free_function_is_private_helper
    src = F010_PRELUDE + F010_GUARDED + "\nfunc Drain(amount runar.Bigint) {\n\trunar.Assert(true)\n}\n"
    assert_equal [], f010_errors(src)
    assert_equal ['unlock(public)', 'drain(private)'], f010_methods(src)
  end

  def test_f010_helper_struct_ignored
    helper = "\ntype Helper struct {\n\tAmount runar.Bigint\n}\n"
    [F010_PRELUDE + F010_GUARDED + helper, F010_PRELUDE + helper + F010_GUARDED].each do |src|
      result = parse(src, 'Guarded.runar.go')
      assert_empty result.errors.map(&:format_message)
      assert_equal 'Guarded', result.contract.name
      assert_equal ['pubKey'], result.contract.properties.map(&:name)
    end
  end

  def test_f010_no_contract_struct
    src = F010_PRELUDE + "\ntype Helper struct {\n\tAmount runar.Bigint\n}\n"
    assert_equal ['no Rúnar contract struct found in Go source'], f010_errors(src)
  end

  def test_f010_two_contract_structs
    src = F010_PRELUDE + F010_GUARDED + "\ntype Other struct {\n\trunar.StatefulSmartContract\n\tCount runar.Bigint\n}\n"
    assert_equal [
      "multiple Rúnar contract structs found in Go source: 'Guarded' and 'Other'; " \
      'exactly one struct may embed runar.SmartContract, runar.StatefulSmartContract or runar.UnsafeSmartContract'
    ], f010_errors(src)
  end

  private

  def find_bytestring_literal(stmts)
    stmts.each do |s|
      next unless s.is_a?(RunarCompiler::Frontend::ExpressionStmt)

      hit = walk_for_bs_lit(s.expr)
      return hit unless hit.nil?
    end
    nil
  end

  def walk_for_bs_lit(expr)
    case expr
    when RunarCompiler::Frontend::ByteStringLiteral then expr
    when RunarCompiler::Frontend::CallExpr
      expr.args.each do |a|
        hit = walk_for_bs_lit(a)
        return hit unless hit.nil?
      end
      nil
    when RunarCompiler::Frontend::BinaryExpr
      walk_for_bs_lit(expr.left) || walk_for_bs_lit(expr.right)
    end
  end

  def contains_plain_data_ident?(stmts)
    stmts.any? do |s|
      next false unless s.is_a?(RunarCompiler::Frontend::ExpressionStmt)
      walk_for_data_ident(s.expr)
    end
  end

  def walk_for_data_ident(expr)
    case expr
    when RunarCompiler::Frontend::Identifier
      expr.name == 'data'
    when RunarCompiler::Frontend::BinaryExpr
      walk_for_data_ident(expr.left) || walk_for_data_ident(expr.right)
    when RunarCompiler::Frontend::CallExpr
      # Must NOT be a lingering byteString(data) call masquerading as unwrap.
      if expr.callee.is_a?(RunarCompiler::Frontend::Identifier) && expr.callee.name == 'byteString'
        return false
      end
      expr.args.any? { |a| walk_for_data_ident(a) } || walk_for_data_ident(expr.callee)
    else
      false
    end
  end
end
