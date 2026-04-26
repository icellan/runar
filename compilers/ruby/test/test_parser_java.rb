# frozen_string_literal: true

require_relative "test_helper"

# Tests for the .runar.java parser.
#
# The Ruby Java parser follows the authoritative surface spec in
# compilers/java/src/main/java/runar/compiler/frontend/JavaParser.java
# and mirrors the worked examples in JavaParserTest.java.

class TestParserJava < Minitest::Test
  # Eager-load the parser so the Frontend module's AST classes are defined
  # before we reference them in test assertions.
  require "runar_compiler/frontend/parser_java"

  include RunarCompiler::Frontend

  def parse(source, file_name = "Test.runar.java")
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  P2PKH_SOURCE = <<~JAVA
    package runar.examples.p2pkh;

    import runar.lang.SmartContract;
    import runar.lang.annotations.Public;
    import runar.lang.annotations.Readonly;
    import runar.lang.types.Addr;
    import runar.lang.types.PubKey;
    import runar.lang.types.Sig;
    import static runar.lang.Builtins.assertThat;
    import static runar.lang.Builtins.checkSig;
    import static runar.lang.Builtins.hash160;

    class P2PKH extends SmartContract {
        @Readonly Addr pubKeyHash;

        P2PKH(Addr pubKeyHash) {
            super(pubKeyHash);
            this.pubKeyHash = pubKeyHash;
        }

        @Public
        void unlock(Sig sig, PubKey pubKey) {
            assertThat(hash160(pubKey).equals(pubKeyHash));
            assertThat(checkSig(sig, pubKey));
        }
    }
  JAVA

  # -------------------------------------------------------------------
  # 1. Valid P2PKH
  # -------------------------------------------------------------------

  def test_parses_p2pkh_contract
    result = parse(P2PKH_SOURCE, "P2PKH.runar.java")
    assert_empty result.errors.map(&:format_message),
                 "P2PKH should parse without errors"
    refute_nil result.contract

    c = result.contract
    assert_equal "P2PKH", c.name
    assert_equal "SmartContract", c.parent_class
    assert_equal "P2PKH.runar.java", c.source_file

    assert_equal 1, c.properties.length
    pkh = c.properties[0]
    assert_equal "pubKeyHash", pkh.name
    assert pkh.readonly, "pubKeyHash should be readonly"
    assert_instance_of PrimitiveType, pkh.type
    assert_equal "Addr", pkh.type.name
    assert_nil pkh.initializer
  end

  def test_p2pkh_constructor_has_super_and_assignment
    result = parse(P2PKH_SOURCE, "P2PKH.runar.java")
    ctor = result.contract.constructor

    assert_equal "constructor", ctor.name
    assert_equal 1, ctor.params.length
    assert_equal "pubKeyHash", ctor.params[0].name

    assert_equal 2, ctor.body.length

    super_stmt = ctor.body[0]
    assert_instance_of ExpressionStmt, super_stmt
    super_call = super_stmt.expr
    assert_instance_of CallExpr, super_call
    assert_instance_of Identifier, super_call.callee
    assert_equal "super", super_call.callee.name
    assert_equal 1, super_call.args.length
    assert_equal "pubKeyHash", super_call.args[0].name

    assign_stmt = ctor.body[1]
    assert_instance_of AssignmentStmt, assign_stmt
    assert_instance_of PropertyAccessExpr, assign_stmt.target
    assert_equal "pubKeyHash", assign_stmt.target.property
    assert_instance_of Identifier, assign_stmt.value
    assert_equal "pubKeyHash", assign_stmt.value.name
  end

  def test_p2pkh_unlock_method_shape
    result = parse(P2PKH_SOURCE, "P2PKH.runar.java")
    c = result.contract
    assert_equal 1, c.methods.length

    unlock = c.methods[0]
    assert_equal "unlock", unlock.name
    assert_equal "public", unlock.visibility
    assert_equal 2, unlock.params.length
    assert_equal "Sig", unlock.params[0].type.name
    assert_equal "PubKey", unlock.params[1].type.name

    assert_equal 2, unlock.body.length

    first_stmt = unlock.body[0]
    assert_instance_of ExpressionStmt, first_stmt
    first_call = first_stmt.expr
    assert_instance_of CallExpr, first_call
    # The peer parser rewrites the static-imported `assertThat` to `assert`
    # so the shared typechecker (which only knows `assert`) accepts the call.
    assert_equal "assert", first_call.callee.name
    assert_equal 1, first_call.args.length

    # Inner: hash160(pubKey).equals(pubKeyHash) -> CallExpr with MemberExpr callee
    equals_call = first_call.args[0]
    assert_instance_of CallExpr, equals_call
    assert_instance_of MemberExpr, equals_call.callee
    assert_equal "equals", equals_call.callee.property
    hash160_call = equals_call.callee.object
    assert_instance_of CallExpr, hash160_call
    assert_equal "hash160", hash160_call.callee.name
  end

  # -------------------------------------------------------------------
  # 2. Stateful Counter
  # -------------------------------------------------------------------

  def test_stateful_counter_contract
    source = <<~JAVA
      class Counter extends StatefulSmartContract {
          BigInteger count;
          Counter(BigInteger count) {
              super(count);
              this.count = count;
          }
      }
    JAVA

    result = parse(source, "Counter.runar.java")
    assert_empty result.errors.map(&:format_message),
                 "Counter should parse without errors"
    refute_nil result.contract

    c = result.contract
    assert_equal "Counter", c.name
    assert_equal "StatefulSmartContract", c.parent_class
    assert_equal 1, c.properties.length

    count_prop = c.properties[0]
    assert_equal "count", count_prop.name
    refute count_prop.readonly, "count should be mutable in a stateful contract"
    assert_equal "bigint", count_prop.type.name
  end

  # -------------------------------------------------------------------
  # 3. Property initializer
  # -------------------------------------------------------------------

  def test_property_initializer
    source = <<~JAVA
      class Counter extends StatefulSmartContract {
          BigInteger count = BigInteger.ZERO;
          @Readonly PubKey owner;
          Counter(PubKey owner) { super(owner); this.owner = owner; }
      }
    JAVA

    result = parse(source, "Counter.runar.java")
    assert_empty result.errors.map(&:format_message),
                 "Counter should parse without errors"
    refute_nil result.contract

    c = result.contract
    assert_equal 2, c.properties.length

    count_prop = c.properties.find { |p| p.name == "count" }
    refute_nil count_prop
    refute_nil count_prop.initializer,
               "count should carry its literal initializer"
    assert_instance_of BigIntLiteral, count_prop.initializer
    assert_equal 0, count_prop.initializer.value
  end

  # -------------------------------------------------------------------
  # 4. Unknown base class is rejected
  # -------------------------------------------------------------------

  def test_rejects_unknown_base_class
    source = "class Bad extends Frobulator { }"
    result = parse(source, "Bad.runar.java")
    refute_empty result.errors, "parser should reject unknown base classes"
    assert result.errors.any? { |d| d.message.include?("Frobulator") },
           "error should mention the unrecognized base class"
  end

  # -------------------------------------------------------------------
  # 5. Missing extends clause is rejected
  # -------------------------------------------------------------------

  def test_rejects_missing_extends_clause
    source = "class Bad { @Readonly Addr pkh; }"
    result = parse(source, "Bad.runar.java")
    refute_empty result.errors, "parser should reject missing extends clause"
    assert result.errors.any? { |d| d.message.include?("must extend") },
           "error should mention the missing extends clause"
  end

  # -------------------------------------------------------------------
  # 6. ByteString.fromHex lowering
  # -------------------------------------------------------------------

  def test_bytestring_from_hex_is_literal
    source = <<~JAVA
      class C extends SmartContract {
          @Readonly ByteString magic;
          @Public void check() {
              assertThat(magic.equals(ByteString.fromHex("deadbeef")));
          }
      }
    JAVA

    result = parse(source, "C.runar.java")
    assert_empty result.errors.map(&:format_message)
    refute_nil result.contract

    check = result.contract.methods[0]
    stmt = check.body[0]
    assert_instance_of ExpressionStmt, stmt
    assert_call = stmt.expr
    equals_call = assert_call.args[0]
    # equals_call.args[0] is the fromHex literal argument
    lit = equals_call.args[0]
    assert_instance_of ByteStringLiteral, lit
    assert_equal "deadbeef", lit.value
  end

  # -------------------------------------------------------------------
  # 7. BigInteger.valueOf lowering
  # -------------------------------------------------------------------

  def test_big_integer_value_of_is_literal
    source = <<~JAVA
      class C extends SmartContract {
          @Readonly BigInteger threshold;
          @Public void check(BigInteger x) {
              assertThat(x == BigInteger.valueOf(7));
          }
      }
    JAVA

    result = parse(source, "C.runar.java")
    assert_empty result.errors.map(&:format_message)
    refute_nil result.contract

    check = result.contract.methods[0]
    stmt = check.body[0]
    assert_instance_of ExpressionStmt, stmt
    assert_call = stmt.expr
    cmp = assert_call.args[0]
    assert_instance_of BinaryExpr, cmp
    assert_equal "===", cmp.op
    assert_instance_of Identifier, cmp.left
    assert_equal "x", cmp.left.name
    # RHS must be a BigIntLiteral, not a call
    assert_instance_of BigIntLiteral, cmp.right
    assert_equal 7, cmp.right.value
  end

  # -------------------------------------------------------------------
  # 8. Binary ops
  # -------------------------------------------------------------------

  def test_binary_operators_preserved
    source = <<~JAVA
      class Arith extends SmartContract {
          @Readonly BigInteger target;
          @Public void go(BigInteger a, BigInteger b) {
              BigInteger x = a + b * BigInteger.valueOf(3);
              assertThat(x >= target && a != b);
          }
      }
    JAVA

    result = parse(source, "Arith.runar.java")
    assert_empty result.errors.map(&:format_message),
                 "binary-op contract should parse without errors"
    refute_nil result.contract

    go = result.contract.methods[0]
    # First stmt: var decl x = a + b * 3
    var_decl = go.body[0]
    assert_instance_of VariableDeclStmt, var_decl
    assert_equal "x", var_decl.name

    plus = var_decl.init
    assert_instance_of BinaryExpr, plus
    assert_equal "+", plus.op
    assert_instance_of Identifier, plus.left
    assert_equal "a", plus.left.name

    times = plus.right
    assert_instance_of BinaryExpr, times
    assert_equal "*", times.op
    assert_instance_of Identifier, times.left
    assert_equal "b", times.left.name
    assert_instance_of BigIntLiteral, times.right
    assert_equal 3, times.right.value

    # Second stmt: assertThat(x >= target && a != b)
    assert_stmt = go.body[1]
    and_expr = assert_stmt.expr.args[0]
    assert_instance_of BinaryExpr, and_expr
    assert_equal "&&", and_expr.op

    ge = and_expr.left
    assert_instance_of BinaryExpr, ge
    assert_equal ">=", ge.op

    neq = and_expr.right
    assert_instance_of BinaryExpr, neq
    assert_equal "!==", neq.op
  end

  # -------------------------------------------------------------------
  # 9. Dispatch integration -- unknown extension still raises.
  # -------------------------------------------------------------------

  def test_dispatch_accepts_java_extension
    # Sanity: the dispatcher routes .runar.java to our parser.
    result = parse(P2PKH_SOURCE, "ignored.runar.java")
    assert_empty result.errors.map(&:format_message)
    refute_nil result.contract
    assert_equal "P2PKH", result.contract.name
  end
end
