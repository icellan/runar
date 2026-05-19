# frozen_string_literal: true

# Type checking pass for the Runar compiler.
#
# Verifies type consistency of a validated Runar AST.
# Direct port of compilers/python/runar_compiler/frontend/typecheck.py.

require_relative "ast_nodes"
require_relative "diagnostic"

module RunarCompiler
  module Frontend
    # Output of the type checking pass.
    class TypeCheckResult
      attr_reader :contract, :errors

      def initialize(contract: nil, errors: [])
        @contract = contract
        @errors = errors
      end

      # Return formatted error messages as plain strings.
      def error_strings
        @errors.map(&:format_message)
      end
    end

    # Signature of a function: parameter types and return type.
    FuncSig = Struct.new(:params, :return_type, keyword_init: true)

    # All built-in Runar function signatures.
    BUILTIN_FUNCTIONS = {
      "sha256"            => FuncSig.new(params: ["ByteString"], return_type: "Sha256"),
      "ripemd160"         => FuncSig.new(params: ["ByteString"], return_type: "Ripemd160"),
      "hash160"           => FuncSig.new(params: ["ByteString"], return_type: "Ripemd160"),
      "hash256"           => FuncSig.new(params: ["ByteString"], return_type: "Sha256"),
      "checkSig"          => FuncSig.new(params: ["Sig", "PubKey"], return_type: "boolean"),
      "checkMultiSig"     => FuncSig.new(params: ["Sig[]", "PubKey[]"], return_type: "boolean"),
      "assert"            => FuncSig.new(params: ["boolean"], return_type: "void"),
      "len"               => FuncSig.new(params: ["ByteString"], return_type: "bigint"),
      "cat"               => FuncSig.new(params: ["ByteString", "ByteString"], return_type: "ByteString"),
      "substr"            => FuncSig.new(params: ["ByteString", "bigint", "bigint"], return_type: "ByteString"),
      "num2bin"           => FuncSig.new(params: ["bigint", "bigint"], return_type: "ByteString"),
      "bin2num"           => FuncSig.new(params: ["ByteString"], return_type: "bigint"),
      "checkPreimage"     => FuncSig.new(params: ["SigHashPreimage"], return_type: "boolean"),
      "verifyRabinSig"    => FuncSig.new(params: ["ByteString", "RabinSig", "ByteString", "RabinPubKey"], return_type: "boolean"),
      "verifyWOTS"        => FuncSig.new(params: ["ByteString", "ByteString", "ByteString"], return_type: "boolean"),
      "verifySLHDSA_SHA2_128s" => FuncSig.new(params: ["ByteString", "ByteString", "ByteString"], return_type: "boolean"),
      "verifySLHDSA_SHA2_128f" => FuncSig.new(params: ["ByteString", "ByteString", "ByteString"], return_type: "boolean"),
      "verifySLHDSA_SHA2_192s" => FuncSig.new(params: ["ByteString", "ByteString", "ByteString"], return_type: "boolean"),
      "verifySLHDSA_SHA2_192f" => FuncSig.new(params: ["ByteString", "ByteString", "ByteString"], return_type: "boolean"),
      "verifySLHDSA_SHA2_256s" => FuncSig.new(params: ["ByteString", "ByteString", "ByteString"], return_type: "boolean"),
      "verifySLHDSA_SHA2_256f" => FuncSig.new(params: ["ByteString", "ByteString", "ByteString"], return_type: "boolean"),
      "ecAdd"              => FuncSig.new(params: ["Point", "Point"], return_type: "Point"),
      "ecMul"              => FuncSig.new(params: ["Point", "bigint"], return_type: "Point"),
      "ecMulGen"           => FuncSig.new(params: ["bigint"], return_type: "Point"),
      "ecNegate"           => FuncSig.new(params: ["Point"], return_type: "Point"),
      "ecOnCurve"          => FuncSig.new(params: ["Point"], return_type: "boolean"),
      "ecModReduce"        => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "ecEncodeCompressed" => FuncSig.new(params: ["Point"], return_type: "ByteString"),
      "ecMakePoint"        => FuncSig.new(params: ["bigint", "bigint"], return_type: "Point"),
      "ecPointX"           => FuncSig.new(params: ["Point"], return_type: "bigint"),
      "ecPointY"           => FuncSig.new(params: ["Point"], return_type: "bigint"),
      # P-256 (secp256r1 / NIST P-256)
      "p256Add"              => FuncSig.new(params: ["P256Point", "P256Point"], return_type: "P256Point"),
      "p256Mul"              => FuncSig.new(params: ["P256Point", "bigint"], return_type: "P256Point"),
      "p256MulGen"           => FuncSig.new(params: ["bigint"], return_type: "P256Point"),
      "p256Negate"           => FuncSig.new(params: ["P256Point"], return_type: "P256Point"),
      "p256OnCurve"          => FuncSig.new(params: ["P256Point"], return_type: "boolean"),
      "p256EncodeCompressed" => FuncSig.new(params: ["P256Point"], return_type: "ByteString"),
      "verifyECDSA_P256"     => FuncSig.new(params: ["ByteString", "ByteString", "ByteString"], return_type: "boolean"),
      # P-384 (secp384r1 / NIST P-384)
      "p384Add"              => FuncSig.new(params: ["P384Point", "P384Point"], return_type: "P384Point"),
      "p384Mul"              => FuncSig.new(params: ["P384Point", "bigint"], return_type: "P384Point"),
      "p384MulGen"           => FuncSig.new(params: ["bigint"], return_type: "P384Point"),
      "p384Negate"           => FuncSig.new(params: ["P384Point"], return_type: "P384Point"),
      "p384OnCurve"          => FuncSig.new(params: ["P384Point"], return_type: "boolean"),
      "p384EncodeCompressed" => FuncSig.new(params: ["P384Point"], return_type: "ByteString"),
      "verifyECDSA_P384"     => FuncSig.new(params: ["ByteString", "ByteString", "ByteString"], return_type: "boolean"),
      "sha256Compress"     => FuncSig.new(params: ["ByteString", "ByteString"], return_type: "ByteString"),
      "sha256Finalize"     => FuncSig.new(params: ["ByteString", "ByteString", "bigint"], return_type: "ByteString"),
      "bbFieldAdd"         => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "bbFieldSub"         => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "bbFieldMul"         => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "bbFieldInv"         => FuncSig.new(params: ["bigint"], return_type: "bigint"),
      "bbExt4Mul0"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "bbExt4Mul1"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "bbExt4Mul2"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "bbExt4Mul3"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "bbExt4Inv0"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "bbExt4Inv1"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "bbExt4Inv2"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "bbExt4Inv3"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      # KoalaBear field arithmetic (p = 2130706433)
      "kbFieldAdd"         => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "kbFieldSub"         => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "kbFieldMul"         => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "kbFieldInv"         => FuncSig.new(params: ["bigint"], return_type: "bigint"),
      # KoalaBear quartic extension field (W = 3)
      "kbExt4Mul0"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "kbExt4Mul1"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "kbExt4Mul2"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "kbExt4Mul3"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "kbExt4Inv0"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "kbExt4Inv1"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "kbExt4Inv2"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      "kbExt4Inv3"         => FuncSig.new(params: ["bigint", "bigint", "bigint", "bigint"], return_type: "bigint"),
      # BN254 field arithmetic
      "bn254FieldAdd"      => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "bn254FieldSub"      => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "bn254FieldMul"      => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "bn254FieldInv"      => FuncSig.new(params: ["bigint"], return_type: "bigint"),
      "bn254FieldNeg"      => FuncSig.new(params: ["bigint"], return_type: "bigint"),
      # BN254 G1 curve operations
      "bn254G1Add"         => FuncSig.new(params: ["Point", "Point"], return_type: "Point"),
      "bn254G1ScalarMul"   => FuncSig.new(params: ["Point", "bigint"], return_type: "Point"),
      "bn254G1Negate"      => FuncSig.new(params: ["Point"], return_type: "Point"),
      "bn254G1OnCurve"     => FuncSig.new(params: ["Point"], return_type: "boolean"),
      "merkleRootSha256"   => FuncSig.new(params: ["ByteString", "ByteString", "bigint", "bigint"], return_type: "ByteString"),
      "merkleRootHash256"  => FuncSig.new(params: ["ByteString", "ByteString", "bigint", "bigint"], return_type: "ByteString"),
      "blake3Compress"     => FuncSig.new(params: ["ByteString", "ByteString"], return_type: "ByteString"),
      "blake3Hash"         => FuncSig.new(params: ["ByteString"], return_type: "ByteString"),
      "abs"                => FuncSig.new(params: ["bigint"], return_type: "bigint"),
      "min"                => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "max"                => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "within"             => FuncSig.new(params: ["bigint", "bigint", "bigint"], return_type: "boolean"),
      "safediv"            => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "safemod"            => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "clamp"              => FuncSig.new(params: ["bigint", "bigint", "bigint"], return_type: "bigint"),
      "sign"               => FuncSig.new(params: ["bigint"], return_type: "bigint"),
      "pow"                => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "mulDiv"             => FuncSig.new(params: ["bigint", "bigint", "bigint"], return_type: "bigint"),
      "percentOf"          => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "sqrt"               => FuncSig.new(params: ["bigint"], return_type: "bigint"),
      "gcd"                => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "divmod"             => FuncSig.new(params: ["bigint", "bigint"], return_type: "bigint"),
      "log2"               => FuncSig.new(params: ["bigint"], return_type: "bigint"),
      "bool"               => FuncSig.new(params: ["bigint"], return_type: "boolean"),
      "reverseBytes"       => FuncSig.new(params: ["ByteString"], return_type: "ByteString"),
      "left"               => FuncSig.new(params: ["ByteString", "bigint"], return_type: "ByteString"),
      "right"              => FuncSig.new(params: ["ByteString", "bigint"], return_type: "ByteString"),
      "split"              => FuncSig.new(params: ["ByteString", "bigint"], return_type: "ByteString"),
      "int2str"            => FuncSig.new(params: ["bigint", "bigint"], return_type: "ByteString"),
      "toByteString"       => FuncSig.new(params: ["ByteString"], return_type: "ByteString"),
      "exit"               => FuncSig.new(params: ["boolean"], return_type: "void"),
      "pack"               => FuncSig.new(params: ["bigint"], return_type: "ByteString"),
      "unpack"             => FuncSig.new(params: ["ByteString"], return_type: "bigint"),
      "extractVersion"        => FuncSig.new(params: ["SigHashPreimage"], return_type: "bigint"),
      "extractHashPrevouts"   => FuncSig.new(params: ["SigHashPreimage"], return_type: "Sha256"),
      "extractHashSequence"   => FuncSig.new(params: ["SigHashPreimage"], return_type: "Sha256"),
      "extractOutpoint"       => FuncSig.new(params: ["SigHashPreimage"], return_type: "ByteString"),
      "extractInputIndex"     => FuncSig.new(params: ["SigHashPreimage"], return_type: "bigint"),
      "extractScriptCode"     => FuncSig.new(params: ["SigHashPreimage"], return_type: "ByteString"),
      "extractAmount"         => FuncSig.new(params: ["SigHashPreimage"], return_type: "bigint"),
      "extractSequence"       => FuncSig.new(params: ["SigHashPreimage"], return_type: "bigint"),
      "extractOutputHash"     => FuncSig.new(params: ["SigHashPreimage"], return_type: "Sha256"),
      "extractOutputs"        => FuncSig.new(params: ["SigHashPreimage"], return_type: "Sha256"),
      "extractLocktime"       => FuncSig.new(params: ["SigHashPreimage"], return_type: "bigint"),
      "extractSigHashType"    => FuncSig.new(params: ["SigHashPreimage"], return_type: "bigint"),
      "buildChangeOutput"     => FuncSig.new(params: ["ByteString", "bigint"], return_type: "ByteString"),
      "computeStateOutput"    => FuncSig.new(params: ["ByteString", "bigint"], return_type: "ByteString"),
      # Intent sub-covenant intrinsics (BSVM Phase 13). Witness-bridge wrappers
      # that compile down to standard primitives + auto-injected method params.
      # See docs/cross-covenant-pattern.md.
      #
      # First arg of extractPrevOutputScript / requireOutputP2PKH MUST be an
      # integer literal -- enforced as a special case in check_call_args.
      "extractPrevOutputScript" => FuncSig.new(params: ["bigint", "ByteString"], return_type: "ByteString"),
      "requireOutputP2PKH"      => FuncSig.new(params: ["bigint", "ByteString", "bigint"], return_type: "void"),
      "currentBlockHeight"      => FuncSig.new(params: [], return_type: "bigint"),
    }.freeze

    # -------------------------------------------------------------------
    # Subtyping
    # -------------------------------------------------------------------

    BYTESTRING_SUBTYPES = %w[
      ByteString PubKey Sig Sha256 Ripemd160 Addr SigHashPreimage Point P256Point P384Point
    ].to_set.freeze

    BIGINT_SUBTYPES = %w[
      bigint RabinSig RabinPubKey
    ].to_set.freeze

    # Return true if +actual+ is a subtype of +expected+.
    def self.subtype?(actual, expected)
      return true if actual == expected

      # <inferred> and <unknown> are compatible with anything
      return true if actual == "<inferred>" || actual == "<unknown>"
      return true if expected == "<inferred>" || expected == "<unknown>"

      return true if expected == "ByteString" && BYTESTRING_SUBTYPES.include?(actual)
      return true if expected == "bigint" && BIGINT_SUBTYPES.include?(actual)

      if expected.end_with?("[]") && actual.end_with?("[]")
        return subtype?(actual[0..-3], expected[0..-3])
      end

      false
    end

    # Return true if +t+ belongs to the bigint type family.
    def self.bigint_family?(type_name)
      BIGINT_SUBTYPES.include?(type_name)
    end

    # Return true if +t+ belongs to the ByteString type family.
    def self.byte_family?(type_name)
      BYTESTRING_SUBTYPES.include?(type_name)
    end

    # Type-check a Runar AST. Returns the same AST plus any errors.
    #
    # @param contract [ContractNode]
    # @return [TypeCheckResult]
    def self.type_check(contract)
      checker = TypeChecker.new(contract)

      checker.check_constructor
      contract.methods.each { |method| checker.check_method(method) }

      TypeCheckResult.new(contract: contract, errors: checker.errors)
    end

    # -------------------------------------------------------------------
    # Type environment
    # -------------------------------------------------------------------

    # @api private
    class TypeEnv
      def initialize
        @scopes = [{}]
      end

      def push_scope
        @scopes.push({})
      end

      def pop_scope
        @scopes.pop unless @scopes.empty?
      end

      def define(name, type_name)
        @scopes.last[name] = type_name
      end

      # @return [Array(String, Boolean)] the type and whether it was found
      def lookup(name)
        @scopes.reverse_each do |scope|
          return [scope[name], true] if scope.key?(name)
        end
        ["", false]
      end
    end

    # -------------------------------------------------------------------
    # Affine types
    # -------------------------------------------------------------------

    AFFINE_TYPES = %w[Sig SigHashPreimage].to_set.freeze

    CONSUMING_FUNCTIONS = {
      "checkSig"      => [0],
      "checkMultiSig" => [0],
      "checkPreimage" => [0],
    }.freeze

    # -------------------------------------------------------------------
    # Type checker
    # -------------------------------------------------------------------

    # @api private
    class TypeChecker
      attr_reader :errors

      def initialize(contract)
        @contract = contract
        @errors = []
        @prop_types = {}
        @method_sigs = {}
        @consumed_values = {}
        @affine_aliases = {}
        @current_method_loc = nil
        @current_stmt_loc = nil

        contract.properties.each do |prop|
          @prop_types[prop.name] = type_node_to_string(prop.type)
        end

        # For StatefulSmartContract, add the implicit txPreimage property
        if contract.parent_class == "StatefulSmartContract"
          @prop_types["txPreimage"] = "SigHashPreimage"
        end

        contract.methods.each do |method|
          params = method.params.map { |p| type_node_to_string(p.type) }
          ret_type = "void"
          if method.visibility != "public"
            ret_type = TypeChecker.infer_method_return_type(method)
          end
          @method_sigs[method.name] = FuncSig.new(params: params, return_type: ret_type)
        end
      end

      def check_constructor
        ctor = @contract.constructor
        env = TypeEnv.new

        # Set current method location for diagnostics
        @current_method_loc = ctor.source_location

        # Reset affine tracking
        @consumed_values = {}
        @affine_aliases = {}

        ctor.params.each do |param|
          env.define(param.name, type_node_to_string(param.type))
        end
        @contract.properties.each do |prop|
          env.define(prop.name, type_node_to_string(prop.type))
        end

        check_statements(ctor.body, env)
      end

      def check_method(method)
        env = TypeEnv.new

        # Set current method location for diagnostics
        @current_method_loc = method.source_location

        # Reset affine tracking
        @consumed_values = {}
        @affine_aliases = {}

        method.params.each do |param|
          env.define(param.name, type_node_to_string(param.type))
        end

        check_statements(method.body, env)

        # Crit-3 -- reject mixing requireOutputP2PKH with addDataOutput in the
        # same method body. The intrinsic's compile-time output-offset
        # computation assumes a fixed 34-byte stride per output, which is
        # silently wrong when an OP_RETURN output (variable length) precedes
        # the indexed P2PKH output. v1 forbids the mix; v2 may relax with a
        # variable-stride decoder.
        has_require_p2pkh = TypeChecker.body_calls_builtin?(method.body, "requireOutputP2PKH")
        has_add_data_output = TypeChecker.body_calls_add_data_output?(method.body)
        if has_require_p2pkh && has_add_data_output
          add_error(
            "method '#{method.name}' mixes requireOutputP2PKH() with addDataOutput() -- " \
            "v1 of the intrinsic assumes a fixed 34-byte output stride and " \
            "variable-length OP_RETURN outputs break the offset computation; " \
            "split the addDataOutput call into a separate method"
          )
        end
      end

      # -------------------------------------------------------------------
      # Crit-3 body walkers -- recursive scan for builtin calls and
      # addDataOutput calls inside a method body. Mirrors the Go
      # bodyCallsBuiltin / bodyCallsAddDataOutput helpers in
      # compilers/go/frontend/typecheck.go.
      # -------------------------------------------------------------------

      def self.body_calls_builtin?(body, name)
        body.any? { |stmt| stmt_contains_call_to?(stmt, name) }
      end

      def self.body_calls_add_data_output?(body)
        body.any? { |stmt| stmt_contains_add_data_output?(stmt) }
      end

      def self.stmt_contains_call_to?(stmt, name)
        case stmt
        when ExpressionStmt
          expr_contains_call_to?(stmt.expr, name)
        when VariableDeclStmt
          expr_contains_call_to?(stmt.init, name)
        when AssignmentStmt
          expr_contains_call_to?(stmt.value, name) ||
            expr_contains_call_to?(stmt.target, name)
        when IfStmt
          return true if expr_contains_call_to?(stmt.condition, name)
          return true if stmt.then.any? { |t| stmt_contains_call_to?(t, name) }
          return true if !stmt.else_.empty? && stmt.else_.any? { |e| stmt_contains_call_to?(e, name) }
          false
        when ForStmt
          stmt.body.any? { |t| stmt_contains_call_to?(t, name) }
        when ReturnStmt
          stmt.value.nil? ? false : expr_contains_call_to?(stmt.value, name)
        else
          false
        end
      end

      def self.expr_contains_call_to?(expr, name)
        return false if expr.nil?

        case expr
        when CallExpr
          if expr.callee.is_a?(Identifier) && expr.callee.name == name
            return true
          end
          expr.args.any? { |a| expr_contains_call_to?(a, name) }
        when BinaryExpr
          expr_contains_call_to?(expr.left, name) || expr_contains_call_to?(expr.right, name)
        when UnaryExpr
          expr_contains_call_to?(expr.operand, name)
        when TernaryExpr
          expr_contains_call_to?(expr.condition, name) ||
            expr_contains_call_to?(expr.consequent, name) ||
            expr_contains_call_to?(expr.alternate, name)
        when IndexAccessExpr
          expr_contains_call_to?(expr.object, name) || expr_contains_call_to?(expr.index, name)
        when ArrayLiteralExpr
          expr.elements.any? { |el| expr_contains_call_to?(el, name) }
        else
          false
        end
      end

      def self.stmt_contains_add_data_output?(stmt)
        case stmt
        when ExpressionStmt
          expr_contains_add_data_output?(stmt.expr)
        when VariableDeclStmt
          expr_contains_add_data_output?(stmt.init)
        when AssignmentStmt
          expr_contains_add_data_output?(stmt.value) ||
            expr_contains_add_data_output?(stmt.target)
        when IfStmt
          return true if expr_contains_add_data_output?(stmt.condition)
          return true if stmt.then.any? { |t| stmt_contains_add_data_output?(t) }
          return true if !stmt.else_.empty? && stmt.else_.any? { |e| stmt_contains_add_data_output?(e) }
          false
        when ForStmt
          stmt.body.any? { |t| stmt_contains_add_data_output?(t) }
        when ReturnStmt
          stmt.value.nil? ? false : expr_contains_add_data_output?(stmt.value)
        else
          false
        end
      end

      def self.expr_contains_add_data_output?(expr)
        return false if expr.nil?

        case expr
        when CallExpr
          if expr.callee.is_a?(PropertyAccessExpr) && expr.callee.property == "addDataOutput"
            return true
          end
          if expr.callee.is_a?(MemberExpr) && expr.callee.property == "addDataOutput"
            return true
          end
          expr.args.any? { |a| expr_contains_add_data_output?(a) }
        when BinaryExpr
          expr_contains_add_data_output?(expr.left) || expr_contains_add_data_output?(expr.right)
        when UnaryExpr
          expr_contains_add_data_output?(expr.operand)
        when TernaryExpr
          expr_contains_add_data_output?(expr.condition) ||
            expr_contains_add_data_output?(expr.consequent) ||
            expr_contains_add_data_output?(expr.alternate)
        when IndexAccessExpr
          expr_contains_add_data_output?(expr.object) || expr_contains_add_data_output?(expr.index)
        when ArrayLiteralExpr
          expr.elements.any? { |el| expr_contains_add_data_output?(el) }
        else
          false
        end
      end

      # -------------------------------------------------------------------
      # Private method return type inference (class-level)
      # -------------------------------------------------------------------

      def self.infer_method_return_type(method)
        return_types = collect_return_types(method.body)
        return "void" if return_types.empty?

        first = return_types[0]
        return first if return_types.all? { |t| t == first }

        # Check if all are in the bigint family
        return "bigint" if return_types.all? { |t| BIGINT_SUBTYPES.include?(t) }

        # Check if all are in the ByteString family
        return "ByteString" if return_types.all? { |t| BYTESTRING_SUBTYPES.include?(t) }

        # Check if all are boolean
        return "boolean" if return_types.all? { |t| t == "boolean" }

        first
      end

      def self.collect_return_types(stmts)
        types = []
        stmts.each do |stmt|
          case stmt
          when ReturnStmt
            types << infer_expr_type_static(stmt.value) unless stmt.value.nil?
          when IfStmt
            types.concat(collect_return_types(stmt.then))
            types.concat(collect_return_types(stmt.else_)) unless stmt.else_.empty?
          when ForStmt
            types.concat(collect_return_types(stmt.body))
          end
        end
        types
      end

      def self.infer_expr_type_static(expr)
        return "<unknown>" if expr.nil?

        case expr
        when BigIntLiteral
          "bigint"
        when BoolLiteral
          "boolean"
        when ByteStringLiteral
          "ByteString"
        when Identifier
          return "boolean" if expr.name == "true" || expr.name == "false"
          "<unknown>"
        when BinaryExpr
          if %w[+ - * / % & | ^ << >>].include?(expr.op)
            "bigint"
          else
            # Comparison, equality, logical operators -> boolean
            "boolean"
          end
        when UnaryExpr
          expr.op == "!" ? "boolean" : "bigint"
        when CallExpr
          if expr.callee.is_a?(Identifier)
            # Expression-form asm<T>({...}) statically yields type T.
            if expr.callee.name == "asm" && !expr.asm_return_type.nil?
              return expr.asm_return_type
            end
            sig = BUILTIN_FUNCTIONS[expr.callee.name]
            return sig.return_type unless sig.nil?
          end
          if expr.callee.is_a?(PropertyAccessExpr)
            sig = BUILTIN_FUNCTIONS[expr.callee.property]
            return sig.return_type unless sig.nil?
          end
          "<unknown>"
        when TernaryExpr
          cons_type = infer_expr_type_static(expr.consequent)
          return cons_type if cons_type != "<unknown>"
          infer_expr_type_static(expr.alternate)
        when IncrementExpr, DecrementExpr
          "bigint"
        else
          "<unknown>"
        end
      end

      private

      def add_error(msg)
        loc = @current_stmt_loc || @current_method_loc
        @errors << Diagnostic.new(message: msg, severity: Severity::ERROR, loc: loc)
      end

      def type_node_to_string(node)
        return "<unknown>" if node.nil?

        case node
        when PrimitiveType
          node.name
        when FixedArrayType
          "#{type_node_to_string(node.element)}[]"
        when CustomType
          node.name
        else
          "<unknown>"
        end
      end

      # -------------------------------------------------------------------
      # Statement checking
      # -------------------------------------------------------------------

      def check_statements(stmts, env)
        stmts.each { |stmt| check_statement(stmt, env) }
      end

      def check_statement(stmt, env)
        # Set statement-level source location for diagnostics
        prev_stmt_loc = @current_stmt_loc
        stmt_loc = stmt_source_location(stmt)
        @current_stmt_loc = stmt_loc unless stmt_loc.nil?

        case stmt
        when VariableDeclStmt
          init_type = infer_expr_type(stmt.init, env)
          if !stmt.type.nil?
            declared_type = type_node_to_string(stmt.type)
            unless Frontend.subtype?(init_type, declared_type)
              add_error("type '#{init_type}' is not assignable to type '#{declared_type}'")
            end
            env.define(stmt.name, declared_type)
            decl_type = declared_type
          else
            env.define(stmt.name, init_type)
            decl_type = init_type
          end
          # Affine alias tracking — 2026-04-30 audit finding F6.
          if AFFINE_TYPES.include?(decl_type)
            origin = affine_origin_of_expr(stmt.init)
            @affine_aliases[stmt.name] = origin unless origin.nil?
          end

        when AssignmentStmt
          target_type = infer_expr_type(stmt.target, env)
          value_type = infer_expr_type(stmt.value, env)
          unless Frontend.subtype?(value_type, target_type)
            add_error("type '#{value_type}' is not assignable to type '#{target_type}'")
          end

        when IfStmt
          cond_type = infer_expr_type(stmt.condition, env)
          if cond_type != "boolean"
            add_error("if condition must be boolean, got '#{cond_type}'")
          end
          env.push_scope
          check_statements(stmt.then, env)
          env.pop_scope
          unless stmt.else_.empty?
            env.push_scope
            check_statements(stmt.else_, env)
            env.pop_scope
          end

        when ForStmt
          env.push_scope
          check_statement(stmt.init, env)
          cond_type = infer_expr_type(stmt.condition, env)
          if cond_type != "boolean"
            add_error("for loop condition must be boolean, got '#{cond_type}'")
          end
          check_statements(stmt.body, env)
          env.pop_scope

        when ExpressionStmt
          infer_expr_type(stmt.expr, env)

        when ReturnStmt
          infer_expr_type(stmt.value, env) unless stmt.value.nil?
        end

        # Restore previous statement location
        @current_stmt_loc = prev_stmt_loc
      end

      def stmt_source_location(stmt)
        loc = stmt.respond_to?(:source_location) ? stmt.source_location : nil
        return nil if loc.nil?
        return loc if loc.file && !loc.file.empty?
        return loc if loc.line > 0

        nil
      end

      # -------------------------------------------------------------------
      # Type inference
      # -------------------------------------------------------------------

      def infer_expr_type(expr, env)
        return "<unknown>" if expr.nil?

        case expr
        when BigIntLiteral
          "bigint"
        when BoolLiteral
          "boolean"
        when ByteStringLiteral
          "ByteString"

        when Identifier
          return "<this>" if expr.name == "this"
          return "<super>" if expr.name == "super"

          type_name, found = env.lookup(expr.name)
          return type_name if found
          return "<builtin>" if BUILTIN_FUNCTIONS.key?(expr.name)

          "<unknown>"

        when PropertyAccessExpr
          return @prop_types[expr.property] if @prop_types.key?(expr.property)
          "<unknown>"

        when MemberExpr
          obj_type = infer_expr_type(expr.object, env)
          if obj_type == "<this>"
            return @prop_types[expr.property] if @prop_types.key?(expr.property)
            return "<method>" if @method_sigs.key?(expr.property)
            return "<method>" if expr.property == "getStateScript"
            return "<unknown>"
          end
          if expr.object.is_a?(Identifier) && expr.object.name == "SigHash"
            return "bigint"
          end
          "<unknown>"

        when BinaryExpr
          check_binary_expr(expr, env)

        when UnaryExpr
          check_unary_expr(expr, env)

        when CallExpr
          check_call_expr(expr, env)

        when TernaryExpr
          cond_type = infer_expr_type(expr.condition, env)
          if cond_type != "boolean"
            add_error("ternary condition must be boolean, got '#{cond_type}'")
          end
          cons_type = infer_expr_type(expr.consequent, env)
          alt_type = infer_expr_type(expr.alternate, env)
          if cons_type != alt_type
            return cons_type if Frontend.subtype?(alt_type, cons_type)
            return alt_type if Frontend.subtype?(cons_type, alt_type)
          end
          cons_type

        when IndexAccessExpr
          obj_type = infer_expr_type(expr.object, env)
          index_type = infer_expr_type(expr.index, env)
          unless Frontend.bigint_family?(index_type)
            add_error("array index must be bigint, got '#{index_type}'")
          end
          return obj_type[0..-3] if obj_type.end_with?("[]")
          "<unknown>"

        when IncrementExpr
          operand_type = infer_expr_type(expr.operand, env)
          unless Frontend.bigint_family?(operand_type)
            add_error("++ operator requires bigint, got '#{operand_type}'")
          end
          "bigint"

        when DecrementExpr
          operand_type = infer_expr_type(expr.operand, env)
          unless Frontend.bigint_family?(operand_type)
            add_error("-- operator requires bigint, got '#{operand_type}'")
          end
          "bigint"

        else
          "<unknown>"
        end
      end

      # -------------------------------------------------------------------
      # Binary expression type checking
      # -------------------------------------------------------------------

      def check_binary_expr(expr, env)
        left_type = infer_expr_type(expr.left, env)
        right_type = infer_expr_type(expr.right, env)

        # ByteString concatenation: ByteString + ByteString -> ByteString (via OP_CAT)
        if expr.op == "+" && Frontend.byte_family?(left_type) && Frontend.byte_family?(right_type)
          return "ByteString"
        end

        # Arithmetic: bigint x bigint -> bigint
        if %w[+ - * / %].include?(expr.op)
          unless Frontend.bigint_family?(left_type)
            add_error("left operand of '#{expr.op}' must be bigint, got '#{left_type}'")
          end
          unless Frontend.bigint_family?(right_type)
            add_error("right operand of '#{expr.op}' must be bigint, got '#{right_type}'")
          end
          return "bigint"
        end

        if %w[< <= > >=].include?(expr.op)
          unless Frontend.bigint_family?(left_type)
            add_error("left operand of '#{expr.op}' must be bigint, got '#{left_type}'")
          end
          unless Frontend.bigint_family?(right_type)
            add_error("right operand of '#{expr.op}' must be bigint, got '#{right_type}'")
          end
          return "boolean"
        end

        if expr.op == "===" || expr.op == "!=="
          compatible =
            Frontend.subtype?(left_type, right_type) ||
            Frontend.subtype?(right_type, left_type) ||
            (BYTESTRING_SUBTYPES.include?(left_type) && BYTESTRING_SUBTYPES.include?(right_type)) ||
            (BIGINT_SUBTYPES.include?(left_type) && BIGINT_SUBTYPES.include?(right_type))
          unless compatible
            if left_type != "<unknown>" && right_type != "<unknown>"
              add_error("cannot compare '#{left_type}' and '#{right_type}' with '#{expr.op}'")
            end
          end
          return "boolean"
        end

        if expr.op == "&&" || expr.op == "||"
          if left_type != "boolean" && left_type != "<unknown>"
            add_error("left operand of '#{expr.op}' must be boolean, got '#{left_type}'")
          end
          if right_type != "boolean" && right_type != "<unknown>"
            add_error("right operand of '#{expr.op}' must be boolean, got '#{right_type}'")
          end
          return "boolean"
        end

        if expr.op == "<<" || expr.op == ">>"
          unless Frontend.bigint_family?(left_type)
            add_error("left operand of '#{expr.op}' must be bigint, got '#{left_type}'")
          end
          unless Frontend.bigint_family?(right_type)
            add_error("right operand of '#{expr.op}' must be bigint, got '#{right_type}'")
          end
          return "bigint"
        end

        # Bitwise operators: bigint x bigint -> bigint, or ByteString x ByteString -> ByteString
        if %w[& | ^].include?(expr.op)
          if Frontend.byte_family?(left_type) && Frontend.byte_family?(right_type)
            return "ByteString"
          end
          unless Frontend.bigint_family?(left_type)
            add_error("left operand of '#{expr.op}' must be bigint or ByteString, got '#{left_type}'")
          end
          unless Frontend.bigint_family?(right_type)
            add_error("right operand of '#{expr.op}' must be bigint or ByteString, got '#{right_type}'")
          end
          return "bigint"
        end

        "<unknown>"
      end

      # -------------------------------------------------------------------
      # Unary expression type checking
      # -------------------------------------------------------------------

      def check_unary_expr(expr, env)
        operand_type = infer_expr_type(expr.operand, env)

        case expr.op
        when "!"
          if operand_type != "boolean" && operand_type != "<unknown>"
            add_error("operand of '!' must be boolean, got '#{operand_type}'")
          end
          "boolean"

        when "-"
          unless Frontend.bigint_family?(operand_type)
            add_error("operand of unary '-' must be bigint, got '#{operand_type}'")
          end
          "bigint"

        when "~"
          return "ByteString" if Frontend.byte_family?(operand_type)
          unless Frontend.bigint_family?(operand_type)
            add_error("operand of '~' must be bigint or ByteString, got '#{operand_type}'")
          end
          "bigint"

        else
          "<unknown>"
        end
      end

      # -------------------------------------------------------------------
      # Call expression type checking
      # -------------------------------------------------------------------

      def check_call_expr(expr, env)
        # super() call
        if expr.callee.is_a?(Identifier) && expr.callee.name == "super"
          expr.args.each { |arg| infer_expr_type(arg, env) }
          return "void"
        end

        # asm is a compile-time intrinsic -- the parser has already rewritten
        # the { body, in_arity?, out_arity? } object-literal argument into
        # three positional args (body, in_arity, out_arity). The statement
        # form returns void; the expression form asm<T>({...}) carries the
        # captured return type on asm_return_type and produces a value of
        # that type.
        if expr.callee.is_a?(Identifier) && expr.callee.name == "asm"
          expr.args.each { |arg| infer_expr_type(arg, env) }
          return expr.asm_return_type unless expr.asm_return_type.nil?

          return "void"
        end

        # Direct builtin call
        if expr.callee.is_a?(Identifier)
          name = expr.callee.name
          if BUILTIN_FUNCTIONS.key?(name)
            return check_call_args(name, BUILTIN_FUNCTIONS[name], expr.args, env)
          end
          # Check if it's a known contract method
          if @method_sigs.key?(name)
            return check_call_args(name, @method_sigs[name], expr.args, env)
          end
          # Check if it's a local variable
          _, found = env.lookup(name)
          if found
            expr.args.each { |arg| infer_expr_type(arg, env) }
            return "<unknown>"
          end
          add_error(
            "unknown function '#{name}' -- only Runar built-in functions " \
            "and contract methods are allowed"
          )
          expr.args.each { |arg| infer_expr_type(arg, env) }
          return "<unknown>"
        end

        # this.method() via PropertyAccessExpr
        if expr.callee.is_a?(PropertyAccessExpr)
          prop = expr.callee.property
          if prop == "getStateScript"
            return "ByteString"
          end
          if prop == "addOutput"
            expr.args.each { |arg| infer_expr_type(arg, env) }
            return "void"
          end
          if prop == "addRawOutput"
            expr.args.each { |arg| infer_expr_type(arg, env) }
            return "void"
          end
          if prop == "addDataOutput"
            expr.args.each { |arg| infer_expr_type(arg, env) }
            return "void"
          end
          if @method_sigs.key?(prop)
            return check_call_args(prop, @method_sigs[prop], expr.args, env)
          end
          add_error(
            "unknown method 'this.#{prop}' -- only Runar built-in methods " \
            "and contract methods are allowed"
          )
          expr.args.each { |arg| infer_expr_type(arg, env) }
          return "<unknown>"
        end

        # this.method() via MemberExpr
        if expr.callee.is_a?(MemberExpr)
          obj_type = infer_expr_type(expr.callee.object, env)
          is_this = obj_type == "<this>" ||
            (expr.callee.object.is_a?(Identifier) && expr.callee.object.name == "this")
          if is_this
            if expr.callee.property == "getStateScript"
              return "ByteString"
            end
            if expr.callee.property == "addOutput"
              expr.args.each { |arg| infer_expr_type(arg, env) }
              return "void"
            end
            if expr.callee.property == "addRawOutput"
              expr.args.each { |arg| infer_expr_type(arg, env) }
              return "void"
            end
            if expr.callee.property == "addDataOutput"
              expr.args.each { |arg| infer_expr_type(arg, env) }
              return "void"
            end
            if @method_sigs.key?(expr.callee.property)
              return check_call_args(
                expr.callee.property,
                @method_sigs[expr.callee.property],
                expr.args,
                env
              )
            end
          end
          # Not this.method -- reject (e.g. Math.floor)
          obj_name = "<expr>"
          if expr.callee.object.is_a?(Identifier)
            obj_name = expr.callee.object.name
          end
          add_error(
            "unknown function '#{obj_name}.#{expr.callee.property}' -- only Runar " \
            "built-in functions and contract methods are allowed"
          )
          expr.args.each { |arg| infer_expr_type(arg, env) }
          return "<unknown>"
        end

        # Fallback -- unknown callee shape
        add_error(
          "unsupported function call expression -- only Runar built-in " \
          "functions and contract methods are allowed"
        )
        infer_expr_type(expr.callee, env)
        expr.args.each { |arg| infer_expr_type(arg, env) }
        "<unknown>"
      end

      # -------------------------------------------------------------------
      # Argument checking
      # -------------------------------------------------------------------

      def check_call_args(func_name, sig, args, env)
        # extractPrevOutputScript / requireOutputP2PKH -- the index arg MUST
        # be a compile-time integer literal so the ANF lowering can derive a
        # stable auto-injected witness-param name (extractPrevOutputScript) or
        # a constant byte offset (requireOutputP2PKH).
        if func_name == "extractPrevOutputScript" || func_name == "requireOutputP2PKH"
          if !args.empty?
            idx_lit = nil
            if args[0].is_a?(BigIntLiteral)
              idx_lit = args[0]
            # Accept `-N` (UnaryExpr "-" over BigIntLiteral) so the bounds
            # check below produces a clear "must be >= 0" rather than the
            # misleading "must be an integer literal" message.
            elsif args[0].is_a?(UnaryExpr) && args[0].op == "-" &&
                  args[0].operand.is_a?(BigIntLiteral) &&
                  !args[0].operand.value.nil?
              idx_lit = BigIntLiteral.new(value: -args[0].operand.value)
            end
            if idx_lit.nil?
              add_error("#{func_name}() argument 1 (index) must be an integer literal")
            elsif !idx_lit.value.nil?
              # R-2: bound the index literal. For requireOutputP2PKH, the
              # emitted Stack-IR computes byte-offset = idx * 34; require
              # 0 <= idx <= 1000 to keep the offset well under script-int
              # max and to reject obvious nonsense (e.g. negative or
              # astronomically large).
              idx = idx_lit.value
              if idx < 0
                add_error("#{func_name}() argument 1 (index) must be >= 0; got #{idx}")
              end
              if func_name == "requireOutputP2PKH" && idx > 1000
                add_error(
                  "requireOutputP2PKH() argument 1 (outputIndex) bound to <= 1000; " \
                  "got #{idx} (the emitted Stack-IR computes byte-offset = idx*34; " \
                  "unrealistic indexes indicate a programming error)"
                )
              end
            end
          end
        end

        # extractPrevOutputScript variable-arity special case (2-arg full-hash
        # or 3-arg prefix-hash form, BSVM Crit-2). Validates types + literal-only
        # on the optional prefixLen, then returns the signature's return type to
        # bypass the standard arg-count check below (which would reject the
        # 3-arg form against the 2-arg sig table entry).
        if func_name == "extractPrevOutputScript"
          if args.length != 2 && args.length != 3
            add_error("extractPrevOutputScript() expects 2 or 3 arguments, got #{args.length}")
          end
          if args.length >= 1
            infer_expr_type(args[0], env) # already validated as literal above
          end
          if args.length >= 2
            arg_type = infer_expr_type(args[1], env)
            if !Frontend.subtype?(arg_type, "ByteString") && arg_type != "<unknown>"
              add_error("argument 2 of extractPrevOutputScript(): expected 'ByteString', got '#{arg_type}'")
            end
          end
          if args.length == 3
            if !args[2].is_a?(BigIntLiteral)
              add_error("extractPrevOutputScript() argument 3 (prefixLen) must be an integer literal when supplied")
            elsif !args[2].value.nil?
              # R-4: bound the prefixLen literal. The intrinsic hashes
              # substr(witness, 0, prefixLen) and compares against a
              # 32-byte SHA-256 hash. prefixLen < 32 is suspicious (the
              # prefix bytes don't even cover a hash-sized chunk).
              # prefixLen > 4 MiB exceeds MAX_SCRIPT_BYTES -- wouldn't
              # fit in a legal Bitcoin Script anyway.
              n = args[2].value
              if n < 32
                add_error(
                  "extractPrevOutputScript() argument 3 (prefixLen) must be >= 32 " \
                  "(the hash assertion compares a 32-byte SHA-256); got #{n}"
                )
              end
              if n > 4 * 1024 * 1024
                add_error(
                  "extractPrevOutputScript() argument 3 (prefixLen) must be <= " \
                  "MAX_SCRIPT_BYTES (4 MiB); got #{n}"
                )
              end
            end
            infer_expr_type(args[2], env)
          end
          return sig.return_type
        end

        # requireOutputP2PKH and currentBlockHeight need the auto-injected
        # txPreimage -- only available in StatefulSmartContract methods.
        if func_name == "requireOutputP2PKH" || func_name == "currentBlockHeight"
          if !@contract.nil? && @contract.parent_class != "StatefulSmartContract"
            add_error("#{func_name}() is only available in StatefulSmartContract methods")
          end
        end

        # assert special case
        if func_name == "assert"
          if args.length < 1 || args.length > 2
            add_error("assert() expects 1 or 2 arguments, got #{args.length}")
          end
          if args.length >= 1
            cond_type = infer_expr_type(args[0], env)
            if cond_type != "boolean" && cond_type != "<unknown>"
              add_error("assert() condition must be boolean, got '#{cond_type}'")
            end
          end
          infer_expr_type(args[1], env) if args.length >= 2
          return sig.return_type
        end

        # checkMultiSig special case (Sig[] / PubKey[] arrays). Only
        # arity is special; arg-type validation falls through to the
        # standard subtype loop below so callers cannot pass
        # bigint[] or other element types. 2026-04-30 audit finding
        # F5.
        if func_name == "checkMultiSig"
          if args.length != 2
            add_error("checkMultiSig() expects 2 arguments, got #{args.length}")
            args.each { |arg| infer_expr_type(arg, env) }
            check_affine_consumption(func_name, args, env)
            return sig.return_type
          end
          # Fall through to the standard subtype check below.
        end

        # Standard arg count check
        if args.length != sig.params.length
          add_error("#{func_name}() expects #{sig.params.length} argument(s), got #{args.length}")
        end

        count = [args.length, sig.params.length].min

        count.times do |i|
          arg_type = infer_expr_type(args[i], env)
          expected_type = sig.params[i]
          if !Frontend.subtype?(arg_type, expected_type) && arg_type != "<unknown>"
            add_error(
              "argument #{i + 1} of #{func_name}(): expected '#{expected_type}', " \
              "got '#{arg_type}'"
            )
          end
        end

        (count...args.length).each do |i|
          infer_expr_type(args[i], env)
        end

        # Affine type enforcement
        check_affine_consumption(func_name, args, env)

        sig.return_type
      end

      # -------------------------------------------------------------------
      # Affine consumption
      # -------------------------------------------------------------------

      # Track consumption by *origin*, not variable name, so aliases
      # (`const again = sig`) and property accesses (`this.sig`)
      # cannot launder a double-consumption past the affine check.
      # 2026-04-30 audit finding F6.
      def check_affine_consumption(func_name, args, env)
        consumed_indices = CONSUMING_FUNCTIONS[func_name]
        return if consumed_indices.nil?

        consumed_indices.each do |param_index|
          next if param_index >= args.length

          arg = args[param_index]
          arg_type = affine_expr_type(arg, env)
          next if arg_type.nil? || !AFFINE_TYPES.include?(arg_type)

          origin = affine_origin_of_expr(arg)
          next if origin.nil?

          label =
            if arg.is_a?(Identifier)
              arg.name
            elsif arg.is_a?(PropertyAccessExpr)
              "this.#{arg.property}"
            else
              origin
            end

          if @consumed_values[origin]
            add_error("affine value '#{label}' has already been consumed")
          else
            @consumed_values[origin] = true
          end
        end
      end

      # Resolve the canonical affine origin for an expression.
      def affine_origin_of_expr(expr)
        return nil if expr.nil?
        if expr.is_a?(Identifier)
          @affine_aliases[expr.name] || expr.name
        elsif expr.is_a?(PropertyAccessExpr)
          "prop:#{expr.property}"
        end
      end

      # Look up the type of an expression for affine purposes.
      def affine_expr_type(expr, env)
        return nil if expr.nil?
        if expr.is_a?(Identifier)
          arg_type, found = env.lookup(expr.name)
          found ? arg_type : nil
        elsif expr.is_a?(PropertyAccessExpr)
          @prop_types[expr.property]
        end
      end
    end
  end
end
