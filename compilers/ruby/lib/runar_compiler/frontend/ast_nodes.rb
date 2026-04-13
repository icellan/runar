# frozen_string_literal: true

# AST node types for the Runar compiler frontend.
#
# This module defines all AST node types used by all Runar parsers. It is a
# direct port of compilers/python/runar_compiler/frontend/ast_nodes.py.

module RunarCompiler
  module Frontend
    # -------------------------------------------------------------------
    # Source locations
    # -------------------------------------------------------------------

    # A position in a source file.
    SourceLocation = Struct.new(:file, :line, :column, keyword_init: true) do
      def initialize(file: "", line: 0, column: 0)
        super
      end
    end

    # -------------------------------------------------------------------
    # Type nodes
    # -------------------------------------------------------------------

    # A built-in scalar type like bigint, boolean, ByteString, etc.
    PrimitiveType = Struct.new(:name, keyword_init: true)

    # A fixed-length array type: FixedArray<T, N>.
    FixedArrayType = Struct.new(:element, :length, keyword_init: true)

    # An unrecognized type reference.
    CustomType = Struct.new(:name, keyword_init: true)

    # TypeNode is the union of PrimitiveType, FixedArrayType, and CustomType.
    # In Ruby we rely on duck typing; any of those three structs is a valid
    # TypeNode.

    # -------------------------------------------------------------------
    # Expressions
    # -------------------------------------------------------------------

    # A bigint literal like 42n.
    BigIntLiteral = Struct.new(:value, keyword_init: true)

    # A boolean literal.
    BoolLiteral = Struct.new(:value, keyword_init: true)

    # A hex-encoded byte string literal.
    ByteStringLiteral = Struct.new(:value, keyword_init: true)

    # A variable or name reference.
    Identifier = Struct.new(:name, keyword_init: true)

    # this.x -- property access on the contract.
    PropertyAccessExpr = Struct.new(:property, keyword_init: true)

    # A member access like obj.property (not this.x).
    MemberExpr = Struct.new(:object, :property, keyword_init: true)

    # A binary operation like a + b.
    # op is one of: "+", "-", "*", "/", "%", "===", "!==", "<", "<=",
    #   ">", ">=", "&&", "||", "&", "|", "^", "<<", ">>"
    BinaryExpr = Struct.new(:op, :left, :right, keyword_init: true)

    # A unary operation like !a, -a, ~a.
    # op is one of: "!", "-", "~"
    UnaryExpr = Struct.new(:op, :operand, keyword_init: true)

    # A function/method call.
    CallExpr = Struct.new(:callee, :args, keyword_init: true) do
      def initialize(callee: nil, args: [])
        super
      end
    end

    # A method call on an object: obj.method(args).
    MethodCallExpr = Struct.new(:object, :method, :args, keyword_init: true) do
      def initialize(object: nil, method: nil, args: [])
        super
      end
    end

    # A conditional expression: cond ? a : b.
    TernaryExpr = Struct.new(:condition, :consequent, :alternate, keyword_init: true)

    # Array index access: arr[i].
    IndexAccessExpr = Struct.new(:object, :index, keyword_init: true)

    # i++ or ++i.
    IncrementExpr = Struct.new(:operand, :prefix, keyword_init: true) do
      def initialize(operand: nil, prefix: false)
        super
      end
    end

    # i-- or --i.
    DecrementExpr = Struct.new(:operand, :prefix, keyword_init: true) do
      def initialize(operand: nil, prefix: false)
        super
      end
    end

    # An array literal: [elem, ...].
    ArrayLiteralExpr = Struct.new(:elements, keyword_init: true) do
      def initialize(elements: [])
        super
      end
    end

    # Expression is the union of all expression node types. In Ruby we rely
    # on duck typing; any of the above expression structs is valid.

    # -------------------------------------------------------------------
    # Statements
    # -------------------------------------------------------------------

    # const x: T = expr or let x: T = expr.
    VariableDeclStmt = Struct.new(:name, :type, :mutable, :init, :source_location, keyword_init: true) do
      def initialize(name: nil, type: nil, mutable: false, init: nil, source_location: SourceLocation.new)
        super
      end
    end

    # target = value.
    AssignmentStmt = Struct.new(:target, :value, :source_location, keyword_init: true) do
      def initialize(target: nil, value: nil, source_location: SourceLocation.new)
        super
      end
    end

    # An if/else statement.
    IfStmt = Struct.new(:condition, :then, :else_, :source_location, keyword_init: true) do
      def initialize(condition: nil, then: [], else_: [], source_location: SourceLocation.new)
        super
      end
    end

    # A for loop with constant bounds.
    ForStmt = Struct.new(:init, :condition, :update, :body, :source_location, keyword_init: true) do
      def initialize(init: nil, condition: nil, update: nil, body: [], source_location: SourceLocation.new)
        super
      end
    end

    # A return statement.
    ReturnStmt = Struct.new(:value, :source_location, keyword_init: true) do
      def initialize(value: nil, source_location: SourceLocation.new)
        super
      end
    end

    # An expression used as a statement.
    ExpressionStmt = Struct.new(:expr, :source_location, keyword_init: true) do
      def initialize(expr: nil, source_location: SourceLocation.new)
        super
      end
    end

    # An assert statement: assert(condition) or assert(condition, message).
    AssertStmt = Struct.new(:condition, :message, :source_location, keyword_init: true) do
      def initialize(condition: nil, message: nil, source_location: SourceLocation.new)
        super
      end
    end

    # Statement is the union of all statement node types. In Ruby we rely
    # on duck typing; any of the above statement structs is valid.

    # -------------------------------------------------------------------
    # Top-level nodes
    # -------------------------------------------------------------------

    # A method parameter.
    ParamNode = Struct.new(:name, :type, keyword_init: true) do
      def initialize(name: "", type: nil)
        super
      end
    end

    # A contract property declaration.
    #
    # +synthetic_array_chain+ is attached by the FixedArray expansion pass
    # (+expand_fixed_arrays.rb+) on each synthetic scalar leaf created when a
    # +FixedArray<T, N>+ property is desugared into N scalar siblings.  Each
    # entry is a Hash with +:base+, +:index+, +:length+ keys, outermost first.
    # The artifact assembler uses this marker to re-group the flat synthetic
    # runs back into logical +FixedArray+ ABI and state entries.  User-written
    # scalar properties leave this field as +nil+.
    PropertyNode = Struct.new(:name, :type, :readonly, :initializer, :source_location, :synthetic_array_chain, keyword_init: true) do
      def initialize(name: "", type: nil, readonly: false, initializer: nil, source_location: SourceLocation.new, synthetic_array_chain: nil)
        super
      end
    end

    # A contract method.
    MethodNode = Struct.new(:name, :params, :body, :visibility, :source_location, keyword_init: true) do
      def initialize(name: "", params: [], body: [], visibility: "public", source_location: SourceLocation.new)
        super
      end
    end

    # A contract constructor.
    ConstructorNode = Struct.new(:params, :body, :source_location, keyword_init: true) do
      def initialize(params: [], body: [], source_location: SourceLocation.new)
        super
      end
    end

    # The parsed representation of a Runar smart contract class.
    ContractNode = Struct.new(:name, :parent_class, :properties, :constructor, :methods, :source_file, keyword_init: true) do
      def initialize(name: "", parent_class: "", properties: [], constructor: ConstructorNode.new, methods: [], source_file: "")
        super
      end
    end

    # -------------------------------------------------------------------
    # Primitive type names
    # -------------------------------------------------------------------

    PRIMITIVE_TYPE_NAMES = %w[
      bigint
      boolean
      ByteString
      PubKey
      Sig
      Sha256
      Ripemd160
      Addr
      SigHashPreimage
      RabinSig
      RabinPubKey
      void
      Point
    ].to_set.freeze

    # Return true if +name+ is a recognized Runar primitive type.
    def self.primitive_type?(name)
      PRIMITIVE_TYPE_NAMES.include?(name)
    end
  end
end
