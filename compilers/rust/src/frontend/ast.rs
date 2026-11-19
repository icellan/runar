//! Rúnar AST types.
//!
//! These types mirror the TypeScript `runar-ast.ts` definitions. They represent
//! the parsed contract structure before ANF lowering.

use num_bigint::BigInt;

// ---------------------------------------------------------------------------
// Source locations
// ---------------------------------------------------------------------------

/// Source location in the original file.
#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Primitive type names recognized by Rúnar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimitiveTypeName {
    Bigint,
    Boolean,
    ByteString,
    PubKey,
    Sig,
    Sha256,
    Ripemd160,
    Addr,
    SigHashPreimage,
    RabinSig,
    RabinPubKey,
    Point,
    P256Point,
    P384Point,
    Void,
}

impl PrimitiveTypeName {
    /// Parse a string into a PrimitiveTypeName, if recognized.
    pub fn from_str(s: &str) -> Option<PrimitiveTypeName> {
        match s {
            "bigint" => Some(PrimitiveTypeName::Bigint),
            "boolean" => Some(PrimitiveTypeName::Boolean),
            "ByteString" => Some(PrimitiveTypeName::ByteString),
            "PubKey" => Some(PrimitiveTypeName::PubKey),
            "Sig" => Some(PrimitiveTypeName::Sig),
            "Sha256" => Some(PrimitiveTypeName::Sha256),
            "Ripemd160" => Some(PrimitiveTypeName::Ripemd160),
            "Addr" => Some(PrimitiveTypeName::Addr),
            "SigHashPreimage" => Some(PrimitiveTypeName::SigHashPreimage),
            "RabinSig" => Some(PrimitiveTypeName::RabinSig),
            "RabinPubKey" => Some(PrimitiveTypeName::RabinPubKey),
            "Point" => Some(PrimitiveTypeName::Point),
            "P256Point" => Some(PrimitiveTypeName::P256Point),
            "P384Point" => Some(PrimitiveTypeName::P384Point),
            "void" => Some(PrimitiveTypeName::Void),
            _ => None,
        }
    }

    /// Convert back to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            PrimitiveTypeName::Bigint => "bigint",
            PrimitiveTypeName::Boolean => "boolean",
            PrimitiveTypeName::ByteString => "ByteString",
            PrimitiveTypeName::PubKey => "PubKey",
            PrimitiveTypeName::Sig => "Sig",
            PrimitiveTypeName::Sha256 => "Sha256",
            PrimitiveTypeName::Ripemd160 => "Ripemd160",
            PrimitiveTypeName::Addr => "Addr",
            PrimitiveTypeName::SigHashPreimage => "SigHashPreimage",
            PrimitiveTypeName::RabinSig => "RabinSig",
            PrimitiveTypeName::RabinPubKey => "RabinPubKey",
            PrimitiveTypeName::Point => "Point",
            PrimitiveTypeName::P256Point => "P256Point",
            PrimitiveTypeName::P384Point => "P384Point",
            PrimitiveTypeName::Void => "void",
        }
    }
}

/// A type node in the AST.
#[derive(Debug, Clone)]
pub enum TypeNode {
    Primitive(PrimitiveTypeName),
    FixedArray {
        element: Box<TypeNode>,
        length: usize,
    },
    Custom(String),
}

// ---------------------------------------------------------------------------
// Top-level nodes
// ---------------------------------------------------------------------------

/// A complete Rúnar contract.
#[derive(Debug, Clone)]
pub struct ContractNode {
    pub name: String,
    pub parent_class: String, // "SmartContract" or "StatefulSmartContract"
    pub properties: Vec<PropertyNode>,
    pub constructor: MethodNode,
    pub methods: Vec<MethodNode>,
    pub source_file: String,
}

/// One level of the synthetic-array chain attached to expanded leaf
/// properties. Mirrors the TS `__syntheticArrayChain` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticArrayLevel {
    pub base: String,
    pub index: usize,
    pub length: usize,
}

/// A contract property declaration.
#[derive(Debug, Clone)]
pub struct PropertyNode {
    pub name: String,
    pub prop_type: TypeNode,
    pub readonly: bool,
    pub initializer: Option<Expression>,
    /// Issue #109: set by the parser when a `/** @embedAlways */` (or
    /// `// @embedAlways`) comment directive immediately precedes a readonly
    /// field. Opts the field OUT of dead-code elimination so its deploy-time
    /// bytes survive into the on-chain locking script (a constructor slot).
    /// Comment-directive form (not a decorator) keeps it portable across
    /// surface formats. Only meaningful on readonly fields.
    pub embed_always: bool,
    pub source_location: SourceLocation,
    /// Non-empty for synthetic scalar leaves produced by the
    /// expand-fixed-arrays pass. Outermost level first. Used by the
    /// assembler to re-group these back into a single (possibly nested)
    /// FixedArray ABI/state entry.
    pub synthetic_array_chain: Option<Vec<SyntheticArrayLevel>>,
}

/// A method (constructor or named method).
#[derive(Debug, Clone)]
pub struct MethodNode {
    pub name: String,
    pub params: Vec<ParamNode>,
    pub body: Vec<Statement>,
    pub visibility: Visibility,
    /// Issue #123: the BIP-143 sighash type declared via a
    /// `/** @sighash <FLAGS> */` directive on a public method (e.g. `0x43`
    /// for SINGLE|FORKID). `None` = the default `ALL|FORKID` (0x41),
    /// byte-identical to the historically-pinned mode. Drives the
    /// auto-injected preimage-type assert, the OP_PUSH_TX binding flag, the
    /// ABI `sigHashType`, and the SDK-side preimage/signature construction.
    pub sighash_type: Option<i64>,
    /// The Any-S OP_PUSH_TX binding construction from a
    /// `/** @bindingVariant <lowS|all> */` directive on a public `.runar.ts`
    /// method (ports #170). `None` = the default lowS. `Some("all")` selects
    /// the compact non-low-S blob, spendable only when the spending tx has
    /// nVersion > 1.
    pub binding_variant: Option<String>,
    /// D12 FE-F4: the return type the source declares, when its surface
    /// syntax can spell one (Ruby cannot; TypeScript may omit it). `None` =
    /// inferred from the body by the type checker, with the full
    /// environment. The type checker enforces it on every `return` and gives
    /// it to every call.
    pub return_type: Option<TypeNode>,
    pub source_location: SourceLocation,
}

/// Method visibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Private,
}

/// A method parameter.
#[derive(Debug, Clone)]
pub struct ParamNode {
    pub name: String,
    pub param_type: TypeNode,
}

// ---------------------------------------------------------------------------
// Statements
// ---------------------------------------------------------------------------

/// Statement variants.
#[derive(Debug, Clone)]
pub enum Statement {
    VariableDecl {
        name: String,
        var_type: Option<TypeNode>,
        mutable: bool,
        init: Expression,
        source_location: SourceLocation,
    },
    Assignment {
        target: Expression,
        value: Expression,
        source_location: SourceLocation,
    },
    IfStatement {
        condition: Expression,
        then_branch: Vec<Statement>,
        else_branch: Option<Vec<Statement>>,
        source_location: SourceLocation,
    },
    ForStatement {
        init: Box<Statement>, // Always VariableDecl
        condition: Expression,
        update: Box<Statement>,
        body: Vec<Statement>,
        source_location: SourceLocation,
    },
    ReturnStatement {
        value: Option<Expression>,
        source_location: SourceLocation,
    },
    ExpressionStatement {
        expression: Expression,
        source_location: SourceLocation,
    },
}

impl Statement {
    /// The statement's own source location (every variant carries one).
    pub fn source_location(&self) -> &SourceLocation {
        match self {
            Statement::VariableDecl { source_location, .. }
            | Statement::Assignment { source_location, .. }
            | Statement::IfStatement { source_location, .. }
            | Statement::ForStatement { source_location, .. }
            | Statement::ReturnStatement { source_location, .. }
            | Statement::ExpressionStatement { source_location, .. } => source_location,
        }
    }

    /// Mutable access to the statement's own source location (every variant
    /// carries one). Parsers that build a statement after consuming it use
    /// this to stamp the position of its first token (F-337).
    pub fn source_location_mut(&mut self) -> &mut SourceLocation {
        match self {
            Statement::VariableDecl { source_location, .. }
            | Statement::Assignment { source_location, .. }
            | Statement::IfStatement { source_location, .. }
            | Statement::ForStatement { source_location, .. }
            | Statement::ReturnStatement { source_location, .. }
            | Statement::ExpressionStatement { source_location, .. } => source_location,
        }
    }
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

/// Binary operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryOp {
    Add,       // +
    Sub,       // -
    Mul,       // *
    Div,       // /
    Mod,       // %
    StrictEq,  // ===
    StrictNe,  // !==
    Lt,        // <
    Le,        // <=
    Gt,        // >
    Ge,        // >=
    And,       // &&
    Or,        // ||
    BitAnd,    // &
    BitOr,     // |
    BitXor,    // ^
    Shl,       // <<
    Shr,       // >>
}

impl BinaryOp {
    /// Convert to the string representation used in ANF IR.
    pub fn as_str(&self) -> &'static str {
        match self {
            BinaryOp::Add => "+",
            BinaryOp::Sub => "-",
            BinaryOp::Mul => "*",
            BinaryOp::Div => "/",
            BinaryOp::Mod => "%",
            BinaryOp::StrictEq => "===",
            BinaryOp::StrictNe => "!==",
            BinaryOp::Lt => "<",
            BinaryOp::Le => "<=",
            BinaryOp::Gt => ">",
            BinaryOp::Ge => ">=",
            BinaryOp::And => "&&",
            BinaryOp::Or => "||",
            BinaryOp::BitAnd => "&",
            BinaryOp::BitOr => "|",
            BinaryOp::BitXor => "^",
            BinaryOp::Shl => "<<",
            BinaryOp::Shr => ">>",
        }
    }
}

/// Unary operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnaryOp {
    Not,    // !
    Neg,    // -
    BitNot, // ~
}

impl UnaryOp {
    /// Convert to the string representation used in ANF IR.
    pub fn as_str(&self) -> &'static str {
        match self {
            UnaryOp::Not => "!",
            UnaryOp::Neg => "-",
            UnaryOp::BitNot => "~",
        }
    }
}

/// D12 FE-F1: the operand family the type checker records on an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandType {
    Bytes,
    Numeric,
}

/// D12 FE-F1: the slot an operator node carries its operand family in. The
/// type checker walks the AST through `&` borrows, so the slot is a `Cell`.
#[derive(Debug, Clone, Default)]
pub struct OperandSlot(std::cell::Cell<Option<OperandType>>);

impl OperandSlot {
    pub fn get(&self) -> Option<OperandType> {
        self.0.get()
    }
    pub fn set(&self, t: Option<OperandType>) {
        self.0.set(t)
    }
}

// The slot holds a `Copy` value replaced whole by `set`, so a panic can never
// leave it half-written: observing it after `catch_unwind` (as callers of
// `lower_to_anf` do) is sound. Without this, `Cell` would make every
// `&ContractNode` non-`RefUnwindSafe`.
impl std::panic::RefUnwindSafe for OperandSlot {}

/// A slot already holding `t` (for nodes a pass synthesises after the type
/// checker ran, e.g. expand_fixed_arrays' index dispatch).
pub fn operand_slot(t: OperandType) -> OperandSlot {
    OperandSlot(std::cell::Cell::new(Some(t)))
}

/// Binary operators whose lowering depends on the operand family (D12 FE-F1).
pub fn is_typed_binary_op(op: &BinaryOp) -> bool {
    matches!(
        op,
        BinaryOp::Add
            | BinaryOp::StrictEq
            | BinaryOp::StrictNe
            | BinaryOp::BitAnd
            | BinaryOp::BitOr
            | BinaryOp::BitXor
    )
}

/// Expression variants.
#[derive(Debug, Clone)]
pub enum Expression {
    BinaryExpr {
        op: BinaryOp,
        left: Box<Expression>,
        right: Box<Expression>,
        /// Where the expression starts, including a leading `(` (N-472).
        /// Every surface parser sets it, as the TS reference does; a node a
        /// parser synthesizes carries `None` and the type checker falls back
        /// to the leftmost leaf.
        source_location: Option<SourceLocation>,
        /// D12 FE-F1: the operand family the TYPE CHECKER resolved for an
        /// operator whose lowering depends on it (`+` = OP_CAT vs OP_ADD,
        /// `===` / `!==` = OP_EQUAL vs OP_NUMEQUAL, `& | ^` on byte strings vs
        /// numbers). Written by the type checker through a shared `&` borrow
        /// (hence the `Cell`) and by expand_fixed_arrays for the nodes it
        /// synthesises; a clone keeps it. ANF lowering refuses a typed
        /// operator that carries none. Never set by a parser.
        operand_type: OperandSlot,
    },
    UnaryExpr {
        op: UnaryOp,
        operand: Box<Expression>,
        /// The operator token (N-472); every surface parser sets it.
        source_location: Option<SourceLocation>,
        /// D12 FE-F1: see `BinaryExpr::operand_type`; used for `~`.
        operand_type: OperandSlot,
    },
    CallExpr {
        callee: Box<Expression>,
        args: Vec<Expression>,
        /// Set only for the expression form `asm<T>({...})` of the asm
        /// compiler intrinsic. Carries the captured primitive return type
        /// ("bigint", "boolean", or "ByteString"); `None` for the statement
        /// form and for every non-asm call.
        asm_return_type: Option<String>,
    },
    MemberExpr {
        object: Box<Expression>,
        property: String,
    },
    Identifier {
        name: String,
        /// The identifier's token (N-463). Every surface parser sets it, as
        /// the TS reference does; a synthesized identifier carries `None`. The
        /// type checker derives a composite expression's position from it.
        source_location: Option<SourceLocation>,
    },
    BigIntLiteral {
        /// Arbitrary-precision integer literal.
        ///
        /// Widened from `i128` so 256-bit constants (e.g. the secp256k1 group
        /// order used in schnorr-zkp's s-bound assert) round-trip losslessly
        /// from the SWC parser's `num_bigint::BigInt` token through ANF /
        /// Stack IR and into the final push-encoded Bitcoin Script bytes.
        /// Mirrors Go's `*big.Int`-backed `BigIntLit` AST node.
        value: BigInt,
    },
    BoolLiteral {
        value: bool,
    },
    ByteStringLiteral {
        value: String, // hex-encoded
        /// The literal's opening quote (N-432). Only the `.runar.ts` parser
        /// sets it, as the TS reference does; elsewhere it is `None` and the
        /// hex diagnostics print no location.
        source_location: Option<SourceLocation>,
    },
    TernaryExpr {
        condition: Box<Expression>,
        consequent: Box<Expression>,
        alternate: Box<Expression>,
    },
    PropertyAccess {
        property: String, // this.x -> property = "x"
        /// The `this` token (N-463); `.runar.ts` parser only.
        source_location: Option<SourceLocation>,
    },
    IndexAccess {
        object: Box<Expression>,
        index: Box<Expression>,
    },
    IncrementExpr {
        operand: Box<Expression>,
        prefix: bool,
    },
    DecrementExpr {
        operand: Box<Expression>,
        prefix: bool,
    },
    ArrayLiteral {
        elements: Vec<Expression>,
    },
}
