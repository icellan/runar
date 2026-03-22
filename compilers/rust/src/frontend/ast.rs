//! Rúnar AST types.
//!
//! These types mirror the TypeScript `runar-ast.ts` definitions. They represent
//! the parsed contract structure before ANF lowering.

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

/// A contract property declaration.
#[derive(Debug, Clone)]
pub struct PropertyNode {
    pub name: String,
    pub prop_type: TypeNode,
    pub readonly: bool,
    pub initializer: Option<Expression>,
    pub source_location: SourceLocation,
}

/// A method (constructor or named method).
#[derive(Debug, Clone)]
pub struct MethodNode {
    pub name: String,
    pub params: Vec<ParamNode>,
    pub body: Vec<Statement>,
    pub visibility: Visibility,
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

/// Expression variants.
#[derive(Debug, Clone)]
pub enum Expression {
    BinaryExpr {
        op: BinaryOp,
        left: Box<Expression>,
        right: Box<Expression>,
    },
    UnaryExpr {
        op: UnaryOp,
        operand: Box<Expression>,
    },
    CallExpr {
        callee: Box<Expression>,
        args: Vec<Expression>,
    },
    MemberExpr {
        object: Box<Expression>,
        property: String,
    },
    Identifier {
        name: String,
    },
    BigIntLiteral {
        value: i64,
    },
    BoolLiteral {
        value: bool,
    },
    ByteStringLiteral {
        value: String, // hex-encoded
    },
    TernaryExpr {
        condition: Box<Expression>,
        consequent: Box<Expression>,
        alternate: Box<Expression>,
    },
    PropertyAccess {
        property: String, // this.x -> property = "x"
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
