# frozen_string_literal: true

# Structured compiler diagnostics.
#
# This module defines the Diagnostic class used to report errors and warnings
# during compilation. It is a direct port of
# compilers/python/runar_compiler/frontend/diagnostic.py.

require_relative "ast_nodes"

module RunarCompiler
  module Frontend
    # Severity constants for diagnostics.
    module Severity
      ERROR   = "error"
      WARNING = "warning"
    end

    # A single compiler diagnostic (error or warning).
    Diagnostic = Struct.new(:message, :severity, :loc, keyword_init: true) do
      def initialize(message:, severity:, loc: nil)
        super
      end

      # Format with optional file:line:column prefix. The column is 0-based
      # (N-078, R88a), so column 0 is a real position and prints as `:0`;
      # only an unknown line (0) drops the column.
      def format_message
        if loc && !loc.file.empty?
          if loc.line > 0
            return "#{loc.file}:#{loc.line}:#{loc.column}: #{message}"
          end

          return "#{loc.file}:#{loc.line}: #{message}"
        end

        message
      end

      def to_s
        format_message
      end
    end

    # F-011's shared diagnostic (the TS reference's UNTERMINATED_STRING_LITERAL):
    # every hand-written tokenizer emits it, at the opening quote, for a quoted
    # literal that reaches a line break or end of file before its closing
    # quote. On .runar.rs, for Python triple-quoted strings, .runar.go backtick
    # raw strings and .runar.ts template literals, which may span lines, only
    # end of file counts.
    UNTERMINATED_STRING_LITERAL = "unterminated string literal"

    # N-121 (user decision R85; the TS reference's OPTIONAL_CHAINING): a
    # .runar.ts +?.+, located at the +?+. Only the first +?.+ in a file is
    # reported.
    OPTIONAL_CHAINING = "optional chaining '?.' is not supported"

    # F-203: a .runar.py string or bytes literal escape that CPython does not
    # define for that literal kind (\q; \N, \u, \U in bytes), a \x not
    # followed by two hex digits, an octal escape above 0o377, or a \N{..} /
    # \u / \U escape in a plain string, which the surface does not support
    # (the TS reference's invalidEscapeSequenceMessage). `escape` is the
    # backslash plus the escape letter, or the whole octal escape.
    def self.invalid_escape_sequence_message(escape)
      "invalid escape sequence '#{escape}'"
    end

    # F-203: CPython's refusal of a non-ASCII character inside b'..' / b".."
    # (the TS reference's PY_BYTES_NON_ASCII).
    PY_BYTES_NON_ASCII = "bytes can only contain ASCII literal characters"

    # F-026: a .runar.zig call argument list or array literal whose elements
    # are not separated by commas (the TS reference's ZIG_LIST_COMMA).
    ZIG_LIST_COMMA = "expected ',' between list elements"

    # F-026: a second .runar.py statement on the same line (the TS reference's
    # PY_STATEMENT_LINE_BREAK).
    PY_STATEMENT_LINE_BREAK = "expected a line break between statements"

    # The TS reference's refusal of a Java char literal.
    JAVA_CHAR_LITERAL = "char literals are unsupported in Rúnar Java contracts"

    # N-053's refusal of a .runar.rb / .runar.py statement whose first token
    # can begin neither a statement nor an expression (the TS reference's
    # unsupportedStatementMessage). +token+ is the token's source text.
    def self.unsupported_statement_message(token)
      "Unsupported statement starting with '#{token}'"
    end

    # N-004's refusal of a .runar.rb class-body token that is not `prop`,
    # `runar_public`, `params`, `def` or a bare `private` / `public` marker
    # (the TS reference's unexpectedClassBodyTokenMessage). It used to be
    # skipped, so an indented `=begin` (lexed as `=`, `begin`) let a
    # "commented-out" method become the only spend path.
    def self.unexpected_class_body_token_message(token)
      "Unexpected token in class body: '#{token}'"
    end

    # N-004's refusal of the first token after a .runar.rb class's `end` (the
    # TS reference's unexpectedTokenAfterClassMessage).
    def self.unexpected_token_after_class_message(token)
      "Unexpected token after class end: '#{token}'"
    end

    # N-050's refusal of a static or class-level method (the TS reference's
    # staticMethodMessage): `static` on .runar.ts / .runar.java,
    # `@staticmethod` / `@classmethod` on .runar.py, `def self.m` on
    # .runar.rb, and a `pub fn` without a self receiver on .runar.rs /
    # .runar.zig. `name` is the method name as written in the source.
    def self.static_method_message(name)
      "static methods are not allowed in Rúnar contracts; method '#{name}' is declared static"
    end

    # N-023's (R49) refusal, on the .runar.java surface, of an assignment
    # (=, op=, ++, --) to a bare property name that no local or parameter
    # shadows (the TS reference's bareJavaPropertyAssignmentMessage). In Java
    # that bare name IS the field.
    def self.bare_java_property_assignment_message(name)
      "bare assignment to property '#{name}' is not allowed; write `this.#{name} = ...`"
    end

    # A tokenizer diagnostic located at line:column of file.
    def self.lex_error(message, file, line, column)
      Diagnostic.new(message: message, severity: Severity::ERROR,
                     loc: SourceLocation.new(file: file, line: line, column: column))
    end

    # Put a tokenizer's diagnostics (F-011) in front of a ParseResult's own.
    def self.with_lex_errors(result, lex)
      result.errors = lex + result.errors unless lex.empty?
      result
    end
  end
end
require_relative "int_literal"
