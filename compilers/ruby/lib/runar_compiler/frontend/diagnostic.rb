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

      # Format with optional file:line:column prefix.
      def format_message
        if loc && !loc.file.empty?
          if loc.column > 0
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

    # F-026: a .runar.zig call argument list or array literal whose elements
    # are not separated by commas (the TS reference's ZIG_LIST_COMMA).
    ZIG_LIST_COMMA = "expected ',' between list elements"

    # F-026: a second .runar.py statement on the same line (the TS reference's
    # PY_STATEMENT_LINE_BREAK).
    PY_STATEMENT_LINE_BREAK = "expected a line break between statements"

    # The TS reference's refusal of a Java char literal.
    JAVA_CHAR_LITERAL = "char literals are unsupported in Rúnar Java contracts"

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
