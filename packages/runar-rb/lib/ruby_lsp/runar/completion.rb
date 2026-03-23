# frozen_string_literal: true

# Runar completion listener for the Ruby LSP.
#
# Provides autocompletion suggestions for Runar-specific identifiers
# in .runar.rb contract files:
#
#   1. Type constants (Bigint, ByteString, PubKey, ...) — suggested when
#      typing a bare constant name, e.g. after `prop :name, `.
#
#   2. Builtin function names (sha256, hash160, check_sig, ...) — suggested
#      when typing a bare method call with no explicit receiver.
#
# Activation: only fires for files whose URI ends with `.runar.rb`.
#
# Integration: the Addon class instantiates this listener via
# `create_completion_listener`; the listener then registers itself with
# the Prism dispatcher so it receives AST events for the current request.

module RubyLsp
  module Runar
    # Completion listener that suggests Runar type constants and builtin
    # function names in .runar.rb contract files.
    #
    # See module-level comment for full documentation.
    class Completion
      # All Runar type constant names, matching the constants defined in
      # Runar::Types.
      TYPE_NAMES = Hover::TYPE_DOCS.keys.freeze

      # All Runar builtin function names, derived from Hover::BUILTIN_DOCS
      # to keep a single source of truth.
      BUILTIN_NAMES = Hover::BUILTIN_DOCS.keys.freeze

      # Instantiate the listener and register it with the dispatcher.
      #
      # response_builder - CollectionResponseBuilder[Interface::CompletionItem]
      # node_context     - RubyLsp::NodeContext for the current cursor position
      # dispatcher       - Prism::Dispatcher that fires AST node events
      # uri              - URI::Generic identifying the file being completed
      def initialize(response_builder, _node_context, dispatcher, uri)
        @response_builder = response_builder
        @uri = uri

        return unless runar_file?

        dispatcher.register(
          self,
          :on_constant_read_node_enter,
          :on_call_node_enter
        )
      end

      # Fired when the cursor is on (or within) a bare constant reference.
      #
      # Offers completions for all Runar type constants whose name starts
      # with the characters already typed. This covers the common case of
      # typing a type after `prop :name, `.
      #
      # node - Prism::ConstantReadNode
      def on_constant_read_node_enter(node)
        typed = node.slice
        return if typed.nil? || typed.empty?

        push_type_completions(range_from_location(node.location), typed)
      end

      # Fired when the cursor is on (or within) a method call node.
      #
      # Offers completions for all Runar builtin functions whose name starts
      # with the characters already typed, provided the call has no explicit
      # receiver (i.e. bare calls like `sha2...` rather than `obj.sha2...`).
      #
      # node - Prism::CallNode
      def on_call_node_enter(node)
        return if node.receiver

        message = node.message
        return if message.nil? || message.empty?

        loc = node.message_loc
        return unless loc

        push_builtin_completions(range_from_location(loc), message)
      end

      private

      # Returns true when the current file is a Runar contract file.
      def runar_file?
        @uri.to_s.end_with?('.runar.rb')
      end

      # Pushes type-constant completion items matching the given prefix.
      def push_type_completions(range, prefix)
        TYPE_NAMES.each do |type_name|
          next unless type_name.start_with?(prefix)

          @response_builder << Interface::CompletionItem.new(
            label: type_name,
            filter_text: type_name,
            text_edit: Interface::TextEdit.new(range: range, new_text: type_name),
            kind: Constant::CompletionItemKind::CONSTANT,
            detail: 'Runar type'
          )
        end
      end

      # Pushes builtin-function completion items matching the given prefix.
      def push_builtin_completions(range, prefix)
        BUILTIN_NAMES.each do |builtin|
          next unless builtin.start_with?(prefix)

          @response_builder << Interface::CompletionItem.new(
            label: builtin,
            filter_text: builtin,
            text_edit: Interface::TextEdit.new(range: range, new_text: builtin),
            kind: Constant::CompletionItemKind::METHOD,
            detail: 'Runar builtin'
          )
        end
      end

      # Builds an Interface::Range from a Prism::Location.
      def range_from_location(loc)
        Interface::Range.new(
          start: Interface::Position.new(
            line: loc.start_line - 1,
            character: loc.start_column
          ),
          end: Interface::Position.new(
            line: loc.end_line - 1,
            character: loc.end_column
          )
        )
      end
    end
  end
end
