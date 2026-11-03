# frozen_string_literal: true

# Runar DSL for declaring typed properties and method metadata.
#
# Provides four class methods: `prop`, `runar_public`, `params`, and
# `runar_sighash`.
# See DESIGN.md for the rationale behind this approach.

module Runar
  module DSL
    def self.included(base)
      base.extend(ClassMethods)
    end

    module ClassMethods
      # Declare a typed property on a Runar contract.
      #
      # Options:
      #   readonly: true   -- generates only a reader; the property cannot be
      #                       mutated by contract methods.
      #   default: value   -- provides an initial value so the property is
      #                       excluded from the auto-generated constructor.
      #                       The default is set before the developer-written
      #                       initialize runs.
      #   embed_always: true -- the native spelling of the compiler's
      #                       `@embedAlways` directive (N-093): keeps the
      #                       readonly property in the locking script even
      #                       when no method reads it. Recorded in the
      #                       property metadata (only when true); it has no
      #                       runtime effect.
      def prop(name, type, readonly: false, default: :__no_default__, embed_always: false)
        @_runar_properties ||= []
        is_readonly = readonly || (self < Runar::SmartContract && !(self < Runar::StatefulSmartContract))
        if is_readonly
          attr_reader name
        else
          attr_accessor name
        end

        has_default = default != :__no_default__
        if has_default
          @_runar_defaults      ||= {}
          @_runar_defaults[name]  = default
        end

        entry = { name: name, type: type, readonly: is_readonly, default: has_default ? default : nil }
        entry[:embed_always] = true if embed_always
        @_runar_properties << entry
      end

      # Returns the hash of { property_name => default_value } for this class
      # and all its superclasses (merged, with the most specific class winning).
      def runar_defaults
        @_runar_defaults || {}
      end

      def runar_public(**param_types)
        @_runar_next_visibility = :public
        @_runar_next_param_types = param_types unless param_types.empty?
      end

      def params(**param_types)
        @_runar_next_param_types = param_types
      end

      # `runar_sighash 'SINGLE|FORKID'` -- the native spelling of the
      # compiler's `@sighash` directive (N-093): declares the BIP-143 sighash
      # mode of the next public method. The compiler reads it from the source;
      # at runtime it is a no-op.
      def runar_sighash(_flags)
        nil
      end

      # Hook: when a method is defined, attach pending visibility/param metadata.
      def method_added(method_name)
        return if method_name == :initialize
        return unless @_runar_next_visibility || @_runar_next_param_types

        @_runar_methods ||= {}
        @_runar_methods[method_name] = {
          visibility: @_runar_next_visibility || :private,
          param_types: @_runar_next_param_types || {}
        }
        @_runar_next_visibility = nil
        @_runar_next_param_types = nil
        super
      end

      def runar_properties
        @_runar_properties || []
      end

      def runar_methods
        @_runar_methods || {}
      end
    end
  end
end
