# frozen_string_literal: true

# Runar DSL for declaring typed properties and method metadata.
#
# Provides three class methods: `prop`, `runar_public`, and `params`.
# See DESIGN.md for the rationale behind this approach.

module Runar
  module DSL
    def self.included(base)
      base.extend(ClassMethods)
    end

    module ClassMethods
      def prop(name, type, readonly: false)
        @_runar_properties ||= []
        is_readonly = readonly || (self < Runar::SmartContract && !(self < Runar::StatefulSmartContract))
        if is_readonly
          attr_reader name
        else
          attr_accessor name
        end
        @_runar_properties << { name: name, type: type, readonly: is_readonly }
      end

      def runar_public(**param_types)
        @_runar_next_visibility = :public
        @_runar_next_param_types = param_types unless param_types.empty?
      end

      def params(**param_types)
        @_runar_next_param_types = param_types
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
