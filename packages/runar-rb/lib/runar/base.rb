# frozen_string_literal: true

# Runar base contract classes.

module Runar
  # Base class for stateless Runar smart contracts.
  #
  # All properties are readonly. The contract logic is pure — no state
  # is carried between spending transactions.
  class SmartContract
    include Runar::DSL

    def initialize(*args)
      # Apply property defaults declared with `default:`. Subclasses should
      # call `super(...)` at the beginning of their `initialize` method so
      # that defaults are set before any custom initialization logic runs.
      self.class.runar_defaults.each do |prop_name, default_value|
        instance_variable_set(:"@#{prop_name}", default_value)
      end
    end
  end

  # Base class for stateful Runar smart contracts.
  #
  # Mutable properties are carried in the UTXO state. The compiler
  # auto-injects checkPreimage at method entry and state continuation
  # at exit.
  class StatefulSmartContract < SmartContract
    attr_accessor :tx_preimage

    def initialize(*args)
      super
      @_outputs = []
      @tx_preimage = ''
    end

    def add_output(satoshis, *state_values)
      @_outputs << { satoshis: satoshis, values: state_values }
    end

    def get_state_script
      ''
    end

    def reset_outputs
      @_outputs = []
    end

    def outputs
      @_outputs
    end
  end
end
