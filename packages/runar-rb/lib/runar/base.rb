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
      @_data_outputs = []
      @_raw_outputs = []
      @tx_preimage = ''
    end

    def add_output(satoshis, *state_values)
      @_outputs << { satoshis: satoshis, values: state_values }
    end

    # Add a raw output -- arbitrary script bytes not tied to the contract's
    # state continuation. Included in the continuation hash as a state
    # output alongside addOutput results.
    def add_raw_output(satoshis, script_bytes)
      @_raw_outputs << { satoshis: satoshis, script_bytes: script_bytes }
    end

    # Add a data output -- arbitrary script bytes (e.g. OP_RETURN data)
    # that are NOT a state continuation. The output is included in the
    # auto-computed continuation hash after state outputs and before the
    # change output, preserving declaration order.
    def add_data_output(satoshis, script_bytes)
      @_data_outputs << { satoshis: satoshis, script_bytes: script_bytes }
    end

    def get_state_script
      ''
    end

    def reset_outputs
      @_outputs = []
      @_data_outputs = []
      @_raw_outputs = []
    end

    def outputs
      @_outputs
    end

    def raw_outputs
      @_raw_outputs
    end

    def data_outputs
      @_data_outputs
    end
  end
end
