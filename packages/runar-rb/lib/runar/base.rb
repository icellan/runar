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
      # Base constructor — contracts call super(...)
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
