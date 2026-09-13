# frozen_string_literal: true

require_relative "dce"

module RunarCompiler
  module Frontend
    # R-237 (CL-GAP-013): warn when DCE strips an un-annotated readonly field.
    #
    # A readonly field with no initializer that no method reads is eliminated
    # from the locking script entirely — silently dropping deploy-time metadata
    # an author may intend to recover from the on-chain script later.
    # +@embedAlways+ fields are forced back in during ANF lowering (a load_prop
    # + @ref alias), so they are "referenced" here and never warn.
    #
    # Four tiers already said this (ts, go, zig, java) and three did not. Port
    # of compilers/go/frontend/embed_always_dce.go, which is itself a port of
    # the TS reference's check in compile().
    module EmbedAlwaysDCE
      module_function

      # @return [Array<String>] one warning per dropped field, in declaration order
      def collect_warnings(contract, program)
        return [] if contract.nil? || program.nil?

        referenced = referenced_props(program)

        contract.properties.filter_map do |prop|
          next unless prop.readonly
          next if prop.respond_to?(:embed_always) && prop.embed_always
          next unless _initializer(prop).nil?
          next if referenced.include?(prop.name)

          "readonly field '#{prop.name}' is not referenced in any method body and was " \
            "eliminated by DCE; annotate it /** @embedAlways */ to preserve it in the " \
            "on-chain script"
        end
      end

      # Property names with a surviving +load_prop+ in a REAL method body.
      #
      # Runs dead-binding elimination on a DEEP COPY first, so a field read only
      # into a never-used local does not count as referenced, and skips the
      # constructor, whose super(...) references every property but is never
      # emitted as script code. Mirrors the Go and TS versions exactly.
      def referenced_props(program)
        probe = Marshal.load(Marshal.dump(program))
        DCE.eliminate_dead_code(probe)

        names = []
        probe.methods.each do |method|
          next if method.name == "constructor"

          _walk_bindings(method.body || [], names)
        end
        names
      end

      def _walk_bindings(bindings, names)
        bindings.each do |binding|
          value = binding.value
          names << value.name if value.kind == "load_prop" && value.name
          _walk_bindings(value.then || [], names) if value.respond_to?(:then)
          _walk_bindings(value.else_ || [], names) if value.respond_to?(:else_)
          _walk_bindings(value.body || [], names) if value.respond_to?(:body)
        end
      end

      def _initializer(prop)
        return prop.initial_value if prop.respond_to?(:initial_value)
        return prop.initializer if prop.respond_to?(:initializer)

        nil
      end
    end
  end
end
