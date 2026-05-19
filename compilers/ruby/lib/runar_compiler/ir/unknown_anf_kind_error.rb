# frozen_string_literal: true

module RunarCompiler
  module IR
    # Raised by ANF dispatch when it encounters a kind it doesn't handle.
    # Typically because a new ANFValue variant was added without updating
    # all dispatch sites -- see CLAUDE.md § Adding a New ANF Value Kind.
    #
    # Historically these dispatchers used silent `else` fall-throughs that
    # returned a no-op value (empty refs list, unchanged ANFValue, false for
    # side-effect checks). Adding a new ANFValue variant and forgetting to
    # wire it into all dispatch sites would then silently corrupt output
    # instead of failing loudly.
    #
    # Every former silent default now throws this error so the regression
    # is caught at the first dispatch site instead of leaking into Stack
    # IR / hex.
    class UnknownANFKindError < StandardError
      attr_reader :kind, :location

      def initialize(kind, location)
        @kind = kind
        @location = location
        super(
          "unknown ANF kind #{kind.inspect} encountered in #{location} -- " \
          "if you added a new ANFValue variant, update all dispatch sites " \
          "(see CLAUDE.md § Adding a New ANF Value Kind)"
        )
      end
    end
  end
end
