"""RawOutputTest -- Exercises add_raw_output alongside add_output for stateful
contracts.
"""

from runar import StatefulSmartContract, Bigint, ByteString, public


class RawOutputTest(StatefulSmartContract):
    """Exercises raw output emission alongside state continuation."""

    count: Bigint

    def __init__(self, count: Bigint):
        super().__init__(count)
        self.count = count

    @public
    def send_to_script(self, script_bytes: ByteString):
        """Emit a raw output with arbitrary script bytes, then increment the
        counter and emit the state continuation."""
        self.add_raw_output(1000, script_bytes)
        self.count = self.count + 1
        self.add_output(0, self.count)
