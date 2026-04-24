"""DataOutputTest -- Exercises add_data_output alongside state continuation."""

from runar import StatefulSmartContract, Bigint, ByteString, public


class DataOutputTest(StatefulSmartContract):
    """Exercises data-output emission alongside state continuation."""

    count: Bigint

    def __init__(self, count: Bigint):
        super().__init__(count)
        self.count = count

    @public
    def publish(self, payload: ByteString):
        """Increment the counter and attach an arbitrary data output whose
        bytes are committed to by the state continuation hash."""
        self.count = self.count + 1
        self.add_data_output(0, payload)
