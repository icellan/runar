# N-244: the sighash marker glued to its flag list on the Python surface.
# Only .runar.ts honours the directive; every other surface must refuse ANY
# occurrence of the marker (N-039's rule), not just a word-bounded one, with
# the one shared "not supported by the Python surface parser" message.
# Before N-244 every tier read the glued form as prose and compiled ALL|FORKID.
from runar import StatefulSmartContract, Bigint, public


class Counter(StatefulSmartContract):
    count: Bigint

    def __init__(self, count: Bigint):
        super().__init__(count)
        self.count = count

    # @sighashSINGLE|FORKID
    @public
    def increment(self):
        self.count += 1
