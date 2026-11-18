# D18 - the Python surface: add_raw_output() with a state write and no
# add_output(). Every tier refuses:
#  method 'sendToScript' writes contract state on a path that reaches no
#  addOutput(): a method that declares its own outputs
#  (addOutput/addRawOutput) gets no auto-injected continuation, so on that
#  path the state write would be lost and the contract's satoshis would leave
#  with the spend. Add this.addOutput(satoshis, ...) on every path that
#  writes state, or stop writing state on a path meant to end the contract
from runar import StatefulSmartContract, Bigint, ByteString, public


class N538(StatefulSmartContract):
    count: Bigint

    def __init__(self, count: Bigint):
        super().__init__(count)
        self.count = count

    @public
    def send_to_script(self, script_bytes: ByteString):
        self.add_raw_output(1000, script_bytes)
        self.count = self.count + 1
