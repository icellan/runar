# D18 - the Python surface: add_raw_output() with a state write and no
# add_output(). Every tier refuses:
#  method 'sendToScript' writes contract state but emits no state
#  continuation: it calls addRawOutput() without addOutput(), and a method
#  that declares its own outputs gets no auto-injected continuation, so the
#  state write would be lost and the contract's satoshis would leave with
#  the spend. Add this.addOutput(satoshis, ...) to carry the new state, or
#  stop writing state in a method meant to end the contract
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
