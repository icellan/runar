use runar::prelude::*;

/// TerminalVarlenRead -- regression fixture for GitHub issue #100: a terminal
/// method that reads the mutable variable-length (ByteString) state field.
#[runar::contract]
pub struct TerminalVarlenRead {
    pub message: ByteString,
}

impl TerminalVarlenRead {
    pub fn post(&mut self, new_message: ByteString) {
        self.message = new_message;
    }

    pub fn reveal(&self, min_len: Bigint) {
        assert!(len(&self.message) > min_len);
    }
}
