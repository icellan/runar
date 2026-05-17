from runar import (
    StatefulSmartContract, ByteString, Bigint, Readonly, public,
)


class IntentOutputP2PKH(StatefulSmartContract):
    """Exercises the requireOutputP2PKH intent intrinsic.

    Asserts that output 0 of the spending transaction is a standard
    P2PKH output paying exactly bondAmount satoshis to bondPKH.

    Note: The properties bondPKH and the builtin requireOutputP2PKH are
    spelled in camelCase here (rather than the usual Python snake_case)
    because the all-caps PKH token does not round-trip through the
    naive snake_case <-> camelCase transform shared across the
    cross-tier Python parsers. Writing them in their canonical
    camelCase form avoids the lossy conversion and keeps the AST
    byte-identical to the Go-source ASTAfter Go parser lowercases the
    leading char of BondPKH/RequireOutputP2PKH.
    """

    bondPKH: Readonly[ByteString]
    bondAmount: Readonly[Bigint]
    count: Bigint

    def __init__(self, bondPKH: ByteString, bondAmount: Bigint, count: Bigint):
        super().__init__(bondPKH, bondAmount, count)
        self.bondPKH = bondPKH
        self.bondAmount = bondAmount
        self.count = count

    @public
    def payBond(self):
        requireOutputP2PKH(0, self.bondPKH, self.bondAmount)
        self.count = self.count + 1
