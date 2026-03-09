"""Runar type aliases and marker types.

Python's int is arbitrary precision — perfect for Bitcoin Script numbers.
All byte-string types use bytes for natural == comparison and binary ops.
"""

from typing import TypeVar, Generic

# Scalar types
Bigint = int
Int = int

# Byte-string types
ByteString = bytes
PubKey = bytes
Sig = bytes
Addr = bytes
Sha256 = bytes
Ripemd160 = bytes
SigHashPreimage = bytes
RabinSig = bytes
RabinPubKey = bytes
Point = bytes  # 64 bytes: x[32] || y[32], big-endian, no prefix

# Readonly marker for stateful contract properties
T = TypeVar('T')

class Readonly(Generic[T]):
    """Marks a property as readonly in StatefulSmartContract."""
    pass
