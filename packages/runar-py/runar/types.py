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


class _FixedArrayMeta(type):
    """Metaclass that makes ``FixedArray[T, N]`` subscriptable at runtime."""

    def __getitem__(cls, item):
        # ``FixedArray[T, N]`` — simply return a type alias that behaves like
        # a plain list at runtime. The Rúnar compiler reads the annotation
        # form directly from source, so this is only for runtime type hints
        # and test instances.
        return list


class FixedArray(list, metaclass=_FixedArrayMeta):
    """Compile-time fixed-size array marker.

    At runtime, ``FixedArray[T, N]`` behaves like ``list`` so contract
    tests can instantiate state with a plain Python list. The Rúnar
    compiler reads the annotation text and lowers it to
    ``FixedArrayType(element=T, length=N)``.
    """
    pass
