"""Runar decorators for contract methods."""

from typing import TypeVar, Callable

F = TypeVar('F', bound=Callable)

def public(func: F | None = None, *, sighash: str | None = None):
    """Marks a method as a public spending entry point.

    Usable bare (``@public``) or with the keyword ``sighash``
    (``@public(sighash="SINGLE|FORKID")``, N-093: the Python spelling of the
    ``@sighash`` directive, read by the compiler from source). Both forms
    return the decorated function itself.
    """
    def mark(f: F) -> F:
        f._runar_public = True  # type: ignore
        return f

    if func is None:
        return mark
    return mark(func)
