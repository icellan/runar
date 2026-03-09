"""Runar decorators for contract methods."""

from typing import TypeVar, Callable

F = TypeVar('F', bound=Callable)

def public(func: F) -> F:
    """Marks a method as a public spending entry point."""
    func._runar_public = True  # type: ignore
    return func
