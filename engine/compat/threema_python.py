"""Compatibility bridge for threema.gateway on newer Python runtimes."""

import asyncio
import inspect
import sys


def install_threema_python_compat():
    """Bridge Threema coroutine introspection on Python 3.14+."""
    if sys.version_info < (3, 14):
        return False

    if asyncio.iscoroutinefunction is inspect.iscoroutinefunction:
        return False

    asyncio.iscoroutinefunction = inspect.iscoroutinefunction
    return True
