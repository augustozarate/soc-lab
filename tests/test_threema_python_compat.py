import asyncio
import inspect
import sys
import warnings


def _legacy_probe(func):
    return inspect.iscoroutinefunction(func)


def test_threema_compat_is_version_scoped():
    from engine.compat.threema_python import install_threema_python_compat

    original = asyncio.iscoroutinefunction

    try:
        asyncio.iscoroutinefunction = _legacy_probe

        changed = install_threema_python_compat()

        if sys.version_info >= (3, 14):
            assert changed is True
            assert asyncio.iscoroutinefunction is inspect.iscoroutinefunction
        else:
            assert changed is False
            assert asyncio.iscoroutinefunction is _legacy_probe
    finally:
        asyncio.iscoroutinefunction = original


def test_threema_compat_is_idempotent():
    from engine.compat.threema_python import install_threema_python_compat

    original = asyncio.iscoroutinefunction

    try:
        asyncio.iscoroutinefunction = _legacy_probe

        first = install_threema_python_compat()
        second = install_threema_python_compat()

        if sys.version_info >= (3, 14):
            assert first is True
            assert second is False
            assert asyncio.iscoroutinefunction is inspect.iscoroutinefunction
        else:
            assert first is False
            assert second is False
            assert asyncio.iscoroutinefunction is _legacy_probe
    finally:
        asyncio.iscoroutinefunction = original


def test_threema_import_is_strict_warning_clean_after_compat():
    from engine.compat.threema_python import install_threema_python_compat

    original = asyncio.iscoroutinefunction

    try:
        install_threema_python_compat()

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            import threema.gateway
    finally:
        asyncio.iscoroutinefunction = original
