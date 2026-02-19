"""Version resolution for package metadata and runtime engine version."""

from .main import basefwx

try:
    from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
    from importlib.metadata import version as _package_version
except Exception:  # pragma: no cover
    _PackageNotFoundError = Exception
    _package_version = None


_engine_version = str(getattr(basefwx, "ENGINE_VERSION", "")).strip()
if _engine_version and _engine_version.lower() != "unknown":
    __version__ = _engine_version
elif _package_version is not None:
    try:
        __version__ = _package_version("basefwx")
    except _PackageNotFoundError:
        __version__ = "0.0.0"
else:
    __version__ = "0.0.0"


__all__ = ["__version__"]
