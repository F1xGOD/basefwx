# SPDX-License-Identifier: GPL-3.0-or-later
#
# BaseFWX Python plugin SPI (3.7.0).
#
# Two ways to author a Python-side plugin:
#
#  1. PURE PYTHON. Subclass :class:`BasefwxPlugin`, override
#     ``forward`` and ``inverse``, register your subclass via the
#     entry-point group ``basefwx.plugins``. The runtime discovers
#     it through ``importlib.metadata.entry_points()``.
#
#  2. NATIVE .so / .dll. Wrap a C-ABI plugin (same shared library
#     used by the C++ host) with :func:`load_native_plugin`. The
#     helper uses ``ctypes`` to call ``basefwx_plugin_entry`` and
#     synthesizes a Python-side :class:`BasefwxPlugin` proxy that
#     forwards every method to the native vtable. This means the
#     same ``.so`` can be loaded from C++, Java (via JNI bridge),
#     and Python without any reimplementation.
#
# Plugins are NOT considered derivative works of BaseFWX as long as
# they only depend on the public ABI/SPI surfaces and ship as
# separate artifacts — see ``LICENSING.md``.

from __future__ import annotations

import abc
import ctypes
import enum
import os
import threading
import warnings
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, Optional


# ABI version this Python SPI conforms to. Mirrors
# BASEFWX_PLUGIN_API_VERSION in cpp/include/basefwx/plugin.h.
API_VERSION = 1

# Length of the stable plugin identifier in bytes.
PLUGIN_ID_LEN = 16


# ---------------------------------------------------------------- positions
class Position(enum.IntFlag):
    """Pipeline positions a plugin can occupy. Bitmask."""

    PRE_AEAD = 1 << 0
    POST_AEAD = 1 << 1


# --------------------------------------------------------------- exceptions
class BasefwxPluginError(Exception):
    """Base for plugin-author error reporting.

    Each concrete subclass maps to a ``BASEFWX_PLUGIN_ERR_*`` code on
    the C side; callers (Python or via JNI) get a typed exception
    they can catch and route on.
    """

    native_code: int = -1


class PluginErrorGeneric(BasefwxPluginError):
    """BASEFWX_PLUGIN_ERR_GENERIC."""
    native_code = -1


class PluginErrorOutputTooSmall(BasefwxPluginError):
    """BASEFWX_PLUGIN_ERR_OUTPUT_TOO_SMALL."""
    native_code = -2


class PluginErrorBadInput(BasefwxPluginError):
    """BASEFWX_PLUGIN_ERR_BAD_INPUT."""
    native_code = -3


class PluginErrorBadState(BasefwxPluginError):
    """BASEFWX_PLUGIN_ERR_BAD_STATE."""
    native_code = -4


class PluginErrorNotSupported(BasefwxPluginError):
    """BASEFWX_PLUGIN_ERR_NOT_SUPPORTED."""
    native_code = -5


_NATIVE_CODE_MAP: Dict[int, type] = {
    -1: PluginErrorGeneric,
    -2: PluginErrorOutputTooSmall,
    -3: PluginErrorBadInput,
    -4: PluginErrorBadState,
    -5: PluginErrorNotSupported,
}


def _raise_for_native_code(code: int, op: str) -> None:
    if code == 0:
        return
    cls = _NATIVE_CODE_MAP.get(code, PluginErrorGeneric)
    raise cls(f"native plugin {op} returned code {code}")


# ------------------------------------------------------------------- plugin
class BasefwxPlugin(abc.ABC):
    """Abstract base class for a Python-side BaseFWX plugin.

    Concrete implementations override :meth:`forward`, :meth:`inverse`,
    :meth:`max_output_for_input`, and optionally :meth:`selftest`.
    The class-level ``PLUGIN_ID``, ``NAME``, ``VERSION``, and
    ``SUPPORTED_POSITIONS`` attributes are required.

    Instances are context-managers — use ``with ... as plugin:`` to
    guarantee :meth:`close` runs and any sensitive state is wiped.
    """

    #: Stable 16-byte identifier. Generate once with ``uuid.uuid4().bytes``
    #: and hard-code into the class. Same value must be returned from
    #: ``plugin_id`` if you also expose this plugin as a C ABI .so.
    PLUGIN_ID: bytes = b""

    NAME: str = ""
    VERSION: str = ""
    SUPPORTED_POSITIONS: int = 0

    def __init__(self, config: bytes = b""):
        """Subclasses MAY override to parse ``config``. Raise
        :class:`PluginErrorBadInput` on malformed config."""
        del config  # default: ignore

    # ----- metadata ----------------------------------------------------

    @classmethod
    def plugin_id(cls) -> bytes:
        if len(cls.PLUGIN_ID) != PLUGIN_ID_LEN:
            raise ValueError(
                f"{cls.__name__}.PLUGIN_ID must be {PLUGIN_ID_LEN} bytes "
                f"(got {len(cls.PLUGIN_ID)})")
        return cls.PLUGIN_ID

    # ----- transform contract -----------------------------------------

    @abc.abstractmethod
    def forward(self, data: bytes) -> bytes:
        """Forward (encrypt-side) transform. ``inverse(forward(x)) == x``."""

    @abc.abstractmethod
    def inverse(self, data: bytes) -> bytes:
        """Inverse (decrypt-side) transform."""

    def max_output_for_input(self, in_len: int) -> int:
        """Worst-case forward output length for ``in_len`` input bytes.
        Default: length-preserving (returns ``in_len``)."""
        return in_len

    def selftest(self) -> bool:
        """Round-trip a fixed vector through forward → inverse.
        Override to test your own vectors. Default returns True iff
        the 32-byte built-in vector round-trips cleanly."""
        kVec = bytes(range(32))
        try:
            mid = self.forward(kVec)
            back = self.inverse(mid)
            return back == kVec
        except BasefwxPluginError:
            return False

    # ----- lifecycle --------------------------------------------------

    def close(self) -> None:
        """Wipe any sensitive state held by the instance.
        Default no-op; subclasses with key material override."""

    def __enter__(self) -> "BasefwxPlugin":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


# ------------------------------------------------------------------ registry
@dataclass(frozen=True)
class _RegistryEntry:
    plugin_id: bytes
    name: str
    version: str
    factory: Callable[[bytes], BasefwxPlugin]


class _PluginRegistry:
    """Thread-safe process-wide plugin registry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_id: Dict[bytes, _RegistryEntry] = {}
        self._discovered_entry_points = False

    def register(self, plugin_cls: type) -> None:
        """Register a :class:`BasefwxPlugin` subclass."""
        plugin_id = plugin_cls.plugin_id()
        entry = _RegistryEntry(
            plugin_id=plugin_id,
            name=getattr(plugin_cls, "NAME", plugin_cls.__name__),
            version=getattr(plugin_cls, "VERSION", "0.0.0"),
            factory=lambda config: plugin_cls(config),
        )
        with self._lock:
            if plugin_id in self._by_id:
                raise RuntimeError(
                    f"plugin id {plugin_id.hex()} already registered")
            self._by_id[plugin_id] = entry

    def register_native(self, lib_path: str) -> None:
        """Wrap a native .so/.dll and register the synthesized plugin."""
        shim = NativePluginShim(lib_path)
        entry = _RegistryEntry(
            plugin_id=shim.plugin_id,
            name=shim.name,
            version=shim.version,
            factory=lambda config, _shim=shim: _shim.instantiate(config),
        )
        with self._lock:
            if shim.plugin_id in self._by_id:
                raise RuntimeError(
                    f"plugin id {shim.plugin_id.hex()} already registered")
            self._by_id[shim.plugin_id] = entry

    def factory_for(self, plugin_id: bytes) -> Optional[_RegistryEntry]:
        with self._lock:
            return self._by_id.get(plugin_id)

    def all(self) -> Iterable[_RegistryEntry]:
        with self._lock:
            return list(self._by_id.values())

    def discover(self) -> int:
        """Walk Python entry points for plugin registrations. Idempotent."""
        with self._lock:
            if self._discovered_entry_points:
                return len(self._by_id)
            self._discovered_entry_points = True
        try:
            from importlib import metadata as importlib_metadata
        except ImportError:  # pragma: no cover - Python < 3.8
            return len(self._by_id)
        try:
            eps = importlib_metadata.entry_points(group="basefwx.plugins")
        except TypeError:
            # Python 3.8/3.9: older entry_points() API
            eps = importlib_metadata.entry_points().get("basefwx.plugins", [])
        for ep in eps:
            try:
                target = ep.load()
                if isinstance(target, type) and issubclass(target, BasefwxPlugin):
                    self.register(target)
                else:
                    warnings.warn(
                        f"basefwx.plugins entry point {ep.name} did not "
                        "resolve to a BasefwxPlugin subclass; skipping",
                        RuntimeWarning, stacklevel=2)
            except Exception as exc:  # noqa: BLE001
                warnings.warn(
                    f"failed to load basefwx.plugins entry point {ep.name}: {exc}",
                    RuntimeWarning, stacklevel=2)
        return len(self._by_id)


_REGISTRY = _PluginRegistry()


def register(plugin_cls: type) -> type:
    """Register a Python plugin class (also usable as a decorator)."""
    _REGISTRY.register(plugin_cls)
    return plugin_cls


def register_native(lib_path: str) -> None:
    """Load a native .so/.dll plugin and add it to the registry."""
    _REGISTRY.register_native(lib_path)


def factory_for(plugin_id: bytes) -> Optional[_RegistryEntry]:
    """Look up the registered factory for a given 16-byte plugin id."""
    return _REGISTRY.factory_for(plugin_id)


def all_plugins() -> Iterable[_RegistryEntry]:
    """Snapshot of all currently registered factories."""
    return _REGISTRY.all()


def discover() -> int:
    """Discover and register plugins published via the
    ``basefwx.plugins`` entry-point group. Idempotent."""
    return _REGISTRY.discover()


# ----------------------------------------------------------- native bridge
class _NativeVtable(ctypes.Structure):
    """ctypes mirror of ``basefwx_plugin_vtable`` (cpp/include/basefwx/plugin.h)."""

    _fields_ = [
        ("api_version", ctypes.c_uint32),
        ("plugin_id", ctypes.c_uint8 * PLUGIN_ID_LEN),
        ("name", ctypes.c_char_p),
        ("version", ctypes.c_char_p),
        ("supported_positions", ctypes.c_uint32),
        ("init", ctypes.CFUNCTYPE(
            ctypes.c_int, ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)),
        ("destroy", ctypes.CFUNCTYPE(None, ctypes.c_void_p)),
        ("forward", ctypes.CFUNCTYPE(
            ctypes.c_int, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t))),
        ("inverse", ctypes.CFUNCTYPE(
            ctypes.c_int, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t))),
        ("max_output_for_input", ctypes.CFUNCTYPE(
            ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t)),
        ("selftest", ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)),
        ("reserved_1", ctypes.c_void_p),
        ("reserved_2", ctypes.c_void_p),
        ("reserved_3", ctypes.c_void_p),
        ("reserved_4", ctypes.c_void_p),
    ]


class NativePluginShim:
    """Wraps a native .so / .dll BaseFWX plugin and exposes it as a
    Python factory. The shim holds the dlopen handle and the vtable
    pointer; instances created via :meth:`instantiate` are
    :class:`_NativePluginProxy` objects that forward each method to
    the C vtable."""

    def __init__(self, lib_path: str):
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"plugin shared library not found: {lib_path}")
        self._lib = ctypes.CDLL(lib_path)
        self._lib.basefwx_plugin_entry.restype = ctypes.POINTER(_NativeVtable)
        self._lib.basefwx_plugin_entry.argtypes = []
        vt_ptr = self._lib.basefwx_plugin_entry()
        if not vt_ptr:
            raise PluginErrorGeneric(
                f"{lib_path}: basefwx_plugin_entry returned NULL")
        vt = vt_ptr.contents
        if vt.api_version != API_VERSION:
            raise PluginErrorNotSupported(
                f"{lib_path}: ABI version {vt.api_version} != host {API_VERSION}")
        self._vtable_ptr = vt_ptr
        self._vtable = vt
        self.plugin_id = bytes(vt.plugin_id)
        self.name = vt.name.decode("utf-8", errors="replace") if vt.name else ""
        self.version = vt.version.decode("utf-8", errors="replace") if vt.version else ""
        self.supported_positions = vt.supported_positions

    def instantiate(self, config: bytes = b"") -> "_NativePluginProxy":
        ctx = ctypes.c_void_p(0)
        cfg = (ctypes.c_uint8 * len(config)).from_buffer_copy(config) if config else None
        cfg_ptr = ctypes.cast(cfg, ctypes.POINTER(ctypes.c_uint8)) if cfg else None
        rc = self._vtable.init(ctypes.byref(ctx), cfg_ptr, len(config))
        _raise_for_native_code(rc, "init")
        return _NativePluginProxy(self, ctx)


class _NativePluginProxy(BasefwxPlugin):
    """Python-side proxy for a native plugin instance."""

    def __init__(self, shim: NativePluginShim, ctx: ctypes.c_void_p):
        # Don't go through BasefwxPlugin.__init__ — we've already
        # initialized via the native vtable.
        self._shim = shim
        self._ctx = ctx
        self._closed = False
        # Mirror the class attributes onto this instance so callers
        # can ``isinstance(x, BasefwxPlugin)`` without surprises.
        self.PLUGIN_ID = shim.plugin_id
        self.NAME = shim.name
        self.VERSION = shim.version
        self.SUPPORTED_POSITIONS = shim.supported_positions

    def _check_open(self) -> None:
        if self._closed:
            raise PluginErrorBadState("plugin already closed")

    def forward(self, data: bytes) -> bytes:
        self._check_open()
        return self._transform(data, inverse=False)

    def inverse(self, data: bytes) -> bytes:
        self._check_open()
        return self._transform(data, inverse=True)

    def max_output_for_input(self, in_len: int) -> int:
        self._check_open()
        return int(self._shim._vtable.max_output_for_input(self._ctx, in_len))

    def selftest(self) -> bool:
        self._check_open()
        return self._shim._vtable.selftest(self._ctx) == 0

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._shim._vtable.destroy(self._ctx)

    def _transform(self, data: bytes, *, inverse: bool) -> bytes:
        cap = self.max_output_for_input(len(data))
        out = (ctypes.c_uint8 * cap)()
        out_len = ctypes.c_size_t(0)
        in_buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data) if data else None
        in_ptr = ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_uint8)) if in_buf else None
        op = self._shim._vtable.inverse if inverse else self._shim._vtable.forward
        rc = op(self._ctx, in_ptr, len(data),
                ctypes.cast(out, ctypes.POINTER(ctypes.c_uint8)),
                cap, ctypes.byref(out_len))
        _raise_for_native_code(rc, "inverse" if inverse else "forward")
        return bytes(out[: out_len.value])


def load_native_plugin(lib_path: str) -> NativePluginShim:
    """Convenience for callers that just want to dlopen a plugin
    without registering it. Use :func:`register_native` to also
    insert it into the registry."""
    return NativePluginShim(lib_path)
