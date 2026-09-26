"""Loader for the optional native crypto library (native/spacecop_crypto.c).

The VPN's data path is ChaCha20-Poly1305.  The pure-Python implementation in
this package is the reference; when a compiled ``spacecop_crypto`` shared
library is found, :mod:`spacecop.crypto.aead` routes through it instead, which
is 50-100x faster.  Nothing else changes: same algorithms, same wire format,
and the two are cross-checked in tests/test_native_crypto.py.

Search order (first hit wins):

1. ``SPACECOP_NATIVE`` environment variable — a file or a directory.
2. A directory registered with :func:`set_native_dir` (Android passes the
   app's nativeLibraryDir).
3. ``spacecop/crypto/lib/`` (native/build.sh puts it there).
4. Next to the running executable / PyInstaller bundle directory.
5. The system loader (``ctypes.util.find_library``).

Set ``SPACECOP_PURE=1`` to force the Python implementation.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
from typing import List, Optional

_NAMES = ("libspacecop_crypto.so", "spacecop_crypto.dll", "libspacecop_crypto.dylib",
          "libspacecop_crypto.dll", "spacecop_crypto.so")

_lib: Optional[ctypes.CDLL] = None      # releases the GIL (large buffers)
_lib_gil: Optional[ctypes.CDLL] = None  # keeps the GIL (small buffers: no thrash)
_tried = False
# Below this size a call is only a few microseconds, and dropping/re-taking
# the GIL around it costs more than the work (and stalls other threads).
GIL_RELEASE_THRESHOLD = 32 * 1024
_path: Optional[str] = None
_extra_dirs: List[str] = []
_errors: List[str] = []       # why each attempted candidate was rejected


def set_native_dir(path: str) -> None:
    """Add a directory to search (call before first use; resets the cache)."""
    global _tried, _lib, _lib_gil
    if path and path not in _extra_dirs:
        _extra_dirs.insert(0, path)
    _tried = False
    _lib = _lib_gil = None


def _candidates() -> List[str]:
    """Candidate library locations, best first.

    Includes both absolute paths (checked for existence) and *bare sonames*
    handed straight to the dynamic linker.  The bare names matter on Android,
    where with the default ``extractNativeLibs=false`` the ``.so`` lives inside
    the APK (no file on disk), so only ``dlopen("libspacecop_crypto.so")`` via
    the linker's search path finds it."""
    out: List[str] = []
    env = os.environ.get("SPACECOP_NATIVE")
    dirs: List[str] = []
    if env:
        if os.path.isfile(env):
            out.append(env)
        else:
            dirs.append(env)
    dirs.extend(_extra_dirs)
    dirs.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
    bundle = getattr(sys, "_MEIPASS", None)
    if bundle:
        dirs.append(bundle)
    dirs.append(os.path.dirname(os.path.abspath(sys.executable)))
    for d in dirs:
        for name in _NAMES:
            path = os.path.join(d, name)
            if os.path.isfile(path):
                out.append(path)
    found = ctypes.util.find_library("spacecop_crypto")
    if found:
        out.append(found)
    # Bare sonames, resolved by the dynamic linker (Android, or any system
    # library path). Attempted even when no file is visible on disk.
    for name in _NAMES:
        out.append(name)
    return out


def _bind(lib: ctypes.CDLL) -> None:
    u8p = ctypes.c_char_p
    lib.sc_version.restype = ctypes.c_char_p
    lib.sc_version.argtypes = []
    lib.sc_aead_encrypt.restype = ctypes.c_int
    lib.sc_aead_encrypt.argtypes = [u8p, u8p, u8p, ctypes.c_size_t, u8p, ctypes.c_size_t, ctypes.c_void_p]
    lib.sc_aead_decrypt.restype = ctypes.c_int
    lib.sc_aead_decrypt.argtypes = [u8p, u8p, u8p, ctypes.c_size_t, u8p, ctypes.c_size_t, ctypes.c_void_p]
    lib.sc_chacha20_xor.restype = ctypes.c_int
    lib.sc_chacha20_xor.argtypes = [u8p, ctypes.c_uint32, u8p, u8p, ctypes.c_size_t, ctypes.c_void_p]
    lib.sc_poly1305.restype = ctypes.c_int
    lib.sc_poly1305.argtypes = [u8p, u8p, ctypes.c_size_t, ctypes.c_void_p]


def load() -> Optional[ctypes.CDLL]:
    """Return the loaded library, or None (cached after the first attempt)."""
    global _lib, _lib_gil, _tried, _path
    if _tried:
        return _lib
    _tried = True
    _errors.clear()
    if os.environ.get("SPACECOP_PURE"):
        _errors.append("SPACECOP_PURE set: forced pure Python")
        return None
    seen = set()
    for cand in _candidates():
        if cand in seen:
            continue
        seen.add(cand)
        try:
            lib = ctypes.CDLL(cand)
            _bind(lib)
            lib.sc_version()          # proves the symbols are really there
        except (OSError, AttributeError) as exc:
            _errors.append(f"{cand}: {exc}")
            continue
        # A second handle that keeps the GIL for small buffers. If PyDLL is
        # unavailable (some embeddings), reuse the CDLL handle rather than
        # dropping the whole library.
        try:
            lib_gil = ctypes.PyDLL(cand)
            _bind(lib_gil)
        except (OSError, AttributeError) as exc:
            _errors.append(f"PyDLL {cand}: {exc} (using CDLL for small buffers)")
            lib_gil = lib
        _lib, _lib_gil, _path = lib, lib_gil, cand
        break
    return _lib


def available() -> bool:
    return load() is not None


def path() -> Optional[str]:
    load()
    return _path


def version() -> Optional[str]:
    lib = load()
    return lib.sc_version().decode() if lib else None


def diagnostics() -> str:
    """One line for logs: the chosen library, or the candidates tried and why
    each was rejected.  Used by the Android app when the backend is Python."""
    load()
    if _path:
        return f"native crypto loaded from {_path}"
    tried = "; ".join(_errors) if _errors else "no candidates found"
    return f"native crypto NOT loaded; tried: {tried}"


def disable() -> None:
    """Force the pure-Python path (tests, or SPACECOP_PURE at runtime)."""
    global _lib, _lib_gil, _tried
    _lib, _lib_gil, _tried = None, None, True


def _handle(n: int) -> ctypes.CDLL:
    return _lib if n >= GIL_RELEASE_THRESHOLD else _lib_gil


# --- thin wrappers (callers check available() first) -----------------------

def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    lib = _handle(len(plaintext))
    out = ctypes.create_string_buffer(len(plaintext) + 16)
    lib.sc_aead_encrypt(key, nonce, aad, len(aad), plaintext, len(plaintext), out)
    return out.raw


def aead_decrypt(key: bytes, nonce: bytes, ciphertext_and_tag: bytes, aad: bytes) -> Optional[bytes]:
    """Returns the plaintext, or None if authentication failed."""
    n = len(ciphertext_and_tag)
    lib = _handle(n)
    if n < 16:
        return None
    out = ctypes.create_string_buffer(max(n - 16, 1))
    rc = lib.sc_aead_decrypt(key, nonce, aad, len(aad), ciphertext_and_tag, n, out)
    if rc != 0:
        return None
    return out.raw[: n - 16]


def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = ctypes.create_string_buffer(max(len(data), 1))
    _handle(len(data)).sc_chacha20_xor(key, counter, nonce, data, len(data), out)
    return out.raw[: len(data)]


def poly1305(key: bytes, message: bytes) -> bytes:
    out = ctypes.create_string_buffer(16)
    _handle(len(message)).sc_poly1305(key, message, len(message), out)
    return out.raw
