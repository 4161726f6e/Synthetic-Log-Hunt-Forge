from __future__ import annotations

"""
_filelock.py
------------
Minimal cross-platform advisory file locking.

  - POSIX (Linux / macOS):  uses ``fcntl.flock``
  - Windows:                uses ``msvcrt.locking``
  - Anything else:          no-op (atomic rename is the primary safety net)

Usage::

    from slhf.learning._filelock import lock_shared, lock_exclusive, unlock

    with open(path, "r") as f:
        lock_shared(f)
        try:
            data = json.load(f)
        finally:
            unlock(f)
"""

import sys
from typing import IO


if sys.platform == "win32":
    import msvcrt
    import os

    _LOCK_SH = 0        # msvcrt has no shared mode; treat as no-op for reads
    _LOCK_EX = msvcrt.LK_NBLCK

    def lock_shared(f: IO) -> None:
        # Windows: shared (read) locks are not natively supported by msvcrt.
        # The atomic-rename write strategy means a read racing a write will
        # either see the old complete file or the new complete file — never
        # a partial write — so a no-op here is safe.
        pass

    def lock_exclusive(f: IO) -> None:
        # Lock the first byte of the file to signal exclusive access.
        try:
            f.flush()
            pos = f.tell()
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            f.seek(pos)
        except (OSError, ValueError):
            # File may not support locking (e.g. already closed, special file).
            pass

    def unlock(f: IO) -> None:
        try:
            pos = f.tell()
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            f.seek(pos)
        except (OSError, ValueError):
            pass

else:
    try:
        import fcntl as _fcntl

        def lock_shared(f: IO) -> None:
            _fcntl.flock(f, _fcntl.LOCK_SH)

        def lock_exclusive(f: IO) -> None:
            _fcntl.flock(f, _fcntl.LOCK_EX)

        def unlock(f: IO) -> None:
            _fcntl.flock(f, _fcntl.LOCK_UN)

    except ImportError:
        # Truly exotic platform — fall back to no-op.
        def lock_shared(f: IO) -> None:   # type: ignore[misc]
            pass

        def lock_exclusive(f: IO) -> None:  # type: ignore[misc]
            pass

        def unlock(f: IO) -> None:  # type: ignore[misc]
            pass
