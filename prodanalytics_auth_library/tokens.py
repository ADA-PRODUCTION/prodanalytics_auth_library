"""Intra-service API tokens that can rotate without restarting anything.

The tokens live in a file mounted from the Kubernetes Secret `pa-api-tokens`
(default `/app/tokens/.env`, override with `PA_API_TOKENS_FILE`), one `KEY=value`
per line. The kubelet rewrites a mounted Secret in place when it changes, and this
module re-reads the file when it changes, so a rotated value is
picked up within about a minute, with no pod restart.

During a rotation a token has up to three live values, all accepted when checking
an incoming request:

    APITOKEN2           the value callers send
    APITOKEN2_NEXT      the upcoming value (step 1: accepted before anyone sends it)
    APITOKEN2_PREVIOUS  the value being retired (step 2: still accepted while callers switch)

Until the file is mounted, every lookup falls back to the process environment
(the existing `ipa-secret` .env), so this code can ship before the Secret exists.
"""

from __future__ import annotations

import hmac
import os
import threading
import time
from typing import Dict, Optional, Tuple

DEFAULT_PATH = "/app/tokens/.env"
# How often the file's mtime is checked at most. os.stat is cheap; this just keeps
# a busy service from doing it on every single request.
CHECK_INTERVAL_S = 2.0
ROTATION_SUFFIXES = ("_NEXT", "_PREVIOUS")


def _parse(text: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if key:
            values[key] = value
    return values


class TokenStore:
    """Thread-safe view of the token file, refreshed when the file changes."""

    def __init__(self, path: Optional[str] = None, check_interval_s: float = CHECK_INTERVAL_S):
        self.path = path or os.getenv("PA_API_TOKENS_FILE", DEFAULT_PATH)
        self.check_interval_s = check_interval_s
        self._lock = threading.Lock()
        self._values: Dict[str, str] = {}
        self._stamp: Optional[Tuple[int, int, int]] = None
        self._checked_at = 0.0

    def _refresh(self) -> Dict[str, str]:
        now = time.monotonic()
        if now - self._checked_at < self.check_interval_s and self._checked_at:
            return self._values
        with self._lock:
            if now - self._checked_at < self.check_interval_s and self._checked_at:
                return self._values
            self._checked_at = now
            try:
                st = os.stat(self.path)
            except OSError:
                # Not mounted (yet), or briefly absent during the kubelet's atomic swap:
                # keep the last good values rather than dropping to nothing.
                return self._values
            # The kubelet swaps a new file in on update, so the inode changes too;
            # checking it as well as mtime catches two writes within one second.
            stamp = (st.st_ino, st.st_mtime_ns, st.st_size)
            if stamp != self._stamp:
                try:
                    with open(self.path, encoding="utf-8") as handle:
                        self._values = _parse(handle.read())
                    self._stamp = stamp
                except OSError:
                    pass
            return self._values

    def current(self, name: str) -> Optional[str]:
        """The value to SEND for `name`: from the token file, else the environment."""
        value = self._refresh().get(name)
        if value:
            return value
        return os.getenv(name) or None

    def accepted(self, name: str) -> Tuple[str, ...]:
        """Every value to ACCEPT for `name` right now (current, next, previous)."""
        values = self._refresh()
        found = [values.get(name) or os.getenv(name)]
        found += [values.get(name + suffix) for suffix in ROTATION_SUFFIXES]
        return tuple(dict.fromkeys(v for v in found if v))

    def is_valid(self, name: str, presented: Optional[str]) -> bool:
        """Constant-time check of an incoming key against every accepted value."""
        if not presented:
            return False
        given = presented.encode("utf-8")
        ok = False
        for value in self.accepted(name):
            # No early exit: the time taken does not reveal which value matched.
            ok |= hmac.compare_digest(given, value.encode("utf-8"))
        return ok


_default: Optional[TokenStore] = None
_default_lock = threading.Lock()


def default_store() -> TokenStore:
    global _default
    if _default is None:
        with _default_lock:
            if _default is None:
                _default = TokenStore()
    return _default


def current_token(name: str) -> Optional[str]:
    """The token to put in the X-API-KEY header when calling another service."""
    return default_store().current(name)


def token_is_valid(name: str, presented: Optional[str]) -> bool:
    """Whether an incoming X-API-KEY is a live value of `name`."""
    return default_store().is_valid(name, presented)
