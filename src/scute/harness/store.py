from __future__ import annotations

import threading
import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class Store(Protocol):
    """Where runs keep their state (JSON strings) and budgets their counters.
    Anything with these two methods works: Redis, a cache, a table.

        class RedisStore:
            def __init__(self, redis): self.redis = redis
            def get(self, key): return self.redis.get(key)
            def set(self, key, value, ttl=None): self.redis.set(key, value, ex=int(ttl) if ttl else None)
    """

    def get(self, key: str) -> str | None: ...

    def set(self, key: str, value: str, ttl: float | None = None) -> None: ...


class MemoryStore:
    """Run state in this process: fine for one server and for tests. With more
    than one process, pass a shared store (Redis, a cache)."""

    def __init__(self) -> None:
        self._data: dict[str, tuple[str, float | None]] = {}
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"MemoryStore({len(self._data)} keys)"

    def get(self, key: str) -> str | None:
        with self._lock:
            found = self._data.get(key)
            if not found:
                return None
            value, until = found
            if until is not None and until < time.time():
                del self._data[key]
                return None
            return value

    def set(self, key: str, value: str, ttl: float | None = None) -> None:
        with self._lock:
            self._data[key] = (value, time.time() + ttl if ttl else None)
