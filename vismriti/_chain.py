"""A small append-only, hash-chained record log (in memory or JSON Lines on disk).

Each record stores the SHA-256 of the previous record, so any edit or deletion
in the middle of the history is detectable with ``verify()``.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Iterator

GENESIS = "0" * 64


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(obj: Any) -> str:
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


class HashChain:
    def __init__(self, path: str | os.PathLike[str] | None = None):
        self.path = os.fspath(path) if path else None
        self._records: list[dict[str, Any]] = []
        if self.path and os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as fh:
                self._records = [json.loads(line) for line in fh if line.strip()]

    def append(self, body: dict[str, Any]) -> dict[str, Any]:
        prev = self._records[-1]["hash"] if self._records else GENESIS
        record = {"seq": len(self._records), "at": utcnow(), **body, "prev": prev}
        record["hash"] = digest(record)
        self._records.append(record)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(canonical(record) + "\n")
        return record

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self._records)

    def __len__(self) -> int:
        return len(self._records)

    def verify(self) -> bool:
        prev = GENESIS
        for i, rec in enumerate(self._records):
            body = {k: v for k, v in rec.items() if k != "hash"}
            if rec.get("seq") != i or rec.get("prev") != prev or digest(body) != rec.get("hash"):
                return False
            prev = rec["hash"]
        return True

    @property
    def head(self) -> str:
        return self._records[-1]["hash"] if self._records else GENESIS
