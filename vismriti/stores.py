"""Erasable stores: every place an AI system can keep a person's data.

A RAG or agent stack copies personal data into many places: the vector index,
a response cache, the agent's long-term memory, application logs. Erasure is only
real if all of them are covered. Each store here implements ``ErasableStore``;
write an adapter with the same three methods for Chroma, pgvector, Redis, etc.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@runtime_checkable
class ErasableStore(Protocol):
    name: str

    def find(self, principal_id: str) -> list[str]:
        """IDs of every item linked to the principal."""

    def erase(self, principal_id: str) -> int:
        """Remove (or irreversibly redact) every linked item. Returns how many."""


@dataclass
class Chunk:
    id: str
    text: str
    principals: tuple[str, ...]
    purposes: tuple[str, ...]  # purposes this data was collected for
    meta: dict = field(default_factory=dict)


_TOKEN = re.compile(r"\w+", re.UNICODE)


def hash_embed(text: str, dim: int = 256) -> list[float]:
    """Deterministic, dependency-free bag-of-words embedding (good enough for demos/tests).

    Swap in a real embedding model in production; the guard logic is unchanged.
    """
    vec = [0.0] * dim
    for tok in _TOKEN.findall(text.lower()):
        h = int.from_bytes(hashlib.blake2b(tok.encode(), digest_size=4).digest(), "big")
        vec[h % dim] += 1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


class InMemoryVectorStore:
    name = "vector_index"

    def __init__(self, embed=hash_embed):
        self.embed = embed
        self._chunks: dict[str, Chunk] = {}
        self._vecs: dict[str, list[float]] = {}

    def add(self, chunk: Chunk) -> None:
        self._chunks[chunk.id] = chunk
        self._vecs[chunk.id] = self.embed(chunk.text)

    def search(self, query: str, k: int = 5) -> list[tuple[Chunk, float]]:
        q = self.embed(query)
        scored = [(self._chunks[i], sum(a * b for a, b in zip(q, v))) for i, v in self._vecs.items()]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:k]

    def __len__(self) -> int:
        return len(self._chunks)

    def find(self, principal_id: str) -> list[str]:
        return [c.id for c in self._chunks.values() if principal_id in c.principals]

    def erase(self, principal_id: str) -> int:
        ids = self.find(principal_id)
        for i in ids:
            self._chunks.pop(i)
            self._vecs.pop(i)
        return len(ids)


class ResponseCache:
    """Cache of generated answers. A cached answer about a person is a copy of their data."""

    name = "response_cache"

    def __init__(self):
        self._items: dict[str, tuple[str, tuple[str, ...]]] = {}

    def put(self, key: str, answer: str, principals: tuple[str, ...]) -> None:
        self._items[key] = (answer, principals)

    def get(self, key: str) -> str | None:
        hit = self._items.get(key)
        return hit[0] if hit else None

    def find(self, principal_id: str) -> list[str]:
        return [k for k, (_, ps) in self._items.items() if principal_id in ps]

    def erase(self, principal_id: str) -> int:
        keys = self.find(principal_id)
        for k in keys:
            self._items.pop(k)
        return len(keys)


class AgentMemory:
    """Long-term memory an agent writes facts into ("customer prefers Hindi")."""

    name = "agent_memory"

    def __init__(self):
        self._facts: dict[str, list[str]] = {}

    def remember(self, principal_id: str, fact: str) -> None:
        self._facts.setdefault(principal_id, []).append(fact)

    def recall(self, principal_id: str) -> list[str]:
        return list(self._facts.get(principal_id, []))

    def find(self, principal_id: str) -> list[str]:
        return [f"{principal_id}#{i}" for i in range(len(self._facts.get(principal_id, [])))]

    def erase(self, principal_id: str) -> int:
        return len(self._facts.pop(principal_id, []))


class LogStore:
    """Application/prompt logs. Lines are tombstoned (content replaced by a hash), not dropped,
    so log ordering and counts stay intact for operations while the personal data is gone."""

    name = "app_logs"

    def __init__(self):
        self._lines: list[dict] = []

    def write(self, message: str, principals: tuple[str, ...] = ()) -> None:
        self._lines.append({"msg": message, "principals": principals})

    def lines(self) -> list[str]:
        return [ln["msg"] for ln in self._lines]

    def find(self, principal_id: str) -> list[str]:
        return [str(i) for i, ln in enumerate(self._lines) if principal_id in ln["principals"]]

    def erase(self, principal_id: str) -> int:
        n = 0
        for ln in self._lines:
            if principal_id in ln["principals"]:
                tomb = hashlib.sha256(ln["msg"].encode()).hexdigest()[:16]
                ln["msg"] = f"[erased under DPDP s.12 · sha256:{tomb}]"
                ln["principals"] = tuple(p for p in ln["principals"] if p != principal_id)
                n += 1
        return n
