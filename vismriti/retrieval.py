"""Purpose-bound retrieval: RAG that only returns data the purpose is allowed to see.

A chunk is returned for a request with purpose P only if
  1. the chunk was collected for P (purpose limitation), and
  2. every data principal in the chunk has an active consent for P.
Everything else is dropped before it reaches the model, and each decision is logged.
"""

from __future__ import annotations

from dataclasses import dataclass

from .consent import ConsentLedger
from .evidence import EvidenceLog
from .pii import Detector, mask
from .stores import Chunk, InMemoryVectorStore


@dataclass
class Retrieved:
    chunk: Chunk
    score: float
    text: str  # possibly masked


@dataclass
class Decision:
    chunk_id: str
    allowed: bool
    reason: str


class PurposeBoundRetriever:
    def __init__(
        self,
        store: InMemoryVectorStore,
        ledger: ConsentLedger,
        evidence: EvidenceLog,
        mask_pii: bool = True,
        detector: Detector | None = None,
        overfetch: int = 4,
    ):
        self.store, self.ledger, self.evidence = store, ledger, evidence
        self.mask_pii, self.detector, self.overfetch = mask_pii, detector, overfetch

    def check(self, chunk: Chunk, purpose: str) -> Decision:
        if purpose not in chunk.purposes:
            return Decision(chunk.id, False, f"collected for {list(chunk.purposes)}, not '{purpose}'")
        missing = [p for p in chunk.principals if not self.ledger.is_permitted(p, purpose)]
        if missing:
            return Decision(chunk.id, False, f"no active consent for '{purpose}' from {missing}")
        return Decision(chunk.id, True, "consented purpose")

    def retrieve(self, query: str, purpose: str, k: int = 3, requester: str = "app") -> list[Retrieved]:
        if purpose not in self.ledger.purposes:
            raise ValueError(f"unknown purpose '{purpose}'")
        results: list[Retrieved] = []
        for chunk, score in self.store.search(query, k * self.overfetch):
            d = self.check(chunk, purpose)
            self.evidence.record(
                "retrieval_allowed" if d.allowed else "retrieval_denied",
                principals=list(chunk.principals), purpose=purpose, chunk=chunk.id,
                reason=d.reason, requester=requester,
            )
            if not d.allowed:
                continue
            text = mask(chunk.text, self.detector)[0] if self.mask_pii else chunk.text
            results.append(Retrieved(chunk, score, text))
            if len(results) == k:
                break
        return results
