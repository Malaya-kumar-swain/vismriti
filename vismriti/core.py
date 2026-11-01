"""``Vismriti``: one object that wires the ledger, stores, retriever and erasure together."""

from __future__ import annotations

import os

from .consent import ConsentLedger, Purpose
from .erasure import DeletionCertificate, ErasureCoordinator
from .evidence import EvidenceLog
from .retrieval import PurposeBoundRetriever, Retrieved
from .stores import AgentMemory, Chunk, ErasableStore, InMemoryVectorStore, LogStore, ResponseCache


class Vismriti:
    def __init__(
        self,
        purposes: list[Purpose],
        signing_key: bytes,
        data_dir: str | os.PathLike[str] | None = None,
        vector_store: InMemoryVectorStore | None = None,
        extra_stores: list[ErasableStore] | None = None,
        mask_pii: bool = True,
    ):
        path = (lambda name: os.path.join(data_dir, name)) if data_dir else (lambda name: None)
        if data_dir:
            os.makedirs(data_dir, exist_ok=True)
        self.ledger = ConsentLedger(purposes, path("consent.jsonl"))
        self.evidence = EvidenceLog(path("evidence.jsonl"))
        self.index = vector_store or InMemoryVectorStore()
        self.cache = ResponseCache()
        self.memory = AgentMemory()
        self.logs = LogStore()
        self.stores: list[ErasableStore] = [self.index, self.cache, self.memory, self.logs, *(extra_stores or [])]
        self.retriever = PurposeBoundRetriever(self.index, self.ledger, self.evidence, mask_pii=mask_pii)
        self.eraser = ErasureCoordinator(self.stores, self.ledger, self.evidence, signing_key)

    # consent
    def grant(self, principal_id: str, purpose: str, notice_version: str = "v1", channel: str = "app") -> None:
        rec = self.ledger.grant(principal_id, purpose, notice_version, channel)
        self.evidence.record("consent_granted", principals=[principal_id], purpose=purpose, ledger=rec["hash"][:16])

    def withdraw(self, principal_id: str, purpose: str | None = None, reason: str = "") -> list[str]:
        recs = self.ledger.withdraw(principal_id, purpose, reason)
        for r in recs:
            self.evidence.record("consent_withdrawn", principals=[principal_id], purpose=r["purpose"], ledger=r["hash"][:16])
        return [r["purpose"] for r in recs]

    # data
    def ingest(self, chunk_id: str, text: str, principals: list[str], purposes: list[str], **meta) -> None:
        for p in purposes:
            if p not in self.ledger.purposes:
                raise ValueError(f"unknown purpose '{p}'")
        self.index.add(Chunk(chunk_id, text, tuple(principals), tuple(purposes), meta))

    def retrieve(self, query: str, purpose: str, k: int = 3, requester: str = "app") -> list[Retrieved]:
        return self.retriever.retrieve(query, purpose, k, requester)

    # rights
    def access_summary(self, principal_id: str) -> dict:
        """What we hold about a principal and why (DPDP s.11), without returning raw data."""
        summary = {
            "principal": principal_id,
            "active_purposes": sorted(self.ledger.active_purposes(principal_id)),
            "consent_history": [
                {"type": r["type"], "purpose": r["purpose"], "at": r["at"], "notice": r.get("notice")}
                for r in self.ledger.history(principal_id)
            ],
            "items_held": self.eraser.preview(principal_id),
        }
        self.evidence.record("access_summary", principals=[principal_id])
        return summary

    def erase(self, principal_id: str, reason: str = "erasure requested by data principal") -> DeletionCertificate:
        return self.eraser.erase(principal_id, reason)

    def verify_certificate(self, cert: DeletionCertificate) -> bool:
        return self.eraser.verify(cert)

    def report(self, principal_id: str | None = None) -> str:
        return self.evidence.report(principal_id)
