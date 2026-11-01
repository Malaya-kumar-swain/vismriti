"""Erasure propagation with a verifiable deletion certificate.

One call withdraws the principal's consents, erases them from every registered
store, re-checks that nothing is left, and returns a signed certificate that the
data fiduciary can keep as evidence (DPDP Act 2023 s.8(7) and s.12).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import asdict, dataclass

from ._chain import canonical, utcnow
from .consent import ConsentLedger
from .evidence import EvidenceLog
from .stores import ErasableStore


@dataclass
class StoreResult:
    store: str
    found: int
    erased: int
    remaining: int


@dataclass
class DeletionCertificate:
    principal_ref: str  # salted hash, so the certificate itself holds no identifier
    requested_at: str
    completed_at: str
    reason: str
    stores: list[StoreResult]
    consents_withdrawn: list[str]
    consent_ledger_head: str
    complete: bool
    signature: str = ""

    def payload(self) -> str:
        body = asdict(self)
        body.pop("signature")
        return canonical(body)

    def to_dict(self) -> dict:
        return asdict(self)


class ErasureCoordinator:
    def __init__(
        self,
        stores: list[ErasableStore],
        ledger: ConsentLedger,
        evidence: EvidenceLog,
        signing_key: bytes,
    ):
        if len(signing_key) < 16:
            raise ValueError("signing_key should be at least 16 bytes")
        self.stores, self.ledger, self.evidence = stores, ledger, evidence
        self._key = signing_key

    def principal_ref(self, principal_id: str) -> str:
        return hmac.new(self._key, principal_id.encode(), hashlib.sha256).hexdigest()[:24]

    def preview(self, principal_id: str) -> dict[str, int]:
        """What would be erased, without changing anything (useful for an access request)."""
        return {s.name: len(s.find(principal_id)) for s in self.stores}

    def erase(self, principal_id: str, reason: str = "consent withdrawn", requested_at: str | None = None) -> DeletionCertificate:
        requested_at = requested_at or utcnow()
        withdrawn = [r["purpose"] for r in self.ledger.withdraw(principal_id, reason=reason)]
        results = []
        for s in self.stores:
            found = len(s.find(principal_id))
            erased = s.erase(principal_id)
            remaining = len(s.find(principal_id))
            results.append(StoreResult(s.name, found, erased, remaining))
        complete = all(r.remaining == 0 for r in results) and not self.ledger.active_purposes(principal_id)
        cert = DeletionCertificate(
            principal_ref=self.principal_ref(principal_id),
            requested_at=requested_at,
            completed_at=utcnow(),
            reason=reason,
            stores=results,
            consents_withdrawn=withdrawn,
            consent_ledger_head=self.ledger.head,
            complete=complete,
        )
        cert.signature = hmac.new(self._key, cert.payload().encode(), hashlib.sha256).hexdigest()
        self.evidence.record(
            "erasure_completed", principals=[principal_id], complete=complete,
            stores={r.store: r.erased for r in results}, certificate=cert.signature[:16],
        )
        return cert

    def verify(self, cert: DeletionCertificate) -> bool:
        expected = hmac.new(self._key, cert.payload().encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, cert.signature)
