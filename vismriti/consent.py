"""Consent ledger: who agreed to which purpose, under which notice, and when they withdrew.

Maps to DPDP Act 2023 sections 5 (notice) and 6 (consent, including withdrawal
under 6(4)). Every grant and withdrawal is a hash-chained record, so the history
can be shown to an auditor and any tampering is detectable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ._chain import HashChain


@dataclass(frozen=True)
class Purpose:
    """A specified purpose for processing, as shown to the data principal in the notice."""

    name: str
    description: str
    retention_days: int | None = None
    data_categories: tuple[str, ...] = field(default_factory=tuple)


class UnknownPurpose(KeyError):
    pass


class ConsentLedger:
    def __init__(self, purposes: list[Purpose], path: str | os.PathLike[str] | None = None):
        self.purposes = {p.name: p for p in purposes}
        self._chain = HashChain(path)

    def _check(self, purpose: str) -> None:
        if purpose not in self.purposes:
            raise UnknownPurpose(purpose)

    def grant(self, principal_id: str, purpose: str, notice_version: str, channel: str = "app") -> dict:
        self._check(purpose)
        return self._chain.append(
            {"type": "grant", "principal": principal_id, "purpose": purpose,
             "notice": notice_version, "channel": channel}
        )

    def withdraw(self, principal_id: str, purpose: str | None = None, reason: str = "") -> list[dict]:
        """Withdraw one purpose, or every active purpose when ``purpose`` is None."""
        targets = [purpose] if purpose else sorted(self.active_purposes(principal_id))
        out = []
        for p in targets:
            self._check(p)
            out.append(self._chain.append(
                {"type": "withdraw", "principal": principal_id, "purpose": p, "reason": reason}
            ))
        return out

    def active_purposes(self, principal_id: str, at: datetime | None = None) -> set[str]:
        """Purposes the principal currently consents to (latest event per purpose wins).

        A grant also lapses when the purpose's retention period has passed.
        """
        at = at or datetime.now(timezone.utc)
        state: dict[str, dict] = {}
        for rec in self._chain:
            if rec["principal"] == principal_id:
                state[rec["purpose"]] = rec
        active = set()
        for purpose, rec in state.items():
            if rec["type"] != "grant":
                continue
            days = self.purposes[purpose].retention_days
            if days is not None:
                granted = datetime.fromisoformat(rec["at"])
                if (at - granted).days >= days:
                    continue
            active.add(purpose)
        return active

    def is_permitted(self, principal_id: str, purpose: str) -> bool:
        return purpose in self.active_purposes(principal_id)

    def history(self, principal_id: str) -> list[dict]:
        return [r for r in self._chain if r["principal"] == principal_id]

    def verify(self) -> bool:
        return self._chain.verify()

    @property
    def head(self) -> str:
        return self._chain.head
