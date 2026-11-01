"""Evidence log: an audit trail of every allow/deny decision and every erasure.

The log never stores raw personal data, only principal IDs, purposes, counts and
hashes, so the evidence itself does not need to be erased later.
"""

from __future__ import annotations

import os
from collections import Counter
from typing import Any

from ._chain import HashChain

# Indicative mapping of event types to DPDP Act 2023 sections. Not legal advice.
DPDP_SECTIONS = {
    "consent_granted": "s.6 consent",
    "consent_withdrawn": "s.6(4) withdrawal of consent",
    "retrieval_allowed": "s.4/s.6 processing for a consented, specified purpose",
    "retrieval_denied": "s.4/s.6 processing for a consented, specified purpose",
    "erasure_completed": "s.8(7) and s.12 erasure",
    "access_summary": "s.11 right to access information",
}


class EvidenceLog:
    def __init__(self, path: str | os.PathLike[str] | None = None):
        self._chain = HashChain(path)

    def record(self, event: str, **fields: Any) -> dict:
        return self._chain.append({"event": event, **fields})

    def events(self, principal_id: str | None = None, event: str | None = None) -> list[dict]:
        out = []
        for rec in self._chain:
            if event and rec["event"] != event:
                continue
            if principal_id and principal_id not in rec.get("principals", [rec.get("principal")]):
                continue
            out.append(rec)
        return out

    def verify(self) -> bool:
        return self._chain.verify()

    @property
    def head(self) -> str:
        return self._chain.head

    def report(self, principal_id: str | None = None) -> str:
        """A Markdown evidence pack an auditor or DPO can read."""
        evs = self.events(principal_id)
        counts = Counter(e["event"] for e in evs)
        lines = [
            "# Vismriti evidence report",
            "",
            f"Scope: {'principal ' + principal_id if principal_id else 'all principals'}",
            f"Events: {len(evs)} · Log integrity: {'verified' if self.verify() else 'BROKEN'}",
            f"Log head: `{self.head}`",
            "",
            "| Event | Count | DPDP reference (indicative) |",
            "|---|---|---|",
        ]
        for ev, n in sorted(counts.items()):
            lines.append(f"| {ev} | {n} | {DPDP_SECTIONS.get(ev, '')} |")
        lines += ["", "## Timeline", ""]
        for e in evs:
            detail = {k: v for k, v in e.items() if k not in ("seq", "prev", "hash", "event", "at")}
            lines.append(f"- `{e['at']}` **{e['event']}** {detail}")
        lines += ["", "_This report is an engineering aid, not legal advice._"]
        return "\n".join(lines)
