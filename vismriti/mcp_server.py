"""MCP server: lets any MCP-capable agent ask Vismriti before it touches personal data.

Run:  VISMRITI_KEY=<32+ random chars> python -m vismriti.mcp_server
Purposes are read from VISMRITI_PURPOSES (comma-separated), default "kyc,support".
Requires the optional dependency:  pip install "vismriti[mcp]"
"""

from __future__ import annotations

import os

try:  # MCP Python SDK 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # SDK 1.x
    from mcp.server.fastmcp import FastMCP as _Server

from . import Purpose, Vismriti, mask


def build(v: Vismriti) -> _Server:
    server = _Server("vismriti")

    @server.tool()
    def check_purpose(principal_id: str, purpose: str) -> dict:
        """Is processing this person's data for this purpose allowed right now?"""
        return {"allowed": v.ledger.is_permitted(principal_id, purpose),
                "active_purposes": sorted(v.ledger.active_purposes(principal_id))}

    @server.tool()
    def record_consent(principal_id: str, purpose: str, notice_version: str = "v1") -> str:
        """Record that the person consented to a specified purpose."""
        v.grant(principal_id, purpose, notice_version)
        return "recorded"

    @server.tool()
    def withdraw_consent(principal_id: str, purpose: str | None = None) -> list[str]:
        """Withdraw one purpose, or all purposes if none is given."""
        return v.withdraw(principal_id, purpose, reason="withdrawn via agent")

    @server.tool()
    def retrieve(query: str, purpose: str, k: int = 3) -> list[dict]:
        """Purpose-bound, PII-masked retrieval from the knowledge base."""
        return [{"id": r.chunk.id, "score": round(r.score, 3), "text": r.text} for r in v.retrieve(query, purpose, k, "mcp")]

    @server.tool()
    def mask_text(text: str) -> str:
        """Mask Indian identifiers (Aadhaar, PAN, UPI, IFSC, GSTIN, phone, email)."""
        return mask(text)[0]

    @server.tool()
    def access_summary(principal_id: str) -> dict:
        """What is held about this person and why (DPDP s.11)."""
        return v.access_summary(principal_id)

    @server.tool()
    def erase_principal(principal_id: str, reason: str = "erasure requested") -> dict:
        """Erase the person everywhere and return a signed deletion certificate."""
        return v.erase(principal_id, reason).to_dict()

    return server


def main() -> None:
    key = os.environ.get("VISMRITI_KEY", "")
    if len(key) < 16:
        raise SystemExit("Set VISMRITI_KEY to a secret of at least 16 characters.")
    names = [n.strip() for n in os.environ.get("VISMRITI_PURPOSES", "kyc,support").split(",") if n.strip()]
    v = Vismriti([Purpose(n, n) for n in names], key.encode(), data_dir=os.environ.get("VISMRITI_DATA", ".vismriti"))
    build(v).run()


if __name__ == "__main__":
    main()
