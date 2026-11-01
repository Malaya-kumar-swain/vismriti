import asyncio

import pytest

pytest.importorskip("mcp")

from vismriti import Purpose, Vismriti  # noqa: E402
from vismriti.mcp_server import build  # noqa: E402


def test_tools_registered_and_callable():
    v = Vismriti([Purpose("kyc", "KYC")], b"test-key-0123456789abcdef")
    server = build(v)
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert {"check_purpose", "record_consent", "withdraw_consent", "retrieve",
            "mask_text", "access_summary", "erase_principal"} <= names

    asyncio.run(server.call_tool("record_consent", {"principal_id": "p1", "purpose": "kyc"}))
    assert v.ledger.is_permitted("p1", "kyc")
    asyncio.run(server.call_tool("erase_principal", {"principal_id": "p1"}))
    assert not v.ledger.is_permitted("p1", "kyc")
