from dataclasses import replace

import pytest

from vismriti import Purpose, Vismriti

KEY = b"test-key-0123456789abcdef"


@pytest.fixture
def v():
    v = Vismriti([Purpose("kyc", "KYC"), Purpose("support", "Support"), Purpose("marketing", "Mkt")], KEY)
    v.grant("asha", "kyc")
    v.grant("asha", "support")
    v.grant("ravi", "kyc")
    v.ingest("a-kyc", "Asha KYC PAN ABCPR1234K", ["asha"], ["kyc"])
    v.ingest("a-tkt", "Asha asked about UPI limit, call 9876543210", ["asha"], ["support"])
    v.ingest("r-tkt", "Ravi asked about UPI limit too", ["ravi"], ["support"])
    v.ingest("joint", "Joint account of Asha and Ravi, UPI limit", ["asha", "ravi"], ["support"])
    return v


def ids(results):
    return sorted(r.chunk.id for r in results)


def test_purpose_limitation(v):
    assert ids(v.retrieve("UPI limit", "support", k=10)) == ["a-tkt"]
    assert ids(v.retrieve("UPI limit", "marketing", k=10)) == []


def test_every_principal_in_chunk_must_consent(v):
    # 'joint' is blocked because Ravi has no 'support' consent
    assert "joint" not in ids(v.retrieve("joint account", "support", k=10))
    v.grant("ravi", "support")
    assert "joint" in ids(v.retrieve("joint account", "support", k=10))


def test_retrieved_text_is_masked(v):
    [r] = v.retrieve("Asha UPI limit", "support", k=1)
    assert "9876543210" not in r.text and "[PHONE_IN]" in r.text


def test_withdrawal_takes_effect_immediately(v):
    v.withdraw("asha", "support")
    assert ids(v.retrieve("UPI limit", "support", k=10)) == []


def test_denials_are_logged(v):
    v.retrieve("UPI limit", "marketing", k=10)
    assert v.evidence.events(event="retrieval_denied")
    assert v.evidence.verify()


def test_erasure_propagates_everywhere(v):
    v.memory.remember("asha", "prefers Hindi")
    v.cache.put("q1", "answer about Asha", ("asha",))
    v.logs.write("prompt about Asha", ("asha",))
    v.logs.write("prompt about Ravi", ("ravi",))

    cert = v.erase("asha")

    assert cert.complete and v.verify_certificate(cert)
    by_store = {s.store: s for s in cert.stores}
    assert by_store["vector_index"].erased == 3  # a-kyc, a-tkt, joint
    assert by_store["agent_memory"].erased == 1
    assert by_store["response_cache"].erased == 1
    assert by_store["app_logs"].erased == 1
    assert all(s.remaining == 0 for s in cert.stores)
    assert v.ledger.active_purposes("asha") == set()
    assert v.memory.recall("asha") == [] and v.cache.get("q1") is None
    assert "Asha" not in " ".join(v.logs.lines()) and "prompt about Ravi" in v.logs.lines()
    assert ids(v.retrieve("Asha", "kyc", k=10)) == []


def test_certificate_hides_identifier_and_detects_tampering(v):
    cert = v.erase("asha")
    assert "asha" not in cert.principal_ref
    forged = replace(cert, complete=True, stores=[replace(cert.stores[0], remaining=0)])
    forged.signature = cert.signature
    assert v.verify_certificate(cert)
    assert not v.verify_certificate(forged)


def test_access_summary(v):
    s = v.access_summary("asha")
    assert s["active_purposes"] == ["kyc", "support"]
    assert s["items_held"]["vector_index"] == 3


def test_persistence(tmp_path):
    p = [Purpose("kyc", "KYC")]
    v1 = Vismriti(p, KEY, data_dir=tmp_path)
    v1.grant("asha", "kyc")
    v2 = Vismriti(p, KEY, data_dir=tmp_path)
    assert v2.ledger.is_permitted("asha", "kyc") and v2.ledger.verify() and v2.evidence.verify()
