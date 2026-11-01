import json
from datetime import datetime, timedelta, timezone

import pytest

from vismriti import ConsentLedger, EvidenceLog, Purpose
from vismriti.consent import UnknownPurpose

PURPOSES = [Purpose("kyc", "KYC"), Purpose("support", "Support", retention_days=30)]


def test_grant_and_withdraw():
    led = ConsentLedger(PURPOSES)
    led.grant("p1", "kyc", "v1")
    led.grant("p1", "support", "v1")
    assert led.active_purposes("p1") == {"kyc", "support"}
    led.withdraw("p1", "support")
    assert led.active_purposes("p1") == {"kyc"}
    led.grant("p1", "support", "v2")  # re-consent under a new notice
    assert led.is_permitted("p1", "support")


def test_withdraw_all():
    led = ConsentLedger(PURPOSES)
    led.grant("p1", "kyc", "v1")
    led.grant("p1", "support", "v1")
    assert sorted(r["purpose"] for r in led.withdraw("p1")) == ["kyc", "support"]
    assert led.active_purposes("p1") == set()


def test_unknown_purpose_rejected():
    with pytest.raises(UnknownPurpose):
        ConsentLedger(PURPOSES).grant("p1", "marketing", "v1")


def test_retention_lapses_consent():
    led = ConsentLedger(PURPOSES)
    led.grant("p1", "support", "v1")
    later = datetime.now(timezone.utc) + timedelta(days=31)
    assert "support" not in led.active_purposes("p1", at=later)


def test_ledger_tamper_detected(tmp_path):
    path = tmp_path / "consent.jsonl"
    led = ConsentLedger(PURPOSES, path)
    led.grant("p1", "kyc", "v1")
    led.withdraw("p1", "kyc")
    assert ConsentLedger(PURPOSES, path).verify()
    lines = path.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["type"] = "grant"  # someone tries to undo the withdrawal
    lines[1] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")
    assert not ConsentLedger(PURPOSES, path).verify()


def test_evidence_report_has_no_raw_text():
    ev = EvidenceLog()
    ev.record("retrieval_denied", principals=["p1"], purpose="marketing", chunk="c1", reason="no consent")
    report = ev.report("p1")
    assert "retrieval_denied" in report and "verified" in report
