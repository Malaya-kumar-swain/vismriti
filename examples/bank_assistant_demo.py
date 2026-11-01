"""Five-minute demo: a bank's GenAI support assistant under the DPDP Act.

All people, numbers and records below are synthetic.
Run:  python examples/bank_assistant_demo.py
"""

import json

from vismriti import Purpose, Vismriti
from vismriti.pii import verhoeff_check_digit


def fake_aadhaar(seed: str) -> str:
    """A synthetic 12-digit number with a valid Verhoeff check digit (not a real Aadhaar)."""
    base = seed[:11]
    full = base + verhoeff_check_digit(base)
    return f"{full[:4]} {full[4:8]} {full[8:]}"


def line(title: str) -> None:
    print(f"\n── {title} " + "─" * (60 - len(title)))


v = Vismriti(
    purposes=[
        Purpose("kyc", "Verify identity for account opening", retention_days=3650),
        Purpose("support", "Answer the customer's service requests", retention_days=365),
        Purpose("marketing", "Offer new products", retention_days=180),
    ],
    signing_key=b"demo-only-key-change-me-0123456789",
)

asha, ravi = "cust-asha", "cust-ravi"
v.grant(asha, "kyc", notice_version="2026-10")
v.grant(asha, "support", notice_version="2026-10")
v.grant(ravi, "kyc", notice_version="2026-10")  # Ravi did NOT consent to support or marketing

v.ingest("kyc-asha", f"Asha Rao KYC: Aadhaar {fake_aadhaar('23456789012')}, PAN ABCPR1234K, mobile 9876543210.",
         [asha], ["kyc"])
v.ingest("ticket-asha", "Asha Rao asked to raise her UPI limit; UPI id asha.rao@okhdfcbank. Prefers Hindi.",
         [asha], ["support"])
v.ingest("ticket-ravi", "Ravi Kumar complained about a failed NEFT to IFSC HDFC0001234; reach him at ravi.k@example.in.",
         [ravi], ["support"])
v.memory.remember(asha, "Prefers replies in Hindi")
v.cache.put("upi limit asha", "Asha's UPI limit request is in progress.", (asha,))
v.logs.write("prompt: raise UPI limit for Asha Rao", (asha,))
v.logs.write("prompt: NEFT failure for Ravi Kumar", (ravi,))

line("1. Support agent asks about UPI limits (purpose = support)")
for r in v.retrieve("customer UPI limit complaint", purpose="support"):
    print(f"  ✔ {r.chunk.id}: {r.text}")
print("  ✘ ticket-ravi was withheld: Ravi never consented to 'support'.")

line("2. Marketing team tries the same data (purpose = marketing)")
print(f"  results: {v.retrieve('customer UPI limit', purpose='marketing')}  ← nothing leaks")

line("3. Asha asks what the bank holds about her (DPDP s.11)")
print(json.dumps(v.access_summary(asha)["items_held"], indent=2))

line("4. Asha withdraws consent and asks for erasure (DPDP s.6(4), s.12)")
cert = v.erase(asha)
for s in cert.stores:
    print(f"  {s.store:15} found {s.found}  erased {s.erased}  remaining {s.remaining}")
print(f"  complete={cert.complete}  signature valid={v.verify_certificate(cert)}")
print(f"  certificate refers to her only as {cert.principal_ref} (no raw identifier)")

line("5. Proof: nothing about Asha is retrievable any more")
print(f"  support search → {[r.chunk.id for r in v.retrieve('Asha UPI limit Hindi', 'support')]}")
print(f"  agent memory   → {v.memory.recall(asha)}")
print(f"  logs           → {v.logs.lines()}")

line("6. Evidence pack for the DPO (first lines)")
print("\n".join(v.report(asha).splitlines()[:12]))
