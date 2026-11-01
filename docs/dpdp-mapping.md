# DPDP Act 2023: what Vismriti helps with

This is an indicative engineering mapping, **not legal advice**. Compliance also
depends on your notices, contracts, security programme and the DPDP Rules 2025.

| DPDP Act 2023 | Obligation (simplified) | Vismriti feature | Status in v0.1 |
|---|---|---|---|
| s.4, s.6(1) | Process personal data only for a lawful, specified purpose the person consented to | `PurposeBoundRetriever`: a chunk reaches the model only if it was collected for that purpose and every person in it has active consent | ✅ |
| s.5 | Give a notice describing the data and purpose | Each consent records the `notice_version` it was given under | ✅ (records only; notices are yours) |
| s.6(4) | Consent can be withdrawn as easily as given; processing must stop | `withdraw()` takes effect on the very next retrieval | ✅ |
| s.6(7)–(9) | Consent managers | Hash-chained consent ledger that a consent-manager integration can feed | 🟡 integration hook, no CM protocol yet |
| s.8(5) | Reasonable security safeguards | PII masking before data reaches the model; tamper-evident logs | 🟡 partial |
| s.8(6) | Report personal data breaches | Evidence log gives the who/what/when trail | 🟡 evidence only, no breach workflow yet |
| s.8(7) | Erase when consent is withdrawn or the purpose is served | `erase()` across vector index, cache, agent memory and logs; retention-based lapse of consent | ✅ |
| s.11 | Right to access information about processing | `access_summary()`: purposes, consent history, items held per store | ✅ |
| s.12 | Right to correction and erasure | `erase()` + signed `DeletionCertificate` | ✅ erasure · ⬜ correction |
| s.13 | Grievance redressal | — | ⬜ roadmap |

Legend: ✅ covered · 🟡 partial · ⬜ not yet
