# Threat model (v0.1)

## What Vismriti protects against

| Risk | Mitigation |
|---|---|
| RAG returns a customer's data for a purpose they never agreed to (e.g. support data used for marketing) | Purpose check on every retrieved chunk, before the LLM sees it |
| Mixed chunks (joint accounts, group chats) leak data of a person who did not consent | Every principal in a chunk must have active consent |
| Personal identifiers reach the model or its logs | Checksum-validated masking of Aadhaar, PAN, GSTIN, IFSC, UPI, phone, email (incl. Indic digits) |
| "We deleted it" but copies survive in a cache, agent memory or logs | Erasure runs across every registered store and re-checks that nothing remains |
| Someone quietly edits the consent history or audit trail | Hash-chained records; `verify()` detects any change |
| A deletion certificate is forged or altered | HMAC-SHA256 signature over the full certificate |
| The audit trail itself becomes a store of personal data | Evidence holds IDs, purposes, counts and hashes, never raw text; certificates use a keyed hash of the ID |

## Known limits (honest list)

- **Model weights.** Erasure covers stores, not data already baked into a fine-tuned model. Do not fine-tune on personal data you may need to erase.
- **Backups and third parties.** Register an `ErasableStore` adapter for every copy (backups, analytics, vendors), or erasure is incomplete.
- **Detection is pattern-based.** Names and addresses are not detected by the built-in detector. Plug in Presidio, bharat-pii or an NER model through the `Detector` interface.
- **Single key.** v0.1 uses an HMAC key; asymmetric signatures (Ed25519) and key rotation are on the roadmap.
- **In-memory reference stores.** Production use needs adapters for your vector DB, cache and log system.
