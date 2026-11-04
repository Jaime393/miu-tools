# Audit records with stable IDs

The previous four generator files contained prose specifications rather than Python implementations. They now share one standard-library implementation, while the three historical command paths remain compatibility entry points.

## Run

```bash
python tools/audit_record_generator.py --input audit-input.json --output-dir audit-output
python -m unittest discover -s tests -v
```

The generator produces a versioned JSON record, Markdown report, compact checkpoint and SHA256 manifest. It never sends data, accesses credentials or claims that local outputs are remotely persisted.

## Input contract

```json
{
  "schema": "miu.audit-input/v1",
  "audit_id": "capability-discovery",
  "revision": 1,
  "timestamp_utc": "2026-11-03T00:00:00Z",
  "producer": {"model": "your-model", "instance": "your-node"},
  "execution": {"status": "partial", "commit": "source-commit-if-known"},
  "sources": [],
  "inputs": [],
  "findings": [
    {
      "finding_id": "route-pending",
      "title": "No independent remote readback yet",
      "state": "unknown",
      "evidence": []
    }
  ]
}
```

- **Sources:** use stable `source_id`, `location`, boolean `read_full` and a SHA256 digest or `null`. Input artifacts use stable `artifact_id` and a required SHA256.
- **Findings:** use stable `finding_id`, `title`, `state` and source IDs in `evidence`. States are `verified`, `reported`, `inferred`, `hypothesis`, `unknown` and `failed`.
- **Verification:** `verified` requires references to fully read, hashed sources. This is structural enforcement of the caller's attestations, not independent verification of their truth.
- **Execution:** allowed states are `succeeded`, `failed`, `partial` and `blocked`. Record code commits and relevant URLs as metadata without credentials.
- **Idempotency:** the same normalized input and revision produce identical bytes. A conflicting existing revision is rejected; increment `revision` instead of overwriting.
- **Stable references:** row-number keys are rejected. Use record IDs, source IDs, commits and content hashes instead of mutable spreadsheet rows.
- **Minimization:** credential fields and common bearer/GitHub token forms are rejected. This is not complete DLP; review every artifact before publishing, especially URLs, free text and private repository references.

## Continue into the network

Commit or upload the generated artifacts to an authorized durable store, then read them back and compare hashes. Record the resulting remote location and receipt in a separate next checkpoint; do not change a signed/hashed revision in place.

The JSON record is the single payload for an API, Hub or Audit Log consumer. The other formats derive from that same normalized record; no independent remote entries are created by this command.
