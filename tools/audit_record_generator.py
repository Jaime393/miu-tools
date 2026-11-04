#!/usr/bin/env python3
"""Deterministic, local audit artifacts. No network calls or credential access."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,100}$")
HEX = re.compile(r"^[a-fA-F0-9]{64}$")
STATES = {"verified", "reported", "inferred", "hypothesis", "unknown", "failed"}
ROW_KEYS = {"row", "row_number", "row_index", "sheet_row", "fila", "numero_fila"}
SECRET_KEYS = {
    "password", "api_key", "apikey", "secret", "totp_secret", "access_token",
    "refresh_token", "authorization", "private_key",
}
TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b|(?i:bearer)\s+[A-Za-z0-9._~-]{16,}")


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError(f"{label} must be a stable ID, not a path or mutable row")
    return value


def guard(value: object) -> None:
    """Basic minimization, not a comprehensive secret scanner."""
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in ROW_KEYS:
                raise ValueError("mutable sheet/row references are not allowed")
            if str(key).lower() in SECRET_KEYS:
                raise ValueError("credential fields are not allowed")
            guard(item)
    elif isinstance(value, list):
        for item in value:
            guard(item)
    elif isinstance(value, str) and TOKEN.search(value):
        raise ValueError("credential-like text is not allowed")


def normalize(data: object) -> dict:
    if not isinstance(data, dict) or data.get("schema") != "miu.audit-input/v1":
        raise ValueError("expected schema miu.audit-input/v1")
    guard(data)
    doc = copy.deepcopy(data)
    require_id(doc.get("audit_id"), "audit_id")
    revision = doc.get("revision", 1)
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise ValueError("revision must be a positive integer")
    doc["revision"] = revision
    stamp = doc.get("timestamp_utc")
    if not isinstance(stamp, str):
        raise ValueError("timestamp_utc is required; generated time is not evidence time")
    parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError("timestamp_utc must have an explicit UTC offset")
    doc["timestamp_utc"] = parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    producer = doc.get("producer")
    if not isinstance(producer, dict) or not all(
        isinstance(producer.get(k), str) and producer[k].strip()
        for k in ("model", "instance")
    ):
        raise ValueError("producer.model and producer.instance are required")
    execution = doc.get("execution")
    if not isinstance(execution, dict) or execution.get("status") not in {
        "succeeded", "failed", "partial", "blocked"
    }:
        raise ValueError("execution.status must be succeeded, failed, partial or blocked")
    for collection, key in (("sources", "source_id"), ("inputs", "artifact_id"),
                            ("findings", "finding_id")):
        items = doc.get(collection)
        if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
            raise ValueError(f"{collection} must be a list of objects")
        ids = [require_id(i.get(key), key) for i in items]
        if len(ids) != len(set(ids)):
            raise ValueError(f"duplicate {key}")
        doc[collection] = sorted(items, key=lambda item: item[key])
    sources = {s["source_id"]: s for s in doc["sources"]}
    for source in sources.values():
        if not isinstance(source.get("location"), str) or not source["location"].strip():
            raise ValueError("each source requires a location")
        if not isinstance(source.get("read_full"), bool):
            raise ValueError("each source must declare read_full as a boolean")
        digest = source.get("sha256")
        if digest is not None and (not isinstance(digest, str) or not HEX.fullmatch(digest)):
            raise ValueError("source sha256 must be a 64-character digest or null")
    for artifact in doc["inputs"]:
        if not isinstance(artifact.get("sha256"), str) or not HEX.fullmatch(artifact["sha256"]):
            raise ValueError("each input artifact requires a SHA256 digest")
    for finding in doc["findings"]:
        if finding.get("state") not in STATES:
            raise ValueError("unsupported finding state")
        if not isinstance(finding.get("title"), str) or not finding["title"].strip():
            raise ValueError("each finding requires a title")
        evidence = finding.get("evidence", [])
        if not isinstance(evidence, list) or not all(isinstance(e, str) for e in evidence):
            raise ValueError("evidence must contain source IDs")
        if any(e not in sources for e in evidence):
            raise ValueError("evidence references an unknown source ID")
        finding["evidence"] = sorted(set(evidence))
        if finding["state"] == "verified":
            if not evidence or not all(
                sources[e]["read_full"] and sources[e].get("sha256") for e in evidence
            ):
                raise ValueError("verified findings require fully read, hashed sources")
    return doc


def render(data: object) -> dict[str, bytes]:
    doc = normalize(data)
    input_digest = sha256(canonical(doc))
    record = {
        **doc, "schema": "miu.audit-record/v1", "input_sha256": input_digest,
        "validation": {
            "structure": "passed",
            "claim_truth": "declared_by_input_not_reverified",
            "remote_persistence": "not_performed",
        },
    }
    stem = f"{doc['audit_id']}.v{doc['revision']}"
    json_name = f"{stem}.json"
    json_bytes = (json.dumps(record, sort_keys=True, ensure_ascii=False,
                             indent=2, allow_nan=False) + "\n").encode("utf-8")
    lines = [
        f"# Audit {doc['audit_id']} / revision {doc['revision']}", "",
        f"Evidence timestamp: {doc['timestamp_utc']}. Execution: {doc['execution']['status']}.",
        "Source readings and finding states are declared by the input, not independently reverified.", "",
        "## Provenance", "",
        f"- Model: {doc['producer']['model']}",
        f"- Instance: {doc['producer']['instance']}",
        f"- Canonical input SHA256: `{input_digest}`",
        "- Persistence: local artifacts only; a remote write and readback are still required.", "",
        "## Findings", "",
    ]
    for finding in doc["findings"]:
        lines += [f"- `{finding['finding_id']}` [{finding['state']}]: {finding['title']}",
                  f"  Evidence IDs: {', '.join(finding['evidence']) or 'none'}. "
                  f"{finding.get('detail', '')}"]
    lines += ["", "## Sources", ""]
    for source in doc["sources"]:
        lines.append(
            f"- `{source['source_id']}`: {source['location']}; "
            f"read_full={str(source['read_full']).lower()}; "
            f"SHA256={source.get('sha256') or 'not supplied'}"
        )
    counts = dict(sorted(Counter(f["state"] for f in doc["findings"]).items()))
    checkpoint = "\n".join([
        f"# Checkpoint {doc['audit_id']}", "",
        f"- Revision: {doc['revision']}",
        f"- Evidence timestamp: {doc['timestamp_utc']}",
        f"- Execution: {doc['execution']['status']}",
        f"- Finding counts: {json.dumps(counts, sort_keys=True)}",
        f"- Record: `{json_name}`",
        f"- Record SHA256: `{sha256(json_bytes)}`",
        "- Remote persistence: pending write and independent readback.", "",
    ])
    outputs = {
        json_name: json_bytes,
        f"{stem}.md": ("\n".join(lines) + "\n").encode("utf-8"),
        f"{stem}.checkpoint.md": checkpoint.encode("utf-8"),
    }
    outputs[f"{stem}.sha256"] = "".join(
        f"{sha256(content)}  {name}\n" for name, content in sorted(outputs.items())
    ).encode("utf-8")
    return outputs


def write_artifacts(data: object, output_dir: Path) -> list[Path]:
    outputs = render(data)
    output_dir.mkdir(parents=True, exist_ok=True)
    # Preflight every destination before creating any output.
    for name, content in outputs.items():
        destination = output_dir / name
        if destination.is_symlink():
            raise ValueError("refusing a symbolic-link output")
        if destination.exists() and destination.read_bytes() != content:
            raise ValueError("conflicting audit revision; use a new revision")
    written = []
    for name, content in outputs.items():
        destination = output_dir / name
        if not destination.exists():
            try:
                with destination.open("xb") as stream:
                    stream.write(content)
            except FileExistsError:
                if destination.is_symlink() or destination.read_bytes() != content:
                    raise ValueError("concurrent conflicting audit revision") from None
        written.append(destination)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Input JSON file, or - for stdin")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.input == "-":
            data = json.load(sys.stdin)
        else:
            with Path(args.input).open(encoding="utf-8") as stream:
                data = json.load(stream)
        paths = write_artifacts(data, args.output_dir)
    except (ValueError, OSError, TypeError) as error:
        print(f"audit generation failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({
        "status": "local_artifacts_written",
        "remote_persistence": "not_performed",
        "files": [str(path) for path in paths],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
