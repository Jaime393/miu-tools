import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "audit_generator", ROOT / "tools" / "audit_record_generator.py"
)
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def sample():
    return {
        "schema": "miu.audit-input/v1", "audit_id": "fixture-audit", "revision": 1,
        "timestamp_utc": "2026-11-03T00:00:00Z",
        "producer": {"model": "fixture-model", "instance": "fixture-instance"},
        "execution": {"status": "partial", "commit": "fixture-only"},
        "sources": [{"source_id": "source-a", "location": "fixture://readme",
                     "read_full": True, "sha256": "a" * 64}],
        "inputs": [{"artifact_id": "input-a", "sha256": "b" * 64}],
        "findings": [{"finding_id": "capability-read", "title": "Fixture observation",
                      "state": "verified", "evidence": ["source-a"]}],
    }


class AuditTests(unittest.TestCase):
    def test_four_artifacts_and_hashes(self):
        outputs = audit.render(sample())
        self.assertEqual(len(outputs), 4)
        manifest = outputs["fixture-audit.v1.sha256"].decode()
        for line in manifest.splitlines():
            digest, name = line.split("  ")
            self.assertEqual(digest, hashlib.sha256(outputs[name]).hexdigest())
        record = json.loads(outputs["fixture-audit.v1.json"])
        self.assertEqual(record["validation"]["remote_persistence"], "not_performed")
        self.assertEqual(record["validation"]["claim_truth"], "declared_by_input_not_reverified")

    def test_deterministic_and_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            first = audit.write_artifacts(sample(), Path(directory))
            original = {p.name: p.read_bytes() for p in first}
            second = audit.write_artifacts(sample(), Path(directory))
            self.assertEqual(original, {p.name: p.read_bytes() for p in second})

    def test_canonical_order_does_not_change_ids_or_outputs(self):
        data = sample()
        data["findings"].append({"finding_id": "another", "title": "Unknown",
                                 "state": "unknown", "evidence": []})
        reordered = copy.deepcopy(data)
        reordered["findings"].reverse()
        self.assertEqual(audit.render(data), audit.render(reordered))

    def test_conflicting_revision_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            audit.write_artifacts(sample(), Path(directory))
            data = sample()
            data["findings"][0]["title"] = "Changed"
            with self.assertRaisesRegex(ValueError, "conflicting"):
                audit.write_artifacts(data, Path(directory))
            data["revision"] = 2
            audit.write_artifacts(data, Path(directory))

    def test_mutable_row_rejected(self):
        data = sample()
        data["findings"][0]["row_number"] = 12
        with self.assertRaisesRegex(ValueError, "mutable"):
            audit.render(data)

    def test_credentials_rejected(self):
        data = sample()
        data["api_key"] = "fixture-not-a-real-key"
        with self.assertRaisesRegex(ValueError, "credential"):
            audit.render(data)

    def test_duplicate_ids_rejected(self):
        data = sample()
        data["findings"].append(copy.deepcopy(data["findings"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            audit.render(data)

    def test_verified_needs_hashed_fully_read_source(self):
        for change in ({"read_full": False}, {"sha256": None}):
            data = sample()
            data["sources"][0].update(change)
            with self.assertRaisesRegex(ValueError, "fully read"):
                audit.render(data)

    def test_utc_required(self):
        data = sample()
        data["timestamp_utc"] = "2026-11-03T00:00:00"
        with self.assertRaisesRegex(ValueError, "UTC"):
            audit.render(data)

    def test_unknown_evidence_rejected(self):
        data = sample()
        data["findings"][0]["evidence"] = ["missing-source"]
        with self.assertRaisesRegex(ValueError, "unknown source"):
            audit.render(data)

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            target = out / "elsewhere"
            target.write_text("do not overwrite")
            (out / "fixture-audit.v1.json").symlink_to(target)
            with self.assertRaisesRegex(ValueError, "symbolic"):
                audit.write_artifacts(sample(), out)
            self.assertEqual(target.read_text(), "do not overwrite")

    def test_aliases_use_same_interface(self):
        for path in ("tools/audit_record_generator.py", "tools/audit_act_generator.py",
                     "tools/generate_audit_record.py", "scripts/generate_audit_record.py"):
            result = subprocess.run([sys.executable, str(ROOT / path), "--help"],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--output-dir", result.stdout)

    def test_cli_malformed_json_is_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/audit_record_generator.py"),
                 "--input", "-", "--output-dir", directory],
                input="{", capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_all_aliases_generate_identical_artifacts(self):
        expected = audit.render(sample())
        for path in ("tools/audit_record_generator.py", "tools/audit_act_generator.py",
                     "tools/generate_audit_record.py", "scripts/generate_audit_record.py"):
            with tempfile.TemporaryDirectory() as directory:
                result = subprocess.run(
                    [sys.executable, str(ROOT / path), "--input", "-",
                     "--output-dir", directory],
                    input=json.dumps(sample()), capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                actual = {p.name: p.read_bytes() for p in Path(directory).iterdir()}
                self.assertEqual(actual, expected)
                self.assertEqual(json.loads(result.stdout)["remote_persistence"], "not_performed")


if __name__ == "__main__":
    unittest.main()
