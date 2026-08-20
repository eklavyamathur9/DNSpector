import csv
import json
from datetime import datetime, timezone

from dns_analyzer.export import (
    CSV_FIELDNAMES,
    build_stix_bundle,
    flatten_record,
    generate_csv_report,
    write_stix_bundle,
)


def _fixed_now() -> datetime:
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_record(**overrides):
    record = {
        "source_ip": "10.0.0.1",
        "destination_ip": "8.8.8.8",
        "query": "evil.com.",
        "registrable_domain": "evil.com",
        "subdomain": "",
        "entropy": 3.9,
        "entropy_z_score": None,
        "timestamp": 1000.0,
        "qdcount": 1,
        "ancount": 0,
        "nscount": 0,
        "arcount": 0,
        "flags": {
            "qr": "QUERY", "opcode": "QUERY", "aa": "FALSE", "tc": "FALSE",
            "rd": "TRUE", "ra": "FALSE", "rcode": "NOERROR",
        },
        "subdomain_burst": False,
        "subdomain_burst_unique_count": None,
        "host_nxdomain_ratio": None,
        "threat_intel": None,
        "severity": "info",
        "remark": "Normal query",
    }
    record.update(overrides)
    return record


class TestFlattenRecord:
    def test_flattens_flags_with_prefix(self):
        flat = flatten_record(make_record())
        assert flat["flags_qr"] == "QUERY"
        assert flat["flags_rcode"] == "NOERROR"
        assert "flags" not in flat

    def test_flattens_threat_intel_when_present(self):
        threat_intel = {"is_malicious": True, "source": "urlhaus", "detail": "3 URLs", "checked_at": 1.0}
        record = make_record(threat_intel=threat_intel)
        flat = flatten_record(record)
        assert flat["threat_intel_is_malicious"] is True
        assert flat["threat_intel_source"] == "urlhaus"
        assert flat["threat_intel_detail"] == "3 URLs"

    def test_missing_threat_intel_yields_none_fields(self):
        flat = flatten_record(make_record(threat_intel=None))
        assert flat["threat_intel_is_malicious"] is None
        assert flat["threat_intel_source"] is None

    def test_output_keys_match_csv_fieldnames(self):
        flat = flatten_record(make_record())
        assert set(flat.keys()) == set(CSV_FIELDNAMES)


class TestGenerateCsvReport:
    def test_writes_header_and_rows(self, tmp_path):
        records = [make_record(query="a.com."), make_record(query="b.com.")]
        csv_path = tmp_path / "out.csv"
        generate_csv_report(records, str(csv_path))

        with open(csv_path, newline="") as f:
            rows = list(csv.DictReader(f))

        assert len(rows) == 2
        assert rows[0]["query"] == "a.com."
        assert rows[1]["query"] == "b.com."
        assert set(rows[0].keys()) == set(CSV_FIELDNAMES)

    def test_empty_records_still_writes_header_only(self, tmp_path):
        csv_path = tmp_path / "out.csv"
        generate_csv_report([], str(csv_path))
        with open(csv_path, newline="") as f:
            rows = list(csv.DictReader(f))
        assert rows == []


class TestBuildStixBundle:
    def test_creates_one_indicator_per_malicious_domain(self):
        records = [
            make_record(
                registrable_domain="evil.com",
                threat_intel={"is_malicious": True, "source": "urlhaus", "detail": "3 URLs", "checked_at": 1.0},
            ),
            make_record(
                registrable_domain="clean.com",
                threat_intel={"is_malicious": False, "source": None, "detail": "no match", "checked_at": 1.0},
            ),
        ]
        bundle = build_stix_bundle(records, now_fn=_fixed_now)
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) == 1
        indicator = bundle["objects"][0]
        assert indicator["type"] == "indicator"
        assert "evil.com" in indicator["pattern"]
        assert "urlhaus" in indicator["description"]

    def test_deduplicates_repeated_malicious_domain(self):
        records = [
            make_record(
                registrable_domain="evil.com",
                threat_intel={"is_malicious": True, "source": "urlhaus", "detail": "x", "checked_at": 1.0},
            )
            for _ in range(5)
        ]
        bundle = build_stix_bundle(records, now_fn=_fixed_now)
        assert len(bundle["objects"]) == 1

    def test_no_malicious_records_yields_empty_bundle(self):
        records = [make_record(threat_intel=None)]
        bundle = build_stix_bundle(records, now_fn=_fixed_now)
        assert bundle["objects"] == []
        assert bundle["type"] == "bundle"

    def test_indicator_id_is_deterministic_for_same_domain(self):
        record = make_record(
            registrable_domain="evil.com",
            threat_intel={"is_malicious": True, "source": "urlhaus", "detail": "x", "checked_at": 1.0},
        )
        bundle1 = build_stix_bundle([record], now_fn=_fixed_now)
        bundle2 = build_stix_bundle([record], now_fn=_fixed_now)
        assert bundle1["objects"][0]["id"] == bundle2["objects"][0]["id"]


class TestWriteStixBundle:
    def test_writes_valid_json_file(self, tmp_path):
        records = [
            make_record(
                registrable_domain="evil.com",
                threat_intel={"is_malicious": True, "source": "openphish", "detail": "listed", "checked_at": 1.0},
            )
        ]
        stix_path = tmp_path / "out.stix.json"
        write_stix_bundle(records, str(stix_path))

        data = json.loads(stix_path.read_text())
        assert data["type"] == "bundle"
        assert len(data["objects"]) == 1
