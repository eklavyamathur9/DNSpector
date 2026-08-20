import statistics

import pytest
from scapy.all import DNS, DNSQR, IP, UDP

from dns_analyzer.detection import (
    DetectionSettings,
    HostEntropyBaseline,
    apply_detection_signals,
    build_dns_record,
    compute_host_baselines,
    compute_nxdomain_ratios,
    detect_subdomain_bursts,
    entropy_z_score,
    generate_remark,
)
from dns_analyzer.dns_parsing import calculate_entropy


def make_record(
    source_ip="10.0.0.1",
    destination_ip="8.8.8.8",
    qr="QUERY",
    rcode="NOERROR",
    entropy=1.0,
    timestamp=1000.0,
    registrable_domain="example.com",
    subdomain="",
    query=None,
):
    """Build a minimal record dict matching build_dns_record()'s output
    shape, for testing the batch-level detection functions without
    needing to construct real scapy packets.
    """
    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "query": query or f"{subdomain + '.' if subdomain else ''}{registrable_domain}.",
        "registrable_domain": registrable_domain,
        "subdomain": subdomain,
        "entropy": entropy,
        "entropy_z_score": None,
        "timestamp": timestamp,
        "qdcount": 1,
        "ancount": 0,
        "nscount": 0,
        "arcount": 0,
        "flags": {"qr": qr, "rcode": rcode},
        "subdomain_burst": False,
        "subdomain_burst_unique_count": None,
        "host_nxdomain_ratio": None,
        "threat_intel": None,
        "remark": "Normal query",
    }


class TestGenerateRemark:
    NORMAL_FLAGS = {"qr": "QUERY", "rcode": "NOERROR"}
    REFUSED_FLAGS = {"qr": "QUERY", "rcode": "REFUSED"}
    RESPONSE_ERROR_FLAGS = {"qr": "RESPONSE", "rcode": "SERVFAIL"}
    RESPONSE_OK_FLAGS = {"qr": "RESPONSE", "rcode": "NOERROR"}

    def test_high_entropy_flags_possible_dga_or_tunneling(self):
        remark = generate_remark(4.0, self.NORMAL_FLAGS)
        assert "DGA" in remark or "Tunneling" in remark

    def test_low_entropy_refused_query_flags_refused(self):
        remark = generate_remark(1.0, self.REFUSED_FLAGS)
        assert remark == "DNS query refused by the server"

    def test_low_entropy_failed_response_flags_misconfiguration(self):
        remark = generate_remark(1.0, self.RESPONSE_ERROR_FLAGS)
        assert "misconfiguration" in remark.lower() or "attack" in remark.lower()

    def test_low_entropy_normal_query_is_normal(self):
        assert generate_remark(1.0, self.NORMAL_FLAGS) == "Normal query"

    def test_low_entropy_successful_response_is_normal(self):
        assert generate_remark(1.0, self.RESPONSE_OK_FLAGS) == "Normal query"

    def test_high_entropy_takes_precedence_over_refused(self):
        # entropy check happens first in generate_remark's branching order
        remark = generate_remark(4.0, self.REFUSED_FLAGS)
        assert "DGA" in remark or "Tunneling" in remark

    def test_custom_entropy_threshold_changes_verdict(self):
        # 3.6 would trip the default 3.5 threshold but not a raised one
        remark = generate_remark(3.6, self.NORMAL_FLAGS, entropy_threshold=4.0)
        assert remark == "Normal query"

    def test_z_score_anomaly_flagged_when_above_threshold(self):
        remark = generate_remark(
            1.0, self.NORMAL_FLAGS, entropy_threshold=10.0, z_score=4.0, z_score_threshold=3.0
        )
        assert "anomalous" in remark.lower()

    def test_z_score_below_threshold_does_not_flag(self):
        remark = generate_remark(
            1.0, self.NORMAL_FLAGS, entropy_threshold=10.0, z_score=1.0, z_score_threshold=3.0
        )
        assert remark == "Normal query"

    def test_z_score_ignored_once_fixed_entropy_threshold_already_trips(self):
        remark = generate_remark(
            5.0, self.NORMAL_FLAGS, entropy_threshold=3.5, z_score=0.1, z_score_threshold=3.0
        )
        assert "DGA" in remark or "Tunneling" in remark


class TestBuildDnsRecord:
    def test_builds_record_for_valid_dns_packet(self):
        pkt = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=5000, dport=53) / DNS(qr=0, qd=DNSQR(qname="example.com"))
        record = build_dns_record(pkt, entropy_threshold=3.5)
        assert record is not None
        assert record["source_ip"] == "10.0.0.1"
        assert record["destination_ip"] == "8.8.8.8"
        assert record["query"] == "example.com."
        assert record["remark"] == "Normal query"
        assert record["threat_intel"] is None

    def test_packet_without_ip_layer_returns_none(self):
        # e.g. non-IPv4 traffic - source/destination can't be determined
        pkt = UDP(sport=5000, dport=53) / DNS(qr=0, qd=DNSQR(qname="example.com"))
        assert build_dns_record(pkt, entropy_threshold=3.5) is None

    def test_packet_without_dnsqr_uses_unknown_query(self):
        # scapy's DNS() auto-populates a default question unless explicitly cleared
        pkt = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=53, dport=5000) / DNS(qr=1, rcode=0, qd=[], qdcount=0)
        record = build_dns_record(pkt, entropy_threshold=3.5)
        assert record["query"] == "Unknown"

    def test_record_includes_registrable_domain_and_subdomain(self):
        pkt = (
            IP(src="10.0.0.1", dst="8.8.8.8")
            / UDP(sport=5000, dport=53)
            / DNS(qr=0, qd=DNSQR(qname="a1.tunnel.evil.com"))
        )
        record = build_dns_record(pkt, entropy_threshold=3.5)
        assert record["registrable_domain"] == "evil.com"
        assert record["subdomain"] == "a1.tunnel"

    def test_entropy_scored_on_label_excluding_public_suffix(self):
        # 'com' contributes no randomness; entropy should reflect only the
        # registrant-controlled label(s), not the full FQDN including TLD
        pkt = (
            IP(src="10.0.0.1", dst="8.8.8.8")
            / UDP(sport=5000, dport=53)
            / DNS(qr=0, qd=DNSQR(qname="www.google.com"))
        )
        record = build_dns_record(pkt, entropy_threshold=3.5)
        assert record["entropy"] == pytest.approx(calculate_entropy("www.google"))

    def test_record_carries_packet_timestamp(self):
        pkt = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=5000, dport=53) / DNS(qr=0, qd=DNSQR(qname="example.com"))
        record = build_dns_record(pkt, entropy_threshold=3.5)
        assert isinstance(record["timestamp"], float)


class TestComputeHostBaselines:
    def test_computes_mean_and_stdev_for_host_with_enough_samples(self):
        entropies = [1.0, 2.0, 3.0, 2.0, 1.0]
        records = [make_record(source_ip="1.1.1.1", entropy=e) for e in entropies]
        baseline = compute_host_baselines(records, min_samples=5)["1.1.1.1"]
        assert baseline.sample_count == 5
        assert baseline.mean == pytest.approx(statistics.mean(entropies))
        assert baseline.stdev == pytest.approx(statistics.pstdev(entropies))

    def test_excludes_hosts_below_min_samples(self):
        records = [make_record(source_ip="2.2.2.2", entropy=1.0) for _ in range(3)]
        assert "2.2.2.2" not in compute_host_baselines(records, min_samples=5)

    def test_ignores_response_records(self):
        records = [make_record(source_ip="3.3.3.3", qr="RESPONSE", entropy=1.0) for _ in range(10)]
        assert "3.3.3.3" not in compute_host_baselines(records, min_samples=5)

    def test_keeps_hosts_independent(self):
        records = [make_record(source_ip="1.1.1.1", entropy=1.0) for _ in range(5)] + [
            make_record(source_ip="2.2.2.2", entropy=5.0) for _ in range(5)
        ]
        baselines = compute_host_baselines(records, min_samples=5)
        assert baselines["1.1.1.1"].mean == pytest.approx(1.0)
        assert baselines["2.2.2.2"].mean == pytest.approx(5.0)


class TestEntropyZScore:
    def test_computes_deviation_in_standard_deviations(self):
        baseline = HostEntropyBaseline(mean=2.0, stdev=1.0, sample_count=10)
        assert entropy_z_score(5.0, baseline) == pytest.approx(3.0)

    def test_none_baseline_returns_none(self):
        assert entropy_z_score(5.0, None) is None

    def test_zero_stdev_returns_none(self):
        baseline = HostEntropyBaseline(mean=2.0, stdev=0.0, sample_count=10)
        assert entropy_z_score(2.0, baseline) is None


class TestDetectSubdomainBursts:
    def test_flags_many_unique_subdomains_under_one_domain_in_one_window(self):
        records = [
            make_record(registrable_domain="evil.com", subdomain=f"chunk{i}", timestamp=1000.0 + i)
            for i in range(20)
        ]
        bursts = detect_subdomain_bursts(records, window_seconds=60, unique_threshold=15)
        assert len(bursts) == 1
        (domain, _bucket), subs = next(iter(bursts.items()))
        assert domain == "evil.com"
        assert len(subs) == 20

    def test_below_threshold_not_flagged(self):
        records = [
            make_record(registrable_domain="evil.com", subdomain=f"chunk{i}", timestamp=1000.0 + i)
            for i in range(5)
        ]
        assert detect_subdomain_bursts(records, window_seconds=60, unique_threshold=15) == {}

    def test_different_time_windows_not_merged(self):
        early = [
            make_record(registrable_domain="evil.com", subdomain=f"a{i}", timestamp=0.0 + i) for i in range(10)
        ]
        later = [
            make_record(registrable_domain="evil.com", subdomain=f"b{i}", timestamp=600.0 + i) for i in range(10)
        ]
        # 10 unique per window, below the threshold of 15 - neither window should trip it
        assert detect_subdomain_bursts(early + later, window_seconds=60, unique_threshold=15) == {}

    def test_response_records_ignored(self):
        records = [
            make_record(qr="RESPONSE", registrable_domain="evil.com", subdomain=f"chunk{i}", timestamp=1000.0 + i)
            for i in range(20)
        ]
        assert detect_subdomain_bursts(records, window_seconds=60, unique_threshold=15) == {}

    def test_records_without_subdomain_ignored(self):
        records = [
            make_record(registrable_domain="evil.com", subdomain="", timestamp=1000.0 + i) for i in range(20)
        ]
        assert detect_subdomain_bursts(records, window_seconds=60, unique_threshold=15) == {}


class TestComputeNxdomainRatios:
    def test_computes_ratio_for_client(self):
        records = [make_record(destination_ip="9.9.9.9", qr="RESPONSE", rcode="NXDOMAIN") for _ in range(4)] + [
            make_record(destination_ip="9.9.9.9", qr="RESPONSE", rcode="NOERROR") for _ in range(6)
        ]
        stats = compute_nxdomain_ratios(records, min_samples=5)["9.9.9.9"]
        assert stats.sample_count == 10
        assert stats.ratio == pytest.approx(0.4)

    def test_excludes_clients_below_min_samples(self):
        records = [make_record(destination_ip="9.9.9.9", qr="RESPONSE", rcode="NXDOMAIN") for _ in range(2)]
        assert "9.9.9.9" not in compute_nxdomain_ratios(records, min_samples=5)

    def test_ignores_query_records(self):
        records = [make_record(destination_ip="9.9.9.9", qr="QUERY", rcode="NXDOMAIN") for _ in range(10)]
        assert "9.9.9.9" not in compute_nxdomain_ratios(records, min_samples=5)

    def test_keyed_by_destination_not_source(self):
        # the client is the destination on a RESPONSE packet (the server is the source)
        records = [
            make_record(source_ip="8.8.8.8", destination_ip="192.168.1.50", qr="RESPONSE", rcode="NXDOMAIN")
            for _ in range(5)
        ]
        ratios = compute_nxdomain_ratios(records, min_samples=5)
        assert "192.168.1.50" in ratios
        assert "8.8.8.8" not in ratios


class TestApplyDetectionSignals:
    def test_flags_entropy_z_score_outlier(self):
        records = [
            make_record(source_ip="1.1.1.1", entropy=1.0, registrable_domain=f"site{i}.com") for i in range(9)
        ] + [make_record(source_ip="1.1.1.1", entropy=5.0, registrable_domain="site9.com")]
        settings = DetectionSettings(entropy_threshold=10.0, z_score_threshold=2.0, min_baseline_samples=5)
        result = apply_detection_signals(records, settings)
        outlier = result[-1]
        assert outlier["entropy_z_score"] == pytest.approx(3.0)
        assert "anomalous" in outlier["remark"].lower()

    def test_flags_subdomain_burst(self):
        records = [
            make_record(registrable_domain="evil.com", subdomain=f"chunk{i}", timestamp=1000.0 + i, entropy=1.0)
            for i in range(20)
        ]
        settings = DetectionSettings(
            entropy_threshold=10.0, burst_window_seconds=60, burst_unique_subdomain_threshold=15
        )
        result = apply_detection_signals(records, settings)
        assert all(r["subdomain_burst"] for r in result)
        assert result[0]["subdomain_burst_unique_count"] == 20
        assert "tunneling" in result[0]["remark"].lower()

    def test_flags_high_nxdomain_ratio_host(self):
        records = [
            make_record(destination_ip="192.168.1.50", qr="RESPONSE", rcode="NXDOMAIN", entropy=1.0)
            for _ in range(8)
        ] + [
            make_record(destination_ip="192.168.1.50", qr="RESPONSE", rcode="NOERROR", entropy=1.0)
            for _ in range(2)
        ]
        settings = DetectionSettings(entropy_threshold=10.0, nxdomain_ratio_threshold=0.5, min_nxdomain_samples=5)
        result = apply_detection_signals(records, settings)
        assert all(r["host_nxdomain_ratio"] == pytest.approx(0.8) for r in result)
        assert all("nxdomain" in r["remark"].lower() for r in result)

    def test_normal_traffic_stays_normal(self):
        records = [make_record(entropy=1.0) for _ in range(3)]
        result = apply_detection_signals(records, DetectionSettings(entropy_threshold=3.5))
        assert all(r["remark"] == "Normal query" for r in result)
