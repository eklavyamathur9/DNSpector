import pytest
from scapy.all import DNS

from dnspector.dns_parsing import OPCODES, RCODES, calculate_entropy, format_flags, parse_dns_flags, parse_domain


class TestCalculateEntropy:
    def test_empty_domain_returns_zero(self):
        assert calculate_entropy("") == 0.0

    def test_single_repeated_character_has_zero_entropy(self):
        assert calculate_entropy("aaaa") == pytest.approx(0.0)

    def test_uniform_distribution_matches_log2_of_alphabet_size(self):
        # 4 distinct, equally frequent characters -> log2(4) = 2 bits
        assert calculate_entropy("abcd") == pytest.approx(2.0)

    def test_high_entropy_random_looking_string_exceeds_dga_threshold(self):
        # 16 distinct characters, each appearing once -> max entropy = log2(16) = 4.0
        assert calculate_entropy("x7q9zk3m1p8wr2nb") > 3.5

    def test_typical_dictionary_word_domain_is_low_entropy(self):
        assert calculate_entropy("google") < 3.5


class TestParseDomain:
    def test_dga_style_domain_has_no_subdomain(self):
        # DGA output is typically the registrable domain itself, not a subdomain
        parts = parse_domain("kj3h4k5j234.com.")
        assert parts.registrable_domain == "kj3h4k5j234.com"
        assert parts.subdomain == ""
        assert parts.scoring_label == "kj3h4k5j234"

    def test_tunneling_style_domain_with_multi_part_suffix(self):
        # co.uk is a two-label public suffix - a naive "last 2 labels" split
        # would get this wrong and treat 'co' as part of the registrable domain
        parts = parse_domain("a1b2c3.tunnel.evil-corp.co.uk.")
        assert parts.registrable_domain == "evil-corp.co.uk"
        assert parts.subdomain == "a1b2c3.tunnel"
        assert parts.scoring_label == "a1b2c3.tunnel.evil-corp"

    def test_normal_domain_excludes_tld_from_scoring_label(self):
        parts = parse_domain("www.google.com.")
        assert parts.registrable_domain == "google.com"
        assert parts.subdomain == "www"
        assert parts.scoring_label == "www.google"
        assert "com" not in parts.scoring_label

    def test_unparseable_domain_falls_back_to_raw_string(self):
        parts = parse_domain("Unknown")
        assert parts.registrable_domain == ""
        assert parts.subdomain == ""
        assert parts.scoring_label == "Unknown"


class TestParseDnsFlags:
    def test_standard_query_flags(self):
        dns = DNS(qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, rcode=0)
        flags = parse_dns_flags(dns)
        assert flags == {
            "qr": "QUERY",
            "opcode": "QUERY",
            "aa": "FALSE",
            "tc": "FALSE",
            "rd": "TRUE",
            "ra": "FALSE",
            "rcode": "NOERROR",
        }

    def test_response_with_refused_rcode(self):
        dns = DNS(qr=1, opcode=0, aa=0, tc=0, rd=1, ra=1, rcode=5)
        flags = parse_dns_flags(dns)
        assert flags["qr"] == "RESPONSE"
        assert flags["rcode"] == "REFUSED"

    def test_uncommon_opcode_does_not_crash(self):
        # opcode=5 (UPDATE) previously caused an IndexError against the
        # old 4-element list; it must now resolve to a name instead.
        dns = DNS(qr=0, opcode=5, aa=0, tc=0, rd=0, ra=0, rcode=0)
        flags = parse_dns_flags(dns)
        assert flags["opcode"] == "UPDATE"

    def test_unassigned_opcode_falls_back_gracefully(self):
        dns = DNS(qr=0, opcode=15, aa=0, tc=0, rd=0, ra=0, rcode=0)
        flags = parse_dns_flags(dns)
        assert flags["opcode"] == "UNKNOWN(15)"

    def test_extended_rcode_does_not_crash(self):
        # rcode=15 previously caused an IndexError against the old
        # 7-element list.
        dns = DNS(qr=1, opcode=0, aa=0, tc=0, rd=0, ra=0, rcode=15)
        flags = parse_dns_flags(dns)
        assert flags["rcode"] == "UNKNOWN(15)"

    def test_all_defined_opcodes_resolve_without_error(self):
        for value, name in OPCODES.items():
            dns = DNS(qr=0, opcode=value, aa=0, tc=0, rd=0, ra=0, rcode=0)
            assert parse_dns_flags(dns)["opcode"] == name

    def test_all_defined_rcodes_resolve_without_error(self):
        for value, name in RCODES.items():
            dns = DNS(qr=1, opcode=0, aa=0, tc=0, rd=0, ra=0, rcode=value)
            assert parse_dns_flags(dns)["rcode"] == name


class TestFormatFlags:
    def test_formats_each_flag_on_its_own_indented_line(self):
        flags = {"qr": "QUERY", "rcode": "NOERROR"}
        assert format_flags(flags) == "  qr: QUERY\n  rcode: NOERROR"
