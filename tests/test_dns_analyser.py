import pytest
from scapy.all import DNS

from Dns_Analyser import (
    calculate_entropy,
    parse_dns_flags,
    format_flags,
    generate_remark,
    OPCODES,
    RCODES,
)


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
