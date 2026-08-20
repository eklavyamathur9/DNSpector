"""Pure DNS-protocol and domain-name parsing helpers.

Nothing in this module does I/O (network, disk, or otherwise) - it only
turns scapy DNS objects and raw domain strings into plain Python values,
which is what makes every function here trivially unit-testable.
"""

from typing import Dict, NamedTuple

import numpy as np
import tldextract
from scapy.all import DNS

# Public-suffix-aware domain parser. suffix_list_urls=() disables fetching
# an updated Public Suffix List over the network and uses the bundled
# snapshot only, so this stays deterministic and works fully offline
# (important for a security tool that may run in isolated environments).
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

# DNS Opcode / RCODE value -> name lookups (RFC 1035, RFC 6895).
# Using dicts with a fallback instead of list indexing avoids IndexError
# on the less common values (e.g. NOTIFY/UPDATE opcodes, extended RCODEs)
# that a fixed-size list would silently not cover.
OPCODES = {
    0: "QUERY", 1: "IQUERY", 2: "STATUS", 3: "RESERVED",
    4: "NOTIFY", 5: "UPDATE", 6: "DSO",
}
RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET",
    8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE",
}


class DomainParts(NamedTuple):
    registrable_domain: str  # "" if the public suffix couldn't be determined
    subdomain: str  # "" if the query has no subdomain labels
    scoring_label: str  # everything except the public suffix (TLD)


def calculate_entropy(domain: str) -> float:
    """Calculate Shannon entropy of a domain name (or domain label)."""
    if not domain:
        return 0.0
    prob = [float(domain.count(c)) / len(domain) for c in set(domain)]
    return -sum(p * np.log2(p) for p in prob)


def parse_domain(domain: str) -> DomainParts:
    """Split a domain into its public-suffix-aware parts.

    The public suffix (TLD, e.g. 'com' or 'co.uk') is fixed and
    low-entropy by construction, so including it when scoring entropy
    dilutes the signal. scoring_label is everything the *registrant*
    controls (subdomain + registrable-domain label), which is where DGA
    randomness or DNS-tunneling-encoded data actually shows up.
    """
    clean = domain.rstrip(".")
    ext = _TLD_EXTRACTOR(clean)
    if not ext.domain or not ext.suffix:
        return DomainParts(registrable_domain="", subdomain="", scoring_label=clean)
    registrable_domain = f"{ext.domain}.{ext.suffix}"
    scoring_parts = [part for part in (ext.subdomain, ext.domain) if part]
    return DomainParts(
        registrable_domain=registrable_domain,
        subdomain=ext.subdomain,
        scoring_label=".".join(scoring_parts),
    )


def parse_dns_flags(dns: DNS) -> Dict[str, str]:
    """Map DNS flag values to human-readable format."""
    return {
        "qr": "RESPONSE" if dns.qr else "QUERY",
        "opcode": OPCODES.get(dns.opcode, f"UNKNOWN({dns.opcode})"),
        "aa": "TRUE" if dns.aa else "FALSE",
        "tc": "TRUE" if dns.tc else "FALSE",
        "rd": "TRUE" if dns.rd else "FALSE",
        "ra": "TRUE" if dns.ra else "FALSE",
        "rcode": RCODES.get(dns.rcode, f"UNKNOWN({dns.rcode})"),
    }


def format_flags(flags: Dict[str, str]) -> str:
    """Format the flags dictionary for better readability in the PDF."""
    return "\n".join([f"  {key}: {value}" for key, value in flags.items()])
