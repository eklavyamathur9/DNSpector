# DNS Traffic Analyzer

[![CI](https://github.com/eklavyamathur9/Dns-Analyser/actions/workflows/ci.yml/badge.svg)](https://github.com/eklavyamathur9/Dns-Analyser/actions/workflows/ci.yml)

The **DNS Traffic Analyzer** is a Python-based tool designed to capture, analyze, and report DNS traffic. It provides insights into DNS queries, flags, and entropy, helping identify potential anomalies such as DNS tunneling, misconfigurations, or malicious activities.

---

## Features

- **Packet Capture**: Captures DNS packets over UDP port 53 for a user-defined duration.
- **Public-suffix-aware Entropy Scoring**: Computes Shannon entropy over the registrant-controlled part of a domain (excluding the TLD), to detect DGA-style and DNS-tunneling-style randomness without a fixed public suffix like `.com` diluting the signal.
- **Per-host Statistical Baselining**: Flags entropy that's anomalous (z-score) for a *specific* querying host, not just a single global cutoff - reduces false positives from naturally high-entropy but legitimate traffic.
- **Subdomain-burst (DNS Tunneling) Detection**: Flags a parent domain receiving an unusually high number of *unique* subdomain queries within a short time window - a signal independent of any single query's entropy.
- **NXDOMAIN-ratio Tracking**: Flags a host whose DNS responses are mostly failed lookups (NXDOMAIN) - a classic sign of a DGA-infected client cycling through candidate C2 domains.
- **DNS Flag Parsing**: Decodes DNS flags into human-readable formats.
- **Detailed Reporting**:
    - **JSON Output**: Saves analysis results, including all detection signals, in a structured JSON file.
    - **PDF Report**: Generates a professional PDF report with detailed insights.
- **Remarks Generation**: Provides remarks combining all of the above signals to highlight potential issues.

---

## Documentation

For a deep dive into how the capture/analysis pipeline works internally, the DNS/security theory behind the entropy and flag-based detection, and known limitations, see **[DOCUMENTATION.md](DOCUMENTATION.md)**.

For the ordered, checklist-driven plan for evolving this project (engineering hardening, detection-quality improvements, threat-intel integration, and eventual open-sourcing), see **[PHASES.md](PHASES.md)**.

---

## Installation

1. Clone the repository:
     ```bash
     git clone https://github.com/eklavyamathur9/Dns-Analyser.git
     cd Dns-Analyser
     ```

2. Install dependencies:
     ```bash
     pip install -r requirements.txt
     ```

---

## Usage

Run the script with the built-in default settings (60-second capture, current directory for output). Raw packet capture needs elevated privileges, so this typically requires `sudo`:

```bash
sudo python Dns_Analyser.py
```

Or configure it via CLI flags:

```bash
sudo python Dns_Analyser.py --duration 30 --iface eth0 --entropy-threshold 4.0 --output-dir ./reports
```

Detection thresholds are also tunable, e.g. to make subdomain-burst (tunneling) detection more sensitive on a short capture:

```bash
sudo python Dns_Analyser.py --burst-window-seconds 30 --burst-unique-subdomain-threshold 8 --z-score-threshold 2.5
```

Run `python Dns_Analyser.py --help` for the full list of options. Any of these can also be set as defaults in a JSON config file (see `config.example.json`) and passed with `--config`:

```bash
sudo python Dns_Analyser.py --config config.example.json
```

CLI flags always override the config file, which overrides the built-in defaults.

After capturing, the tool will:
 - Save captured packets to `dns_capture.pcap` (or `--pcap-file`).
 - Analyze the packets and save results to:
     - `output.json` (or `--json-file`)
     - `dns_report.pdf` (or `--report-file`)

---

## Running Tests

The core detection logic (entropy scoring, DNS flag parsing, remark generation) is covered by a `pytest` suite in `tests/`.

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

---

## Output Files

- **dns_capture.pcap**: Raw captured DNS packets.
- **output.json**: JSON file containing detailed analysis results.
- **dns_report.pdf**: PDF report summarizing the analysis.

---

## Remarks and Insights

- **High Entropy Domains**: Indicates potential DNS tunneling or DGA (Domain Generation Algorithm) activity, either via a fixed threshold or a per-host statistical outlier (z-score).
- **Subdomain Bursts**: Many unique subdomains queried under one parent domain in a short window - a DNS tunneling indicator independent of entropy.
- **High NXDOMAIN Ratio**: A host whose responses are mostly failed lookups - a classic DGA-infected-client indicator.
- **Refused Queries**: Highlights DNS queries refused by the server.
- **Unsuccessful Responses**: Identifies misconfigurations or potential attacks.

See [DOCUMENTATION.md](DOCUMENTATION.md) for the theory behind each of these signals.

---

## Dependencies

- **Python 3.8+**
- **Scapy**: For packet capture and analysis.
- **NumPy**: For entropy calculation.
- **ReportLab**: For generating PDF reports.
- **tldextract**: For public-suffix-aware domain parsing (used offline, against its bundled snapshot - no network calls).

Install dependencies using:
```bash
pip install -r requirements.txt
```

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Disclaimer

This tool is intended for educational and research purposes only. Ensure you have proper authorization before capturing network traffic.
