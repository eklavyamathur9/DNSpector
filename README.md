# DNS Traffic Analyzer

[![CI](https://github.com/eklavyamathur9/Dns-Analyser/actions/workflows/ci.yml/badge.svg)](https://github.com/eklavyamathur9/Dns-Analyser/actions/workflows/ci.yml)

The **DNS Traffic Analyzer** is a Python-based tool designed to capture, analyze, and report DNS traffic. It provides insights into DNS queries, flags, and entropy, helping identify potential anomalies such as DNS tunneling, misconfigurations, or malicious activities.

---

## Features

- **Packet Capture**: Captures DNS packets over UDP port 53 for a user-defined duration.
- **Entropy Calculation**: Computes Shannon entropy for domain names to detect suspicious patterns.
- **DNS Flag Parsing**: Decodes DNS flags into human-readable formats.
- **Detailed Reporting**:
    - **JSON Output**: Saves analysis results in a structured JSON file.
    - **PDF Report**: Generates a professional PDF report with detailed insights.
- **Remarks Generation**: Provides remarks based on entropy and DNS flags to highlight potential issues.

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

- **High Entropy Domains**: Indicates potential DNS tunneling or DGA (Domain Generation Algorithm) activity.
- **Refused Queries**: Highlights DNS queries refused by the server.
- **Unsuccessful Responses**: Identifies misconfigurations or potential attacks.

---

## Dependencies

- **Python 3.6+**
- **Scapy**: For packet capture and analysis.
- **NumPy**: For entropy calculation.
- **ReportLab**: For generating PDF reports.

Install dependencies using:
```bash
pip install scapy numpy reportlab
```

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Disclaimer

This tool is intended for educational and research purposes only. Ensure you have proper authorization before capturing network traffic.
