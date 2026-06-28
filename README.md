# IOC Enrichment Tool

A Python command-line tool for bulk enrichment of Indicators of Compromise (IOCs) against threat intelligence APIs. Supports IP addresses, domains, URLs, and file hashes.

Designed for SOC analysts to rapidly triage and contextualize IOCs during incident response and threat hunting.

---

## Supported APIs

| API | IOC Types | Free Tier |
|---|---|---|
| [VirusTotal](https://www.virustotal.com) | IP, Domain, URL, Hash | 500 req/day |
| [AbuseIPDB](https://www.abuseipdb.com) | IP | 1,000 req/day |

---

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/mir-faizaan-sajjad/ioc-enrichment-tool.git
cd ioc-enrichment-tool
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API keys

Copy the example config and add your keys:

```bash
cp config.example.ini config.ini
```

Edit `config.ini`:

```ini
[virustotal]
api_key = YOUR_VT_API_KEY_HERE

[abuseipdb]
api_key = YOUR_ABUSEIPDB_API_KEY_HERE
```

Get free API keys at:
- VirusTotal: https://www.virustotal.com/gui/join-us
- AbuseIPDB: https://www.abuseipdb.com/register

---

## Usage

### Single IOC

```bash
python enrich.py --ioc 8.8.8.8
python enrich.py --ioc malicious-domain.com
python enrich.py --ioc 44d88612fea8a8f36de82e1278abb02f   # MD5
```

### Bulk from file (one IOC per line)

```bash
python enrich.py --file iocs.txt
```

### Output to CSV

```bash
python enrich.py --file iocs.txt --output results.csv
```

### Specify APIs to query

```bash
python enrich.py --ioc 1.2.3.4 --apis virustotal abuseipdb
```

---

## Output Example

```
IOC                  | Type   | VT Detections | Abuse Score | Country | ASN           | Tags
---------------------|--------|---------------|-------------|---------|---------------|------------------
185.220.101.45       | IP     | 12/94         | 100%        | DE      | AS205100      | TOR, Scanner
malware-c2.xyz       | Domain | 45/94         | N/A         | RU      | AS49505       | Malware, C2
44d88612fea8a8f36... | Hash   | 68/72         | N/A         | N/A     | N/A           | Trojan, Ransomware
```

---

## Files

```
ioc-enrichment-tool/
├── enrich.py           # Main script
├── enrichers/
│   ├── virustotal.py   # VT API handler
│   └── abuseipdb.py    # AbuseIPDB API handler
├── utils/
│   ├── ioc_parser.py   # IOC type detection (IP, domain, hash, URL)
│   └── output.py       # CSV / terminal output formatting
├── config.example.ini  # Config template (copy to config.ini)
├── requirements.txt
└── README.md
```

---

## Requirements

- Python 3.8+
- See `requirements.txt`

---

## Disclaimer

This tool is intended for authorized security operations use only. Do not submit sensitive client IOCs to public threat intelligence APIs without authorization.

---

*Author: Faizaan Sajjad*
