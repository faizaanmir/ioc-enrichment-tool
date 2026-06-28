#!/usr/bin/env python3
"""
IOC Enrichment Tool
===================
Bulk-enrich IPs, domains, URLs, and file hashes against
VirusTotal and AbuseIPDB threat intelligence APIs.

Usage:
    python enrich.py --ioc 8.8.8.8
    python enrich.py --file iocs.txt
    python enrich.py --file iocs.txt --output results.csv
    python enrich.py --ioc 1.2.3.4 --apis virustotal abuseipdb
"""

import argparse
import sys
import time
import configparser
import os
from pathlib import Path

from utils.ioc_parser import classify_ioc, load_iocs_from_file
from utils.output import print_results_table, write_csv
from enrichers.virustotal import enrich_virustotal
from enrichers.abuseipdb import enrich_abuseipdb


CONFIG_PATH = Path(__file__).parent / "config.ini"
RATE_LIMIT_DELAY = 0.5  # seconds between API calls (respect free tier limits)


def load_config():
    """Load API keys from config.ini."""
    if not CONFIG_PATH.exists():
        print(f"[ERROR] config.ini not found. Copy config.example.ini to config.ini and add your API keys.")
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)
    return config


def enrich_ioc(ioc: str, ioc_type: str, config: configparser.ConfigParser, apis: list) -> dict:
    """Run enrichment for a single IOC across selected APIs."""
    result = {
        "ioc": ioc,
        "type": ioc_type,
        "vt_detections": "N/A",
        "vt_total": "N/A",
        "vt_tags": [],
        "abuse_score": "N/A",
        "abuse_country": "N/A",
        "abuse_asn": "N/A",
        "errors": []
    }

    if "virustotal" in apis:
        vt_key = config.get("virustotal", "api_key", fallback=None)
        if vt_key and vt_key != "YOUR_VT_API_KEY_HERE":
            try:
                vt_data = enrich_virustotal(ioc, ioc_type, vt_key)
                result.update(vt_data)
            except Exception as e:
                result["errors"].append(f"VirusTotal: {str(e)}")
        else:
            result["errors"].append("VirusTotal: API key not configured")

    time.sleep(RATE_LIMIT_DELAY)

    if "abuseipdb" in apis and ioc_type == "ip":
        abuse_key = config.get("abuseipdb", "api_key", fallback=None)
        if abuse_key and abuse_key != "YOUR_ABUSEIPDB_API_KEY_HERE":
            try:
                abuse_data = enrich_abuseipdb(ioc, abuse_key)
                result.update(abuse_data)
            except Exception as e:
                result["errors"].append(f"AbuseIPDB: {str(e)}")
        else:
            result["errors"].append("AbuseIPDB: API key not configured")

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Bulk IOC enrichment via VirusTotal and AbuseIPDB",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--ioc", type=str, help="Single IOC to enrich (IP, domain, hash, or URL)")
    input_group.add_argument("--file", type=str, help="Path to text file with one IOC per line")

    parser.add_argument(
        "--output", type=str, default=None,
        help="Output CSV file path (default: print to terminal)"
    )
    parser.add_argument(
        "--apis", nargs="+", default=["virustotal", "abuseipdb"],
        choices=["virustotal", "abuseipdb"],
        help="APIs to query (default: all)"
    )

    args = parser.parse_args()
    config = load_config()

    # Build IOC list
    if args.ioc:
        iocs = [args.ioc.strip()]
    else:
        iocs = load_iocs_from_file(args.file)

    if not iocs:
        print("[ERROR] No valid IOCs found.")
        sys.exit(1)

    print(f"\n[*] Enriching {len(iocs)} IOC(s) via: {', '.join(args.apis)}\n")

    results = []
    for idx, ioc in enumerate(iocs, 1):
        ioc_type = classify_ioc(ioc)
        print(f"[{idx}/{len(iocs)}] {ioc} ({ioc_type})", end=" ... ")

        result = enrich_ioc(ioc, ioc_type, config, args.apis)
        results.append(result)

        if result["errors"]:
            print(f"DONE (warnings: {'; '.join(result['errors'])})")
        else:
            print("DONE")

    print()

    if args.output:
        write_csv(results, args.output)
        print(f"[+] Results saved to: {args.output}")
    else:
        print_results_table(results)


if __name__ == "__main__":
    main()
