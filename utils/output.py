"""
utils/output.py
===============
Terminal table and CSV output for enrichment results.
"""

import csv
from typing import List


def _format_vt(result: dict) -> str:
    det = result.get("vt_detections", "N/A")
    total = result.get("vt_total", "N/A")
    if det == "N/A" or total == "N/A":
        return str(det)
    return f"{det}/{total}"


def _format_tags(result: dict) -> str:
    tags = result.get("vt_tags", [])
    return ", ".join(tags) if tags else "None"


def print_results_table(results: List[dict]):
    """Print enrichment results as a formatted terminal table."""

    col_widths = {
        "ioc":     max(20, max(len(r["ioc"]) for r in results)),
        "type":    8,
        "vt":      15,
        "abuse":   12,
        "country": 9,
        "asn":     25,
        "tags":    30,
    }

    header = (
        f"{'IOC':<{col_widths['ioc']}} | "
        f"{'Type':<{col_widths['type']}} | "
        f"{'VT Detections':<{col_widths['vt']}} | "
        f"{'Abuse Score':<{col_widths['abuse']}} | "
        f"{'Country':<{col_widths['country']}} | "
        f"{'ASN/ISP':<{col_widths['asn']}} | "
        f"{'Tags':<{col_widths['tags']}}"
    )

    separator = "-" * len(header)

    print(separator)
    print(header)
    print(separator)

    for r in results:
        ioc_display = r["ioc"]
        if len(ioc_display) > col_widths["ioc"]:
            ioc_display = ioc_display[:col_widths["ioc"] - 3] + "..."

        print(
            f"{ioc_display:<{col_widths['ioc']}} | "
            f"{r['type']:<{col_widths['type']}} | "
            f"{_format_vt(r):<{col_widths['vt']}} | "
            f"{str(r.get('abuse_score', 'N/A')):<{col_widths['abuse']}} | "
            f"{str(r.get('abuse_country', 'N/A')):<{col_widths['country']}} | "
            f"{str(r.get('abuse_asn', 'N/A'))[:col_widths['asn']]:<{col_widths['asn']}} | "
            f"{_format_tags(r)[:col_widths['tags']]:<{col_widths['tags']}}"
        )

    print(separator)

    # Show warnings if any
    warnings = [(r["ioc"], r["errors"]) for r in results if r.get("errors")]
    if warnings:
        print("\n[!] Warnings:")
        for ioc, errors in warnings:
            for err in errors:
                print(f"    {ioc}: {err}")


def write_csv(results: List[dict], filepath: str):
    """Write enrichment results to a CSV file."""
    fieldnames = [
        "ioc", "type",
        "vt_detections", "vt_total", "vt_tags",
        "abuse_score", "abuse_country", "abuse_asn",
        "errors"
    ]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            row = dict(r)
            row["vt_tags"] = ", ".join(r.get("vt_tags", []))
            row["errors"]  = "; ".join(r.get("errors", []))
            writer.writerow(row)
