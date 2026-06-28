"""
enrichers/virustotal.py
=======================
VirusTotal API v3 enrichment handler.
Supports: IP, domain, URL, MD5/SHA1/SHA256 hashes.

API docs: https://developers.virustotal.com/reference/overview
Free tier: 500 requests/day, 4 requests/minute
"""

import requests
import hashlib


VT_BASE_URL = "https://www.virustotal.com/api/v3"
TIMEOUT = 10  # seconds


def _get_headers(api_key: str) -> dict:
    return {"x-apikey": api_key}


def _parse_stats(stats: dict) -> tuple:
    """Extract malicious/total from last_analysis_stats."""
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total      = sum(stats.values())
    return malicious + suspicious, total


def _extract_tags(data: dict) -> list:
    """Pull popular_threat_classification tags if available."""
    tags = []
    ptc = data.get("attributes", {}).get("popular_threat_classification", {})
    for category in ptc.get("popular_threat_category", []):
        tags.append(category.get("value", ""))
    for name in ptc.get("popular_threat_name", []):
        tags.append(name.get("value", ""))
    return list(set(tags))[:5]  # Cap at 5 tags


def enrich_virustotal(ioc: str, ioc_type: str, api_key: str) -> dict:
    """
    Query VirusTotal for a single IOC.
    Returns a dict with keys: vt_detections, vt_total, vt_tags
    """
    result = {
        "vt_detections": "N/A",
        "vt_total": "N/A",
        "vt_tags": []
    }

    try:
        if ioc_type == "ip":
            url = f"{VT_BASE_URL}/ip_addresses/{ioc}"
        elif ioc_type == "domain":
            url = f"{VT_BASE_URL}/domains/{ioc}"
        elif ioc_type in ("md5", "sha1", "sha256"):
            url = f"{VT_BASE_URL}/files/{ioc}"
        elif ioc_type == "url":
            # VT requires URL ID (base64url-encoded URL without padding)
            import base64
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
            url = f"{VT_BASE_URL}/urls/{url_id}"
        else:
            return result

        response = requests.get(url, headers=_get_headers(api_key), timeout=TIMEOUT)

        if response.status_code == 404:
            result["vt_detections"] = "Not found"
            return result

        if response.status_code == 429:
            raise Exception("Rate limit hit — slow down requests")

        response.raise_for_status()
        data = response.json().get("data", {})
        stats = data.get("attributes", {}).get("last_analysis_stats", {})

        if stats:
            detections, total = _parse_stats(stats)
            result["vt_detections"] = detections
            result["vt_total"] = total

        result["vt_tags"] = _extract_tags(data)

    except requests.exceptions.Timeout:
        raise Exception("Request timed out")
    except requests.exceptions.ConnectionError:
        raise Exception("Connection error — check network")

    return result
