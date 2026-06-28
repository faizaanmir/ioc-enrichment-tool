"""
enrichers/abuseipdb.py
======================
AbuseIPDB API v2 enrichment handler.
Supports: IP addresses only.

API docs: https://docs.abuseipdb.com/
Free tier: 1,000 requests/day
"""

import requests


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = 10  # seconds


def enrich_abuseipdb(ip: str, api_key: str) -> dict:
    """
    Query AbuseIPDB for a single IP address.
    Returns a dict with keys: abuse_score, abuse_country, abuse_asn
    """
    result = {
        "abuse_score": "N/A",
        "abuse_country": "N/A",
        "abuse_asn": "N/A"
    }

    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,       # Look back 90 days
        "verbose": False
    }

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=TIMEOUT
        )

        if response.status_code == 429:
            raise Exception("Rate limit hit")

        response.raise_for_status()
        data = response.json().get("data", {})

        result["abuse_score"]   = f"{data.get('abuseConfidenceScore', 0)}%"
        result["abuse_country"] = data.get("countryCode", "N/A")
        result["abuse_asn"]     = data.get("isp", "N/A")

    except requests.exceptions.Timeout:
        raise Exception("Request timed out")
    except requests.exceptions.ConnectionError:
        raise Exception("Connection error — check network")

    return result
