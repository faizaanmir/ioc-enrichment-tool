"""
utils/ioc_parser.py
===================
Classifies IOCs by type (ip, domain, url, md5, sha1, sha256)
and loads IOC lists from files.
"""

import re
import ipaddress
from pathlib import Path


# Regex patterns
RE_MD5    = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1   = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_URL    = re.compile(r"^https?://", re.IGNORECASE)
RE_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


def classify_ioc(ioc: str) -> str:
    """
    Returns the IOC type as a string:
    'ip', 'domain', 'url', 'md5', 'sha1', 'sha256', or 'unknown'
    """
    ioc = ioc.strip()

    # Try IP address first
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass

    # Hash types
    if RE_SHA256.match(ioc):
        return "sha256"
    if RE_SHA1.match(ioc):
        return "sha1"
    if RE_MD5.match(ioc):
        return "md5"

    # URL (check before domain)
    if RE_URL.match(ioc):
        return "url"

    # Domain
    if RE_DOMAIN.match(ioc):
        return "domain"

    return "unknown"


def load_iocs_from_file(filepath: str) -> list:
    """
    Load IOCs from a text file (one per line).
    Skips blank lines and lines starting with # (comments).
    Returns a deduplicated list preserving order.
    """
    path = Path(filepath)
    if not path.exists():
        print(f"[ERROR] File not found: {filepath}")
        return []

    seen = set()
    iocs = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            ioc = line.strip()
            if not ioc or ioc.startswith("#"):
                continue
            if ioc not in seen:
                seen.add(ioc)
                iocs.append(ioc)

    return iocs
