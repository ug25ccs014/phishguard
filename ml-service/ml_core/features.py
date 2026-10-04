from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import asdict, dataclass
from urllib.parse import parse_qsl, urlsplit

FEATURE_VERSION = "url-lexical-v1"

SUSPICIOUS_TERMS = {
    "account", "activate", "auth", "bank", "billing", "confirm", "credential",
    "crypto", "invoice", "login", "log-in", "mfa", "password", "payment",
    "recover", "secure", "security", "signin", "sign-in", "unlock", "update",
    "verify", "verification", "wallet", "webscr", "session", "support",
}
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.one",
}


@dataclass(frozen=True)
class URLFeatures:
    url_length: int
    hostname_length: int
    path_length: int
    query_length: int
    fragment_length: int
    domain_length: int
    tld_length: int
    path_depth: int
    query_parameter_count: int
    dot_count: int
    slash_count: int
    hyphen_count: int
    underscore_count: int
    digit_count: int
    special_character_count: int
    percent_encoded_count: int
    at_symbol: int
    double_slash_redirect: int
    has_ip_hostname: int
    has_punycode: int
    subdomain_count: int
    suspicious_term_count: int
    suspicious_term_ratio: float
    hostname_entropy: float
    url_entropy: float
    uses_shortener: int
    https: int

    def to_dict(self) -> dict[str, int | float]:
        return asdict(self)


_SPECIAL_RE = re.compile(r"[^A-Za-z0-9]")


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return round(-sum((count / length) * math.log2(count / length) for count in counts.values()), 6)


def _safe_split(url: str):
    parsed = urlsplit(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only valid HTTP/HTTPS URLs with a hostname are supported.")
    return parsed


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def extract_features(url: str) -> URLFeatures:
    parsed = _safe_split(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    domain = hostname.lower().strip(".")
    labels = [label for label in domain.split(".") if label]
    tld = labels[-1] if labels else ""
    path_and_query = f"{path}?{query}" if query else path
    lower = url.lower()

    suspicious_terms = sum(1 for term in SUSPICIOUS_TERMS if re.search(rf"(?<![a-z]){re.escape(term)}(?![a-z])", lower))
    specials = len(_SPECIAL_RE.findall(url))
    digits = sum(char.isdigit() for char in url)
    encoded = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    slash_count = url.count("/")

    return URLFeatures(
        url_length=len(url),
        hostname_length=len(hostname),
        path_length=len(path),
        query_length=len(query),
        fragment_length=len(fragment),
        domain_length=len(domain),
        tld_length=len(tld),
        path_depth=sum(1 for part in path.split("/") if part),
        query_parameter_count=len(parse_qsl(query, keep_blank_values=True)),
        dot_count=url.count("."),
        slash_count=slash_count,
        hyphen_count=url.count("-"),
        underscore_count=url.count("_"),
        digit_count=digits,
        special_character_count=specials,
        percent_encoded_count=encoded,
        at_symbol=int("@" in url),
        double_slash_redirect=int("//" in path_and_query),
        has_ip_hostname=int(_is_ip(hostname)),
        has_punycode=int(any(label.startswith("xn--") for label in labels)),
        subdomain_count=max(len(labels) - 2, 0) if not _is_ip(hostname) else 0,
        suspicious_term_count=suspicious_terms,
        suspicious_term_ratio=round(suspicious_terms / max(len(labels) + len([p for p in path.split("/") if p]), 1), 6),
        hostname_entropy=_entropy(hostname),
        url_entropy=_entropy(url),
        uses_shortener=int(domain in SHORTENER_DOMAINS),
        https=int(parsed.scheme == "https"),
    )


def canonicalize_url(url: str) -> str:
    """Canonical representation used only for training deduplication/leakage checks."""
    from urllib.parse import urlunsplit

    try:
        parsed = _safe_split(url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if not hostname:
            return ""
        port = parsed.port
        netloc = hostname if port is None else f"{hostname}:{port}"
        if parsed.username is not None:
            user = parsed.username
            password = f":{parsed.password}" if parsed.password is not None else ""
            netloc = f"{user}{password}@{netloc}"
        path = parsed.path or "/"
        return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))
    except (ValueError, TypeError):
        return ""


FEATURE_NAMES = list(URLFeatures.__dataclass_fields__.keys())
