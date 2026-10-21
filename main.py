import math
import os
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import dns.resolver
from fastapi import FastAPI, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    title="PhishGuard API",
    description="High-Speed Domain Threat, Brand Impersonation & Typosquatting Detection Engine. Detects phishing domains, homoglyph attacks, lure keywords, high-risk TLDs, and DGA entropy in real time.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

RAPIDAPI_PROXY_SECRET = os.getenv("RAPIDAPI_PROXY_SECRET", "")


def verify_rapidapi_request(secret_header: Optional[str]):
    if RAPIDAPI_PROXY_SECRET and secret_header != RAPIDAPI_PROXY_SECRET:
        raise HTTPException(
            status_code=403,
            detail="Access forbidden: Direct requests not allowed. Please access via RapidAPI marketplace.",
        )


# -------------------------------------------------------------
# Global High-Target Brands Whitelist & Patterns
# -------------------------------------------------------------
OFFICIAL_BRANDS: Dict[str, List[str]] = {
    "google": ["google.com", "google.co.uk", "google.ca", "google.de", "google.fr", "google.com.pk"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "azure.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca", "aws.amazon.com"],
    "paypal": ["paypal.com", "paypal.me"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "stripe": ["stripe.com"],
    "shopify": ["shopify.com", "myshopify.com"],
    "payoneer": ["payoneer.com"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "whatsapp": ["whatsapp.com"],
    "telegram": ["telegram.org", "t.me"],
    "discord": ["discord.com", "discord.gg"],
}

# TLDs with highest statistical abuse in phishing and malware campaigns
HIGH_RISK_TLDS = {
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "zip", "mov", "fit", "work",
    "click", "buzz", "rest", "surf", "monster", "cam", "icu", "sbs", "cfd",
    "beauty", "hair", "quest", "loan", "men", "country", "stream", "gdn"
}

# Lure keywords commonly placed in phishing URLs to trick users
SUSPICIOUS_LURE_KEYWORDS = [
    "login", "signin", "verify", "verification", "security", "account",
    "update", "banking", "wallet", "support", "billing", "confirm",
    "auth", "authenticate", "recover", "password", "protect", "secure",
    "service", "portal", "alert", "notification", "validate", "kyc",
    "claim", "airdrop", "reward", "reauth"
]

# Common visual character substitution pairs used in typosquatting
HOMOGLYPH_SUBSTITUTIONS = {
    "0": "o", "1": "l", "i": "l", "l": "1", "o": "0",
    "vv": "w", "rn": "m", "cl": "d"
}


def clean_domain(raw: str) -> str:
    cleaned = raw.strip().lower()
    if cleaned.startswith("http://") or cleaned.startswith("https://"):
        parsed = urlparse(cleaned)
        cleaned = parsed.netloc or parsed.path
    else:
        cleaned = cleaned.split("/")[0]

    cleaned = cleaned.split(":")[0]
    cleaned = re.sub(r"^www\.", "", cleaned)
    if not cleaned or "." not in cleaned:
        raise HTTPException(status_code=400, detail=f"Invalid domain format: '{raw}'")
    return cleaned


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy to detect algorithmically generated domains (DGA)."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def detect_typosquatting(domain: str) -> Optional[Dict]:
    """Detects brand impersonation using edit distance and visual homoglyph substitutions."""
    parts = domain.split(".")
    domain_body = parts[0]
    full_body = "".join(parts[:-1])

    # Normalize character substitutions (e.g. paypa1 -> paypal, arnazon -> amazon)
    normalized = domain_body
    for fake, real in HOMOGLYPH_SUBSTITUTIONS.items():
        normalized = normalized.replace(fake, real)

    for brand, official_domains in OFFICIAL_BRANDS.items():
        # If it's an official recognized domain, it's NOT a typosquat
        if domain in official_domains:
            return None

        # Check direct containment (e.g. paypal-login-security.com)
        if brand in full_body:
            return {
                "targeted_brand": brand.capitalize(),
                "impersonation_type": "Brand Containment & Keyword Spoofing",
                "confidence": 95,
            }

        # Check Levenshtein distance on primary slug
        dist = levenshtein_distance(domain_body, brand)
        if dist == 1 and len(brand) >= 4:
            return {
                "targeted_brand": brand.capitalize(),
                "impersonation_type": "1-Character Edit Typosquat",
                "confidence": 90,
            }
        elif dist == 2 and len(brand) >= 6:
            return {
                "targeted_brand": brand.capitalize(),
                "impersonation_type": "2-Character Edit Typosquat",
                "confidence": 80,
            }

        # Check normalized substitution distance
        norm_dist = levenshtein_distance(normalized, brand)
        if norm_dist == 0 and domain_body != brand:
            return {
                "targeted_brand": brand.capitalize(),
                "impersonation_type": "Visual Character Replacement (Homoglyph)",
                "confidence": 92,
            }

    return None


def detect_lure_keywords(domain: str) -> List[str]:
    found = []
    lower = domain.lower()
    for kw in SUSPICIOUS_LURE_KEYWORDS:
        if kw in lower:
            found.append(kw)
    return list(dict.fromkeys(found))


def check_dns_records(domain: str) -> Dict[str, bool]:
    has_dns = False
    has_mx = False

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    try:
        resolver.resolve(domain, "A")
        has_dns = True
    except Exception:
        pass

    try:
        resolver.resolve(domain, "MX")
        has_mx = True
    except Exception:
        pass

    return {
        "resolves_dns": has_dns,
        "has_mail_server_mx": has_mx,
    }


def analyze_threat(domain: str) -> Dict:
    cleaned = clean_domain(domain)
    parts = cleaned.split(".")
    tld = parts[-1].lower()
    core_slug = parts[0].lower()

    # Whitelist check
    for brand, official_domains in OFFICIAL_BRANDS.items():
        if cleaned in official_domains or cleaned.endswith("." + official_domains[0]):
            return {
                "domain": cleaned,
                "threat_score": 0,
                "verdict": "SAFE",
                "is_phishing": False,
                "reasons": ["Official verified domain of " + brand.capitalize()],
                "typosquatting": None,
                "lure_keywords": [],
                "tld_risk": {"tld": tld, "is_high_risk": False},
                "entropy": calculate_entropy(core_slug),
                "dns": {"resolves_dns": True, "has_mail_server_mx": True},
            }

    reasons = []
    score = 0

    # 1. Typosquatting / Brand Impersonation Check (+40-50 pts)
    typosquat = detect_typosquatting(cleaned)
    if typosquat:
        score += 45
        reasons.append(
            f"Brand Impersonation detected: targets '{typosquat['targeted_brand']}' via {typosquat['impersonation_type']}"
        )

    # 2. Lure Keywords Check (+15-30 pts)
    lures = detect_lure_keywords(cleaned)
    if lures:
        lure_score = min(30, len(lures) * 15)
        score += lure_score
        reasons.append(f"Suspicious phishing lure keywords detected: {', '.join(lures)}")

    # 3. High-Risk TLD Check (+20 pts)
    is_bad_tld = tld in HIGH_RISK_TLDS
    if is_bad_tld:
        score += 20
        reasons.append(f"High-risk TLD (.{tld}) with statistically heavy abuse and malware history")

    # 4. Homoglyph / Punycode Check (+35 pts)
    is_punycode = cleaned.startswith("xn--") or any(ord(c) > 127 for c in cleaned)
    if is_punycode:
        score += 35
        reasons.append("Punycode/Internationalized Domain Name (IDN) with potential lookalike homoglyph spoofing")

    # 5. Shannon Entropy / DGA Check (+15 pts)
    entropy = calculate_entropy(core_slug)
    if entropy >= 3.7 and len(core_slug) >= 8:
        score += 18
        reasons.append(f"High character randomness / entropy ({entropy}) indicative of DGA malware domain")

    # 6. Hyphen Density / Excessive Subdomains (+10 pts)
    if cleaned.count("-") >= 2:
        score += 12
        reasons.append(f"Excessive hyphens ({cleaned.count('-')}) commonly used in fake security links")
    if len(parts) >= 4:
        score += 10
        reasons.append("Excessive subdomain depth often used to bypass email security filters")

    # 7. DNS Resolution Check
    dns_info = check_dns_records(cleaned)
    if not dns_info["resolves_dns"]:
        score += 10
        reasons.append("Domain does not currently resolve to an active DNS IP address (dead or newly spawned)")

    # Normalize Score
    threat_score = min(100, max(0, score))

    if threat_score >= 65:
        verdict = "DANGEROUS"
        is_phishing = True
    elif threat_score >= 30:
        verdict = "SUSPICIOUS"
        is_phishing = False
    else:
        verdict = "SAFE"
        is_phishing = False

    if not reasons:
        reasons.append("No common phishing or brand impersonation patterns detected.")

    return {
        "domain": cleaned,
        "threat_score": threat_score,
        "verdict": verdict,
        "is_phishing": is_phishing,
        "reasons": reasons,
        "typosquatting": typosquat,
        "lure_keywords": lures,
        "tld_risk": {
            "tld": tld,
            "is_high_risk": is_bad_tld,
        },
        "entropy": entropy,
        "dns": dns_info,
    }


# -------------------------------------------------------------
# Endpoints
# -------------------------------------------------------------
@app.get("/")
def root():
    return {
        "service": "PhishGuard API",
        "description": "Real-Time Domain Threat, Phishing & Typosquatting Detection Engine",
        "documentation": "/docs",
        "version": "1.0.0",
        "status": "operational",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/v1/scan")
def full_threat_scan(
    domain: str = Query(..., description="Target domain or URL to analyze (e.g. paypa1-verify.xyz, google.com)"),
    x_rapidapi_proxy_secret: Optional[str] = Header(None),
):
    """Deep security analysis: returns complete threat breakdown, typosquatting match, entropy, and DNS checks."""
    verify_rapidapi_request(x_rapidapi_proxy_secret)
    return analyze_threat(domain)


@app.get("/v1/quick-check")
def quick_check(
    domain: str = Query(..., description="Target domain or URL to screen"),
    x_rapidapi_proxy_secret: Optional[str] = Header(None),
):
    """Ultra-fast boolean check returning only risk_score, verdict, and is_phishing."""
    verify_rapidapi_request(x_rapidapi_proxy_secret)
    report = analyze_threat(domain)
    return {
        "domain": report["domain"],
        "threat_score": report["threat_score"],
        "verdict": report["verdict"],
        "is_phishing": report["is_phishing"],
    }


@app.get("/v1/typosquat")
def typosquat_check(
    domain: str = Query(..., description="Target domain or URL to check for brand impersonation"),
    x_rapidapi_proxy_secret: Optional[str] = Header(None),
):
    """Specialized endpoint checking brand impersonation and lookalike substitution attacks."""
    verify_rapidapi_request(x_rapidapi_proxy_secret)
    report = analyze_threat(domain)
    return {
        "domain": report["domain"],
        "typosquatting": report["typosquatting"],
        "lure_keywords": report["lure_keywords"],
        "verdict": report["verdict"],
    }
