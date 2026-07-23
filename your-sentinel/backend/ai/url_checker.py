"""
YOUR SENTINEL — AI Model 3: URL Fraud Checker.

Google Safe Browsing + VirusTotal + pattern analysis with PostgreSQL cache.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

import config

logger = logging.getLogger("SENTINEL.AI.URL_CHECKER")


class UrlUtils:
    """URL extraction and normalization utilities."""

    URL_PATTERN = re.compile(
        r"https?://[^\s<>\"']+|www\.[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z]{2,}[^\s<>\"']*",
        re.IGNORECASE,
    )

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        try:
            found = UrlUtils.URL_PATTERN.findall(text)
            normalized: List[str] = []
            for u in found:
                if not u.startswith("http"):
                    u = "https://" + u
                normalized.append(u.strip().rstrip(".,;:)"))
            return list(dict.fromkeys(normalized))
        except Exception as exc:
            logger.error("extract_urls: %s", exc)
            return []

    @staticmethod
    def get_domain(url: str) -> str:
        try:
            parsed = urlparse(url if "://" in url else f"https://{url}")
            host = parsed.netloc or parsed.path.split("/")[0]
            return host.lower().replace("www.", "")
        except Exception:
            return ""

    @staticmethod
    def url_hash(url: str) -> str:
        return hashlib.sha256(url.strip().lower().encode()).hexdigest()


class PatternAnalyzer:
    """Pattern-only URL threat detection (no API keys required)."""

    SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".loan", ".work", ".gq", ".tk", ".ml", ".cf"}
    PHISHING_KEYWORDS = [
        "secure-login", "verify-account", "update-kyc", "bank-login",
        "sbi-online", "hdfc-verify", "paytm-refund", "otp-verify",
        "free-money", "claim-prize", "lottery-winner",
    ]

    @classmethod
    def analyze(cls, url: str) -> Dict[str, Any]:
        try:
            domain = UrlUtils.get_domain(url)
            score = 0.0
            threats: List[str] = []
            url_lower = url.lower()
            for tld in cls.SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    score += 25
                    threats.append(f"suspicious_tld:{tld}")
            for kw in cls.PHISHING_KEYWORDS:
                if kw in url_lower:
                    score += 20
                    threats.append(f"phishing_keyword:{kw}")
            if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
                score += 30
                threats.append("ip_address_url")
            if len(domain) > 40:
                score += 15
                threats.append("long_domain")
            if domain.count("-") >= 3:
                score += 10
                threats.append("hyphen_heavy_domain")
            official_typos = [
                ("onlinesbi", "sbi"), ("hdfcbankk", "hdfc"), ("icicibankk", "icici"),
                ("paytmm", "paytm"), ("phonepee", "phonepe"),
            ]
            for typo, real in official_typos:
                if typo in domain and real not in domain.replace(typo, real):
                    score += 35
                    threats.append(f"typosquat:{typo}")
            return {
                "threat_score": min(score, 100),
                "threat_types": threats,
                "is_malicious": score >= 50,
                "source": "pattern",
            }
        except Exception as exc:
            logger.error("PatternAnalyzer: %s", exc)
            return {"threat_score": 0, "threat_types": [], "is_malicious": False, "source": "pattern"}


class GoogleSafeBrowsing:
    """Google Safe Browsing API v4 lookup."""

    API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(self) -> None:
        self.api_key = config.GOOGLE_SAFE_BROWSING_KEY

    def available(self) -> bool:
        return bool(self.api_key and self.api_key != "YOUR_KEY_HERE")

    async def check(self, url: str) -> Dict[str, Any]:
        if not self.available():
            return {"available": False, "matches": []}
        try:
            payload = {
                "client": {"clientId": "your-sentinel", "clientVersion": "8.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{self.API_URL}?key={self.api_key}",
                    json=payload,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    matches = data.get("matches", [])
                    return {
                        "available": True,
                        "matches": matches,
                        "is_threat": len(matches) > 0,
                        "threat_types": [m.get("threatType") for m in matches],
                    }
        except Exception as exc:
            logger.warning("Safe Browsing check failed: %s", exc)
        return {"available": False, "matches": [], "is_threat": False}


class VirusTotalClient:
    """VirusTotal URL scan API."""

    def __init__(self) -> None:
        self.api_key = config.VIRUSTOTAL_KEY

    def available(self) -> bool:
        return bool(self.api_key and self.api_key != "YOUR_KEY_HERE")

    async def check(self, url: str) -> Dict[str, Any]:
        if not self.available():
            return {"available": False}
        try:
            import base64 as b64
            url_id = b64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": self.api_key}
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
                    return {
                        "available": True,
                        "malicious_count": malicious,
                        "stats": stats,
                        "is_threat": malicious >= 2,
                    }
                if resp.status_code == 404:
                    submit = await client.post(
                        "https://www.virustotal.com/api/v3/urls",
                        headers=headers,
                        data={"url": url},
                    )
                    return {"available": True, "submitted": submit.status_code in (200, 201), "is_threat": False}
        except Exception as exc:
            logger.warning("VirusTotal check failed: %s", exc)
        return {"available": False, "is_threat": False}


class URLChecker:
    """AI 3: orchestrates URL checking with cache integration."""

    def __init__(self) -> None:
        self.safe_browsing = GoogleSafeBrowsing()
        self.virustotal = VirusTotalClient()
        self.pattern = PatternAnalyzer()

    async def check_url(
        self,
        url: str,
        cached: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if cached:
            return {
                "url": url,
                "domain": cached.get("domain"),
                "is_malicious": cached.get("is_malicious", False),
                "threat_score": float(cached.get("threat_score", 0)),
                "threat_types": cached.get("threat_types", []),
                "cached": True,
                "safe_browsing": cached.get("safe_browsing_result", {}),
                "virustotal": cached.get("virustotal_result", {}),
                "pattern": cached.get("pattern_result", {}),
            }
        try:
            domain = UrlUtils.get_domain(url)
            pattern_result = self.pattern.analyze(url)
            sb_result = await self.safe_browsing.check(url)
            vt_result = await self.virustotal.check(url)
            score = float(pattern_result.get("threat_score", 0))
            threat_types = list(pattern_result.get("threat_types", []))
            if sb_result.get("is_threat"):
                score = max(score, 85)
                threat_types.extend(sb_result.get("threat_types", ["SAFE_BROWSING_THREAT"]))
            if vt_result.get("is_threat"):
                mal = vt_result.get("malicious_count", 0)
                score = max(score, min(50 + mal * 5, 95))
                threat_types.append("VIRUSTOTAL_DETECTION")
            is_malicious = score >= 50 or pattern_result.get("is_malicious", False)
            return {
                "url": url,
                "domain": domain,
                "is_malicious": is_malicious,
                "threat_score": round(score, 2),
                "threat_types": threat_types,
                "cached": False,
                "safe_browsing": sb_result,
                "virustotal": vt_result,
                "pattern": pattern_result,
            }
        except Exception as exc:
            logger.error("check_url failed for %s: %s", url, exc)
            return {
                "url": url,
                "is_malicious": False,
                "threat_score": 0,
                "threat_types": [],
                "error": str(exc),
            }

    async def check_urls_concurrent(
        self,
        urls: List[str],
        get_cache_fn=None,
        cache_fn=None,
    ) -> List[Dict[str, Any]]:
        import asyncio
        results: List[Dict[str, Any]] = []
        for url in urls:
            cached = None
            if get_cache_fn:
                try:
                    cached = await get_cache_fn(url)
                except Exception:
                    pass
            result = await self.check_url(url, cached)
            results.append(result)
            if cache_fn and not result.get("cached"):
                try:
                    await cache_fn({
                        "url": url,
                        "domain": result.get("domain"),
                        "is_malicious": result.get("is_malicious"),
                        "threat_score": result.get("threat_score"),
                        "safe_browsing_result": result.get("safe_browsing", {}),
                        "virustotal_result": result.get("virustotal", {}),
                        "pattern_result": result.get("pattern", {}),
                        "threat_types": result.get("threat_types", []),
                    })
                except Exception as exc:
                    logger.warning("cache_url in checker: %s", exc)
        return results
