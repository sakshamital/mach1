"""
YOUR SENTINEL — News Scraper.

Scrapes cybercrime.gov.in, RBI, CERT-IN, PIB every 4 hours.
Seeds 18 hardcoded articles on startup.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("SENTINEL.NEWS_SCRAPER")

HARDCODED_NEWS: List[Dict[str, Any]] = [
    {
        "article_id": "NEWS-001",
        "title": "RBI Warns: No Official Calls to Citizens About Account Blocking",
        "summary": "Reserve Bank clarifies it never contacts citizens by phone regarding KYC or account suspension.",
        "content": "The RBI has reiterated that it does not call, SMS, or email citizens. Any communication claiming to be from RBI demanding immediate action is fraudulent.",
        "source": "RBI",
        "source_url": "https://www.rbi.org.in",
        "category": "banking_otp",
        "severity": "CRITICAL",
        "is_hardcoded": True,
    },
    {
        "article_id": "NEWS-002",
        "title": "Digital Arrest Scam: CBI Issues Nationwide Advisory",
        "summary": "Fraudsters impersonate CBI/ED/NCB officials on video calls demanding money to avoid arrest.",
        "content": "No Indian law enforcement agency conducts digital arrest via video call. Victims across metros have lost crores. Report to 1930 immediately.",
        "source": "Cyber Crime Portal",
        "source_url": "https://cybercrime.gov.in",
        "category": "digital_arrest",
        "severity": "CRITICAL",
        "is_hardcoded": True,
    },
    {
        "article_id": "NEWS-003",
        "title": "TRAI Clarifies: No Calls About SIM Disconnection",
        "summary": "TRAI states it never calls users threatening SIM block within 24 hours.",
        "content": "Press 1 scams claiming TRAI disconnection are fraudulent. Use TRAI DND app for legitimate services only.",
        "source": "TRAI",
        "source_url": "https://www.trai.gov.in",
        "category": "trai_block",
        "severity": "HIGH",
        "is_hardcoded": True,
    },
    {
        "article_id": "NEWS-004",
        "title": "Hi Dad Scam Surge: Police Advisory for Parents",
        "summary": "Family impersonation via WhatsApp from 'new numbers' requesting urgent transfers.",
        "content": "Always verify by calling the family member's original saved number. Scammers exploit emotional urgency.",
        "source": "Delhi Police Cyber Cell",
        "source_url": "https://cybercrime.gov.in",
        "category": "family_impersonation",
        "severity": "HIGH",
        "is_hardcoded": True,
    },
    {
        "article_id": "NEWS-005",
        "title": "Parcel Held in Customs — New Phishing Wave",
        "summary": "Fake FedEx/DHL/India Post SMS with payment links for customs clearance.",
        "content": "Legitimate customs processes do not request UPI payment via random links. Track only on official courier sites.",
        "source": "CERT-In",
        "source_url": "https://www.cert-in.org.in",
        "category": "delivery_customs",
        "severity": "HIGH",
        "is_hardcoded": True,
    },
    {
        "article_id": "NEWS-006",
        "title": "UPI Collect Scam: Scan QR to Receive Money is FALSE",
        "summary": "Scammers send QR codes that debit victim accounts when scanned.",
        "content": "Remember: QR scan is for paying. Receiving money never requires scanning unknown QR codes.",
        "source": "NPCI",
        "source_url": "https://www.npci.org.in",
        "category": "qr_upi",
        "severity": "CRITICAL",
        "is_hardcoded": True,
    },
    {
        "article_id": "NEWS-007",
        "title": "Fake KYC Update Links Targeting Bank Customers",
        "summary": "SMS with bit.ly links claiming account suspension without KYC update.",
        "content": "Banks never send KYC links via SMS. Update only through official banking apps.",
        "source": "Cyber Crime Portal",
        "source_url": "https://cybercrime.gov.in",
        "category": "kyc_aadhaar",
        "severity": "CRITICAL",
        "is_hardcoded": True,
    },
    {
        "article_id": "NEWS-008",
        "title": "Part-Time Job Scams on Telegram — Youth Targeted",
        "summary": "Task completion scams starting with small payments then large deposit demands.",
        "content": "Legitimate employers do not pay via personal UPI for 'likes' and 'ratings'. Initial profits are bait.",
        "source": "Mumbai Cyber Cell",
        "source_url": "https://cybercrime.gov.in",
        "category": "part_time_task",
        "severity": "HIGH",
        "is_hardcoded": True,
    },
    {
        "article_id": "NEWS-009",
        "title": "Microsoft Tech Support Scam Calls Resurface",
        "summary": "Callers claim Windows license expired, request AnyDesk remote access.",
        "content": "Microsoft never proactively calls about PC viruses. Never install remote access for unknown callers.",
        "source": "CERT-In",
        "source_url": "https://www.cert-in.org.in",
        "category": "tech_support",
        "severity": "HIGH",
        "is_hardcoded": True,
    },
    {
        "article_id": "NEWS-010",
        "title": "Investment Scam Apps Removed from Play Store",
        "summary": "SEBI warns against unauthorized trading apps promising guaranteed returns.",
        "content": "Verify SEBI registration. Guaranteed returns are mathematically impossible and legally suspicious.",
        "source": "SEBI",
        "source_url": "https://www.sebi.gov.in",
        "category": "investment_ponzi",
        "severity": "CRITICAL",
        "is_hardcoded": True,
    },
    {
        "article_id": "NEWS-011",
        "title": "Electricity Bill Disconnection Calls — State Advisory",
        "summary": "Fraudsters impersonate electricity boards demanding immediate UPI payment.",
        "content": "Check bills on official state electricity board websites or apps only.",
        "source": "PIB",
        "source_url": "https://pib.gov.in",
        "category": "utility_electricity",
        "severity": "MODERATE",
        "is_hardcoded": True,
    },
    {
        "article_id": "NEWS-012",
        "title": "Loan App Harassment — RBI Ombudsman Alert",
        "summary": "Illegal lending apps using morphed photos and contact list harassment.",
        "content": "Borrow only from RBI-regulated entities. Report illegal apps to cybercrime.gov.in.",
        "source": "RBI",
        "source_url": "https://www.rbi.org.in",
        "category": "loan_app",
        "severity": "HIGH",
        "is_hardcoded": True,
    },
    {
        "article_id": "NEWS-013",
        "title": "Crypto Investment Fraud — ED Investigations",
        "summary": "Fake crypto exchanges blocking withdrawals after large deposits.",
        "content": "RBI has not authorized crypto as legal tender. Unregulated platforms carry extreme fraud risk.",
        "source": "PIB",
        "source_url": "https://pib.gov.in",
        "category": "cryptocurrency",
        "severity": "HIGH",
        "is_hardcoded": True,
    },
    {
        "article_id": "NEWS-014",
        "title": "Lottery SMS Scam — You Have Won 25 Lakh",
        "summary": "Mass SMS claiming lottery wins requiring processing fee payment.",
        "content": "You cannot win a lottery you never entered. Processing fees are always scams.",
        "source": "Cyber Crime Portal",
        "source_url": "https://cybercrime.gov.in",
        "category": "lottery_prize",
        "severity": "HIGH",
        "is_hardcoded": True,
    },
    {
        "article_id": "NEWS-015",
        "title": "Aadhaar Biometric Update Fraud Calls",
        "summary": "Callers claim Aadhaar deactivated, request OTP for 'reactivation'.",
        "content": "UIDAI never asks for OTP on phone. Use only myaadhaar.uidai.gov.in.",
        "source": "UIDAI",
        "source_url": "https://uidai.gov.in",
        "category": "kyc_aadhaar",
        "severity": "CRITICAL",
        "is_hardcoded": True,
    },
    {
        "article_id": "NEWS-016",
        "title": "Job Offer with Registration Fee — IT Sector Alert",
        "summary": "Fake HR from reputed companies asking fees for background verification.",
        "content": "No legitimate company charges candidates registration fees. Verify on official careers portal.",
        "source": "NASSCOM Advisory",
        "source_url": "https://cybercrime.gov.in",
        "category": "job_employment",
        "severity": "MODERATE",
        "is_hardcoded": True,
    },
    {
        "article_id": "NEWS-017",
        "title": "Insurance Maturity Refund Call Scam",
        "summary": "Fraudsters claim LIC/policy maturity, request bank details and OTP.",
        "content": "LIC communicates through official channels. Never share OTP for 'refund processing'.",
        "source": "IRDAI",
        "source_url": "https://www.irdai.gov.in",
        "category": "insurance",
        "severity": "MODERATE",
        "is_hardcoded": True,
    },
    {
        "article_id": "NEWS-018",
        "title": "National Cyber Crime Helpline 1930 — 24x7 Support",
        "summary": "Citizens can report fraud and get immediate guidance by calling 1930.",
        "content": "Save 1930. Report within hours of fraud for best chance of fund freeze. Also file at cybercrime.gov.in.",
        "source": "MHA Cyber Crime",
        "source_url": "https://cybercrime.gov.in",
        "category": "government_impersonation",
        "severity": "MODERATE",
        "is_hardcoded": True,
    },
]

SCRAPE_SOURCES = [
    {"name": "Cyber Crime Portal", "url": "https://cybercrime.gov.in", "category": "government_impersonation"},
    {"name": "RBI", "url": "https://www.rbi.org.in/Scripts/BS_PressReleaseDisplay.aspx", "category": "banking_otp"},
    {"name": "CERT-In", "url": "https://www.cert-in.org.in/s2c.jsp?lang=en", "category": "phishing"},
    {"name": "PIB", "url": "https://pib.gov.in/indexd.aspx", "category": "government_impersonation"},
]


async def seed_hardcoded_news(upsert_fn) -> int:
    """Insert 18 hardcoded articles on startup."""
    count = 0
    try:
        for article in HARDCODED_NEWS:
            data = dict(article)
            data["published_at"] = datetime.now(timezone.utc)
            await upsert_fn(data)
            count += 1
        logger.info("Seeded %d hardcoded news articles", count)
    except Exception as exc:
        logger.error("seed_hardcoded_news failed: %s", exc)
    return count


async def scrape_source(source: Dict[str, str]) -> List[Dict[str, Any]]:
    """Attempt to scrape headlines from a source URL."""
    articles: List[Dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            resp = await client.get(
                source["url"],
                headers={"User-Agent": "YourSentinel/8.0 (Cybercrime News Bot)"},
            )
            if resp.status_code != 200:
                return articles
            html = resp.text
            titles = re.findall(
                r"<title[^>]*>([^<]+)</title>|<h[12][^>]*>([^<]{20,120})</h[12]>",
                html,
                re.IGNORECASE,
            )
            seen = set()
            for match in titles[:5]:
                title = (match[0] or match[1] or "").strip()
                if len(title) < 20 or title in seen:
                    continue
                seen.add(title)
                aid = f"SCRAPE-{uuid.uuid4().hex[:8].upper()}"
                articles.append({
                    "article_id": aid,
                    "title": title[:200],
                    "summary": f"Scraped advisory from {source['name']}.",
                    "content": f"Source: {source['url']}. Review official site for full details.",
                    "source": source["name"],
                    "source_url": source["url"],
                    "category": source.get("category", "unknown"),
                    "severity": "MODERATE",
                    "is_hardcoded": False,
                    "published_at": datetime.now(timezone.utc),
                })
    except Exception as exc:
        logger.warning("scrape_source %s failed: %s", source.get("name"), exc)
    return articles


async def run_full_scrape(upsert_fn, add_learned_fn=None) -> Dict[str, Any]:
    """Run scrape on all sources and upsert articles."""
    results = {"scraped": 0, "sources": [], "errors": []}
    try:
        for source in SCRAPE_SOURCES:
            articles = await scrape_source(source)
            for art in articles:
                try:
                    await upsert_fn(art)
                    results["scraped"] += 1
                    if add_learned_fn and art.get("title"):
                        await add_learned_fn({
                            "source": source["name"],
                            "pattern_text": art["title"],
                            "category": art.get("category"),
                            "keywords": art.get("title", "").lower().split()[:10],
                            "severity": art.get("severity", "MODERATE"),
                        })
                except Exception as exc:
                    results["errors"].append(str(exc))
            results["sources"].append(source["name"])
    except Exception as exc:
        logger.error("run_full_scrape failed: %s", exc)
        results["errors"].append(str(exc))
    return results
