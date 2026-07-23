"""
YOUR SENTINEL v8.0 — Central configuration module.

Contains: environment settings, Official India institution database (35+ entries),
behaviour manipulation patterns, scam taxonomy, mutation templates, prevention tips,
and application constants used across all AI modules and API endpoints.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Environment & API keys
# ---------------------------------------------------------------------------

APP_NAME: str = "Your Sentinel"
APP_VERSION: str = "8.0.0"
APP_TAGLINE: str = "Free AI-powered scam detection for every Indian citizen"

DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://localhost:5432/your_sentinel")
HUGGINGFACE_API_KEY: str = os.getenv("HUGGINGFACE_API_KEY", "YOUR_KEY_HERE")
HUGGINGFACE_MODEL: str = os.getenv(
    "HUGGINGFACE_MODEL", "ai4bharat/indic-bert"
)
HUGGINGFACE_INFERENCE_URL: str = os.getenv(
    "HUGGINGFACE_INFERENCE_URL",
    "https://api-inference.huggingface.co/models/ai4bharat/indic-bert",
)
GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "YOUR_KEY_HERE")
GEMINI_VISION_MODEL: str = os.getenv("GEMINI_VISION_MODEL", "gemini-2.0-flash-exp")
GEMINI_TEXT_MODEL: str = os.getenv("GEMINI_TEXT_MODEL", "gemini-1.5-flash")
GOOGLE_SAFE_BROWSING_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "YOUR_KEY_HERE")
VIRUSTOTAL_KEY: str = os.getenv("VIRUSTOTAL_KEY", "YOUR_KEY_HERE")
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "YOUR_KEY_HERE")
GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")

HOST: str = os.getenv("HOST", "0.0.0.0")
PORT: int = int(os.getenv("PORT", "8000"))
DEBUG: bool = os.getenv("DEBUG", "false").lower() in ("1", "true", "yes")
CORS_ORIGINS: List[str] = os.getenv("CORS_ORIGINS", "*").split(",")

NEWS_SCRAPE_INTERVAL_HOURS: int = int(os.getenv("NEWS_SCRAPE_INTERVAL_HOURS", "4"))
URL_CACHE_TTL_DAYS: int = int(os.getenv("URL_CACHE_TTL_DAYS", "7"))
MAX_SCAN_TEXT_LENGTH: int = int(os.getenv("MAX_SCAN_TEXT_LENGTH", "50000"))
MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "10"))

RISK_THRESHOLDS: Dict[str, float] = {
    "low": 25.0,
    "moderate": 50.0,
    "high": 75.0,
    "critical": 90.0,
}

ANTI_FP_KEYWORD_ONLY_CAP: float = 20.0

# ---------------------------------------------------------------------------
# Behaviour manipulation patterns (7 universal)
# ---------------------------------------------------------------------------

BEHAVIOUR_PATTERNS: Dict[str, Dict[str, Any]] = {
    "creates_fear": {
        "label": "Creates Fear",
        "weight": 12.0,
        "keywords_en": [
            "arrest", "warrant", "legal action", "police", "cbi", "ed raid",
            "account frozen", "suspended", "blocked", "illegal", "crime",
            "digital arrest", "custody", "imprisonment", "fine", "penalty",
        ],
        "keywords_hi": [
            "girftari", "warrant", "police", "jail", "kanoon", "account band",
            "suspend", "illegal", "digital arrest", "jurm", "dhamki",
        ],
    },
    "creates_urgency": {
        "label": "Creates Urgency",
        "weight": 10.0,
        "keywords_en": [
            "urgent", "immediately", "within 24 hours", "last chance", "expire",
            "act now", "limited time", "today only", "hurry", "deadline",
            "before midnight", "final notice", "do not delay",
        ],
        "keywords_hi": [
            "turant", "abhi", "24 ghante", "aakhri mauka", "expire",
            "jaldi", "aaj hi", "der mat karo", "final notice",
        ],
    },
    "promises_money": {
        "label": "Promises Money/Rewards",
        "weight": 11.0,
        "keywords_en": [
            "won", "lottery", "prize", "cashback", "refund", "double your money",
            "investment return", "guaranteed profit", "earn daily", "free money",
            "bonus", "reward", "cash prize", "million", "crore",
        ],
        "keywords_hi": [
            "jeet", "lottery", "inaam", "cashback", "paisa double",
            "return", "profit", "roz kamao", "muft paisa", "bonus",
        ],
    },
    "asks_for_secrets": {
        "label": "Asks for Secrets/OTP/PIN",
        "weight": 15.0,
        "keywords_en": [
            "otp", "pin", "password", "cvv", "card number", "aadhaar number",
            "pan number", "upi pin", "net banking", "verification code",
            "share otp", "send otp", "confirm otp", "security code",
        ],
        "keywords_hi": [
            "otp", "pin", "password", "cvv", "card number", "aadhaar",
            "pan", "upi pin", "net banking", "verification code",
            "otp bhejo", "otp share",
        ],
    },
    "impersonates_authority": {
        "label": "Impersonates Authority",
        "weight": 14.0,
        "keywords_en": [
            "rbi", "income tax", "cbi", "ed", "narcotics", "cyber cell",
            "trai", "uidai", "sebi", "npci", "government", "ministry",
            "official", "department", "customs", "income tax department",
        ],
        "keywords_hi": [
            "rbi", "income tax", "cbi", "sarkar", "sarkari", "official",
            "department", "customs", "cyber cell",
        ],
    },
    "isolates_victim": {
        "label": "Isolates Victim",
        "weight": 9.0,
        "keywords_en": [
            "do not tell", "keep secret", "don't share", "confidential",
            "between us", "don't call bank", "don't discuss", "private matter",
            "no one should know", "stay on call", "don't hang up",
        ],
        "keywords_hi": [
            "kisi ko mat batana", "secret rakho", "bank ko mat batana",
            "sirf hum", "private", "call mat kaatna",
        ],
    },
    "requests_payment": {
        "label": "Requests Payment/Transfer",
        "weight": 13.0,
        "keywords_en": [
            "pay now", "transfer", "upi", "send money", "payment link",
            "paytm", "phonepe", "gpay", "bank transfer", "neft", "rtgs",
            "scan qr", "qr code", "wallet", "recharge", "fee payment",
        ],
        "keywords_hi": [
            "paisa bhejo", "transfer", "upi", "payment", "qr scan",
            "link pe click", "fee bharo",
        ],
    },
}

# ---------------------------------------------------------------------------
# Emotional / family impersonation patterns
# ---------------------------------------------------------------------------

FAMILY_IMPERSONATION_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "hi_dad_mom",
        "patterns": [
            r"hi\s+(dad|papa|father|mom|mummy|ma|beta|beti)",
            r"main\s+(mummy|papa|mom|dad|beta|beti)\s+hoon",
            r"new\s+number",
            r"lost\s+my\s+phone",
            r"emergency\s+need\s+money",
        ],
        "weight": 18.0,
        "verify_mode": True,
    },
    {
        "id": "stranded_emergency",
        "patterns": [
            r"stranded", r"accident", r"hospital", r"need\s+money\s+urgently",
            r"can't\s+call", r"whatsapp\s+only",
        ],
        "weight": 16.0,
        "verify_mode": True,
    },
]

VERIFY_MODE_STEPS: List[str] = [
    "Do NOT send money or share OTP yet.",
    "Call the person on their OLD saved number (not the new number in the message).",
    "Ask a personal question only they would know (childhood nickname, last family event).",
    "If they don't answer or story changes, it is a SCAM — report to 1930.",
    "Tell family members about this verification method.",
    "Save Cyber Crime Helpline: 1930 or visit cybercrime.gov.in.",
]

# ---------------------------------------------------------------------------
# Mutation templates (15+ evolved scam patterns)
# ---------------------------------------------------------------------------

MUTATION_TEMPLATES: List[Dict[str, Any]] = [
    {"id": "money_doubling", "name": "Money Doubling Scheme", "keywords": ["double", "triple", "investment", "guaranteed", "returns"], "base_risk": 85},
    {"id": "digital_arrest", "name": "Digital Arrest Scam", "keywords": ["digital arrest", "video call", "cbi", "ed", "customs"], "base_risk": 95},
    {"id": "trai_block", "name": "TRAI Number Block", "keywords": ["trai", "number block", "sim block", "disconnection"], "base_risk": 80},
    {"id": "parcel_customs", "name": "Parcel/Customs Scam", "keywords": ["parcel", "customs", "fedex", "dhl", "delivery", "consignment"], "base_risk": 75},
    {"id": "kyc_update", "name": "KYC Update Fraud", "keywords": ["kyc", "update kyc", "aadhaar link", "pan link"], "base_risk": 82},
    {"id": "job_offer", "name": "Fake Job Offer", "keywords": ["job", "hiring", "registration fee", "training fee", "offer letter"], "base_risk": 70},
    {"id": "part_time_task", "name": "Part-Time Task Scam", "keywords": ["task", "commission", "like", "rating", "telegram group"], "base_risk": 78},
    {"id": "screen_share", "name": "Screen Share / AnyDesk", "keywords": ["anydesk", "teamviewer", "screen share", "remote access"], "base_risk": 90},
    {"id": "qr_upi", "name": "QR/UPI Collect Scam", "keywords": ["scan qr", "receive money", "upi collect"], "base_risk": 88},
    {"id": "electricity_bill", "name": "Electricity Bill Scam", "keywords": ["electricity", "disconnection", "bill pending", "power cut"], "base_risk": 72},
    {"id": "loan_app", "name": "Illegal Loan App", "keywords": ["instant loan", "no documents", "harassment", "morphed photos"], "base_risk": 85},
    {"id": "crypto_investment", "name": "Crypto Investment", "keywords": ["crypto", "bitcoin", "trading app", "withdrawal fee"], "base_risk": 80},
    {"id": "insurance_refund", "name": "Insurance Refund Scam", "keywords": ["lic", "insurance", "refund", "maturity"], "base_risk": 68},
    {"id": "tech_support", "name": "Tech Support Scam", "keywords": ["microsoft", "virus", "windows support", "refund department"], "base_risk": 83},
    {"id": "romance_trap", "name": "Romance/Honey Trap", "keywords": ["love", "marry", "send gift", "customs fee", "army officer"], "base_risk": 76},
    {"id": "fake_police", "name": "Fake Police/CBI/ED", "keywords": ["cbi officer", "ed raid", "police station", "fir"], "base_risk": 92},
]

# ---------------------------------------------------------------------------
# Scam taxonomy categories
# ---------------------------------------------------------------------------

SCAM_CATEGORIES: List[Dict[str, str]] = [
    {"id": "banking_otp", "name": "Banking / OTP Fraud", "severity_default": "CRITICAL"},
    {"id": "trai_block", "name": "TRAI / Number Blocking Scam", "severity_default": "HIGH"},
    {"id": "digital_arrest", "name": "Digital Arrest Scam", "severity_default": "CRITICAL"},
    {"id": "family_impersonation", "name": "Family Impersonation / Hi Dad Scam", "severity_default": "HIGH"},
    {"id": "investment_ponzi", "name": "Investment / Ponzi Scheme", "severity_default": "CRITICAL"},
    {"id": "delivery_customs", "name": "Delivery / Customs Parcel Scam", "severity_default": "HIGH"},
    {"id": "job_employment", "name": "Job / Employment Scam", "severity_default": "MODERATE"},
    {"id": "kyc_aadhaar", "name": "KYC / Aadhaar Verification Scam", "severity_default": "CRITICAL"},
    {"id": "lottery_prize", "name": "Lottery / Prize Fraud", "severity_default": "HIGH"},
    {"id": "tech_support", "name": "Tech Support Scam", "severity_default": "HIGH"},
    {"id": "romance_honeytrap", "name": "Romantic / Honey-trap Scam", "severity_default": "HIGH"},
    {"id": "fake_police", "name": "Fake Police / CBI / ED Scam", "severity_default": "CRITICAL"},
    {"id": "qr_upi", "name": "QR Code / UPI Scam", "severity_default": "CRITICAL"},
    {"id": "screen_share", "name": "Screen Share / Remote Access Scam", "severity_default": "CRITICAL"},
    {"id": "utility_electricity", "name": "Electricity / Utility Scam", "severity_default": "MODERATE"},
    {"id": "loan_app", "name": "Loan App Fraud", "severity_default": "HIGH"},
    {"id": "cryptocurrency", "name": "Cryptocurrency Fraud", "severity_default": "HIGH"},
    {"id": "part_time_task", "name": "Part Time Job / Task Completion Scam", "severity_default": "MODERATE"},
    {"id": "phishing", "name": "Phishing / Credential Harvesting", "severity_default": "CRITICAL"},
    {"id": "fake_emergency", "name": "Fake Emergency / Stranded Scam", "severity_default": "HIGH"},
    {"id": "insurance", "name": "Insurance Scam", "severity_default": "MODERATE"},
    {"id": "government_impersonation", "name": "Government Impersonation", "severity_default": "CRITICAL"},
    {"id": "unknown", "name": "Suspicious / Unclassified", "severity_default": "MODERATE"},
    {"id": "safe", "name": "Likely Safe", "severity_default": "LOW"},
]

# ---------------------------------------------------------------------------
# Prevention tips database (15+ categories)
# ---------------------------------------------------------------------------

PREVENTION_TIPS: Dict[str, Dict[str, Any]] = {
    "banking_otp": {
        "title": "Banking & OTP Safety",
        "tips": [
            "Banks NEVER ask for OTP, PIN, or CVV over call/SMS.",
            "Never share OTP even if caller claims to be from your bank.",
            "Use official bank app only; type URL yourself.",
            "Enable transaction alerts on your registered mobile.",
        ],
        "helpline": "1930 (Cyber Crime) | Bank fraud: call number on back of card",
    },
    "trai_block": {
        "title": "TRAI Scam Prevention",
        "tips": [
            "TRAI never calls citizens about number blocking.",
            "Do not press any number if IVR claims SIM will be blocked.",
            "Verify via TRAI DND app or trai.gov.in only.",
        ],
        "helpline": "1930",
    },
    "digital_arrest": {
        "title": "Digital Arrest Awareness",
        "tips": [
            "No Indian agency conducts 'digital arrest' over video call.",
            "CBI/ED/Police do not demand money on video calls.",
            "Hang up and report to local cyber police immediately.",
        ],
        "helpline": "1930 | cybercrime.gov.in",
    },
    "family_impersonation": {
        "title": "Family Impersonation",
        "tips": [
            "Always call back on the OLD saved number before sending money.",
            "Ask personal verification questions.",
            "Scammers create urgency — legitimate family allows verification time.",
        ],
        "helpline": "1930",
    },
    "kyc_aadhaar": {
        "title": "KYC / Aadhaar Safety",
        "tips": [
            "Banks send KYC reminders via official app/SMS short codes only.",
            "UIDAI never asks for Aadhaar OTP via phone.",
            "Use only official bank branches or apps for KYC.",
        ],
        "helpline": "1947 (UIDAI) | 1930",
    },
    "qr_upi": {
        "title": "UPI & QR Safety",
        "tips": [
            "Scanning QR is for PAYING — receiving money does not need QR scan.",
            "Verify UPI ID spelling before any transaction.",
            "Google Pay has NO phone support — any caller is a scammer.",
        ],
        "helpline": "1930",
    },
    "tech_support": {
        "title": "Tech Support Scams",
        "tips": [
            "Microsoft/Apple NEVER call about viruses.",
            "Never install AnyDesk/TeamViewer for unknown callers.",
            "Close browser pop-ups claiming virus — they are fake.",
        ],
        "helpline": "1930",
    },
    "delivery_customs": {
        "title": "Parcel Scams",
        "tips": [
            "Customs does not call for small personal parcels with payment links.",
            "Track packages only on official courier websites.",
            "Never pay via UPI links from unknown SMS.",
        ],
        "helpline": "1930",
    },
    "investment_ponzi": {
        "title": "Investment Fraud",
        "tips": [
            "Guaranteed high returns are always scams.",
            "Check SEBI registration before any investment.",
            "Never invest via Telegram/WhatsApp groups.",
        ],
        "helpline": "1930 | SEBI SCORES portal",
    },
    "job_employment": {
        "title": "Job Scam Prevention",
        "tips": [
            "Legitimate employers never ask registration/training fees upfront.",
            "Verify company on MCA portal and official careers page.",
            "Beware of work-from-home with only chat interviews.",
        ],
        "helpline": "1930",
    },
    "phishing": {
        "title": "Phishing Prevention",
        "tips": [
            "Check URL spelling — sbi.co vs onlinesbi.com.",
            "Look for HTTPS and padlock; still verify domain.",
            "Never enter credentials from email/SMS links.",
        ],
        "helpline": "1930",
    },
    "government_impersonation": {
        "title": "Government Impersonation",
        "tips": [
            "RBI NEVER calls citizens — any RBI call is 100% scam.",
            "Income Tax notices come via official portal/email.",
            "Government benefits never require upfront payment.",
        ],
        "helpline": "1930 | cybercrime.gov.in",
    },
    "screen_share": {
        "title": "Remote Access Scams",
        "tips": [
            "Never share screen with unknown callers.",
            "Banks never ask to install remote access apps.",
            "Disconnect immediately if asked for AnyDesk code.",
        ],
        "helpline": "1930",
    },
    "cryptocurrency": {
        "title": "Crypto Scam Awareness",
        "tips": [
            "Unregulated crypto schemes promising fixed returns are fraudulent.",
            "Never transfer crypto to 'investment manager' wallets.",
            "RBI has warned against unauthorized crypto platforms.",
        ],
        "helpline": "1930",
    },
    "fake_emergency": {
        "title": "Emergency Scam Prevention",
        "tips": [
            "Verify emergencies by calling known numbers.",
            "Contact other family members before sending money.",
            "Police impersonators create panic — verify at local station.",
        ],
        "helpline": "1930 | 100 (Police emergency)",
    },
}

# ---------------------------------------------------------------------------
# Official India Database — 35+ institutions
# ---------------------------------------------------------------------------

@dataclass
class OfficialInstitution:
    id: str
    short_name: str
    full_name: str
    websites: List[str] = field(default_factory=list)
    phones: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    apps: List[str] = field(default_factory=list)
    note: str = ""


def _inst(
    id_: str,
    short: str,
    full: str,
    websites: List[str],
    phones: Optional[List[str]] = None,
    emails: Optional[List[str]] = None,
    apps: Optional[List[str]] = None,
    note: str = "",
) -> OfficialInstitution:
    return OfficialInstitution(
        id=id_,
        short_name=short,
        full_name=full,
        websites=websites,
        phones=phones or [],
        emails=emails or [],
        apps=apps or [],
        note=note,
    )


OFFICIAL_INDIA_DB: Dict[str, OfficialInstitution] = {
    "SBI": _inst(
        "SBI", "SBI", "State Bank of India",
        ["https://www.onlinesbi.sbi", "https://www.sbi.co.in"],
        ["1800112211", "18004253800"],
        [],
        ["YONO SBI", "SBI Anywhere"],
        "Official net banking: onlinesbi.sbi — verify spelling carefully.",
    ),
    "HDFC": _inst(
        "HDFC", "HDFC Bank", "HDFC Bank Limited",
        ["https://www.hdfcbank.com", "https://netbanking.hdfcbank.com"],
        ["18002600", "18001600"],
        [],
        ["HDFC Bank MobileBanking"],
    ),
    "ICICI": _inst(
        "ICICI", "ICICI Bank", "ICICI Bank Limited",
        ["https://www.icicibank.com"],
        ["18001080", "18601207777"],
        [],
        ["iMobile Pay"],
    ),
    "AXIS": _inst(
        "AXIS", "Axis Bank", "Axis Bank Limited",
        ["https://www.axisbank.com"],
        ["18001035577", "18604195555"],
        [],
        ["Axis Mobile"],
    ),
    "PNB": _inst(
        "PNB", "PNB", "Punjab National Bank",
        ["https://www.pnbindia.in"],
        ["18001800", "18002021"],
        [],
        ["PNB One"],
    ),
    "BOB": _inst(
        "BOB", "Bank of Baroda", "Bank of Baroda",
        ["https://www.bankofbaroda.in"],
        ["18001024455", "1800223344"],
        [],
        ["Baroda M-Connect"],
    ),
    "KOTAK": _inst(
        "KOTAK", "Kotak Mahindra Bank", "Kotak Mahindra Bank",
        ["https://www.kotak.com"],
        ["18602662666", "18002099999"],
        [],
        ["Kotak Mobile Banking"],
    ),
    "INDUSIND": _inst(
        "INDUSIND", "IndusInd Bank", "IndusInd Bank",
        ["https://www.indusind.com"],
        ["18602677777"],
        [],
        ["IndusMobile"],
    ),
    "RBI": _inst(
        "RBI", "RBI", "Reserve Bank of India",
        ["https://www.rbi.org.in"],
        [],
        [],
        [],
        "RBI NEVER calls citizens. Any RBI call is 100% a scam.",
    ),
    "TRAI": _inst(
        "TRAI", "TRAI", "Telecom Regulatory Authority of India",
        ["https://www.trai.gov.in"],
        [],
        [],
        ["TRAI DND"],
        "TRAI never calls to say your number will be blocked.",
    ),
    "UIDAI": _inst(
        "UIDAI", "UIDAI", "Unique Identification Authority of India",
        ["https://uidai.gov.in", "https://myaadhaar.uidai.gov.in"],
        ["1947"],
        [],
        ["mAadhaar"],
        "UIDAI never asks for Aadhaar OTP via unsolicited calls.",
    ),
    "INCOMETAX": _inst(
        "INCOMETAX", "Income Tax", "Income Tax Department India",
        ["https://www.incometax.gov.in"],
        ["18001030025"],
        [],
        ["AIS for Taxpayer"],
        "Notices via official portal only — not payment links on WhatsApp.",
    ),
    "CYBERCRIME": _inst(
        "CYBERCRIME", "Cyber Crime", "National Cyber Crime Reporting Portal",
        ["https://cybercrime.gov.in"],
        ["1930", "155260"],
        [],
        [],
        "Report all cyber fraud at cybercrime.gov.in or call 1930.",
    ),
    "SEBI": _inst(
        "SEBI", "SEBI", "Securities and Exchange Board of India",
        ["https://www.sebi.gov.in"],
        [],
        [],
        [],
        "Check SEBI registration before investing.",
    ),
    "NPCI": _inst(
        "NPCI", "NPCI", "National Payments Corporation of India",
        ["https://www.npci.org.in"],
        [],
        [],
        ["BHIM"],
    ),
    "LIC": _inst(
        "LIC", "LIC", "Life Insurance Corporation of India",
        ["https://licindia.in", "https://ebiz.licindia.in"],
        ["18004259876"],
        [],
        ["LIC Digital"],
    ),
    "IRDAI": _inst(
        "IRDAI", "IRDAI", "Insurance Regulatory Authority of India",
        ["https://www.irdai.gov.in"],
        [],
        [],
        [],
    ),
    "GOOGLEPAY": _inst(
        "GOOGLEPAY", "Google Pay", "Google Pay India",
        ["https://pay.google.com"],
        [],
        [],
        ["Google Pay"],
        "Google Pay has NO phone support. Any GPay caller is a scammer.",
    ),
    "PHONEPE": _inst(
        "PHONEPE", "PhonePe", "PhonePe Private Limited",
        ["https://www.phonepe.com"],
        ["08068727374"],
        [],
        ["PhonePe"],
    ),
    "PAYTM": _inst(
        "PAYTM", "Paytm", "One97 Communications (Paytm)",
        ["https://paytm.com"],
        ["01204456456"],
        [],
        ["Paytm"],
    ),
    "JIO": _inst(
        "JIO", "Jio", "Reliance Jio Infocomm Limited",
        ["https://www.jio.com"],
        ["199", "18008899999"],
        [],
        ["MyJio"],
    ),
    "AIRTEL": _inst(
        "AIRTEL", "Airtel", "Bharti Airtel Limited",
        ["https://www.airtel.in"],
        ["121", "198"],
        [],
        ["Airtel Thanks"],
    ),
    "BSNL": _inst(
        "BSNL", "BSNL", "Bharat Sanchar Nigam Limited",
        ["https://www.bsnl.co.in"],
        ["1503", "18001801503"],
        [],
        [],
    ),
    "VI": _inst(
        "VI", "Vi", "Vodafone Idea Limited",
        ["https://www.myvi.in"],
        ["199", "198"],
        [],
        ["Vi App"],
    ),
    "AMAZON": _inst(
        "AMAZON", "Amazon India", "Amazon Seller Services Pvt Ltd",
        ["https://www.amazon.in"],
        [],
        [],
        ["Amazon India"],
        "Amazon does not call for OTP or remote access.",
    ),
    "FLIPKART": _inst(
        "FLIPKART", "Flipkart", "Flipkart Internet Private Limited",
        ["https://www.flipkart.com"],
        [],
        [],
        ["Flipkart"],
    ),
    "FEDEX": _inst(
        "FEDEX", "FedEx", "FedEx Express Transportation",
        ["https://www.fedex.com/en-in"],
        ["18004190180"],
        [],
        [],
    ),
    "DHL": _inst(
        "DHL", "DHL", "DHL Express India",
        ["https://www.dhl.co.in"],
        ["1800111345"],
        [],
        [],
    ),
    "INDIAPOST": _inst(
        "INDIAPOST", "India Post", "Department of Posts India",
        ["https://www.indiapost.gov.in"],
        [],
        [],
        [],
    ),
    "MICROSOFT": _inst(
        "MICROSOFT", "Microsoft", "Microsoft Corporation",
        ["https://www.microsoft.com"],
        [],
        [],
        [],
        "Microsoft NEVER calls about virus/PC problems.",
    ),
    "APPLE": _inst(
        "APPLE", "Apple", "Apple Inc.",
        ["https://www.apple.com/in"],
        ["0008004401966"],
        [],
        [],
        "Apple does not proactively call about security issues.",
    ),
    "NABARD": _inst(
        "NABARD", "NABARD", "National Bank for Agriculture and Rural Development",
        ["https://www.nabard.org"],
        [],
        [],
        [],
    ),
    "MEESHO": _inst(
        "MEESHO", "Meesho", "Meesho Technologies Private Limited",
        ["https://www.meesho.com"],
        [],
        [],
        ["Meesho"],
    ),
    "BHIM": _inst(
        "BHIM", "BHIM UPI", "BHIM — Bharat Interface for Money",
        ["https://www.bhimupi.org.in"],
        [],
        [],
        ["BHIM"],
    ),
}

# Domain aliases for mismatch detection
OFFICIAL_DOMAIN_ALIASES: Dict[str, str] = {
    "onlinesbi": "SBI",
    "sbi": "SBI",
    "hdfcbank": "HDFC",
    "icicibank": "ICICI",
    "axisbank": "AXIS",
    "pnbindia": "PNB",
    "bankofbaroda": "BOB",
    "kotak": "KOTAK",
    "rbi": "RBI",
    "trai": "TRAI",
    "uidai": "UIDAI",
    "incometax": "INCOMETAX",
    "cybercrime": "CYBERCRIME",
    "phonepe": "PHONEPE",
    "paytm": "PAYTM",
    "googlepay": "GOOGLEPAY",
    "amazon": "AMAZON",
    "flipkart": "FLIPKART",
}

# ---------------------------------------------------------------------------
# Indian states & UTs for report form
# ---------------------------------------------------------------------------

INDIAN_STATES: List[str] = [
    "Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh",
    "Goa", "Gujarat", "Haryana", "Himachal Pradesh", "Jharkhand", "Karnataka",
    "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur", "Meghalaya",
    "Mizoram", "Nagaland", "Odisha", "Punjab", "Rajasthan", "Sikkim",
    "Tamil Nadu", "Telangana", "Tripura", "Uttar Pradesh", "Uttarakhand",
    "West Bengal",
    "Andaman and Nicobar Islands", "Chandigarh", "Dadra and Nagar Haveli and Daman and Diu",
    "Delhi", "Jammu and Kashmir", "Ladakh", "Lakshadweep", "Puducherry",
]

# ---------------------------------------------------------------------------
# Report legal sections reference
# ---------------------------------------------------------------------------

IT_ACT_SECTIONS: List[str] = [
    "Section 66 — Computer related offences",
    "Section 66C — Identity theft",
    "Section 66D — Cheating by personation using computer resource",
    "Section 66E — Violation of privacy",
    "Section 43 — Penalty for damage to computer resource",
]

BNS_SECTIONS: List[str] = [
    "Section 318 — Cheating",
    "Section 319 — Cheating by personation",
    "Section 336 — Forgery",
    "Section 338 — Forgery for purpose of cheating",
    "Section 351 — Criminal intimidation",
]

# ---------------------------------------------------------------------------
# Pipeline step labels (frontend progress)
# ---------------------------------------------------------------------------

PIPELINE_STEPS: List[str] = [
    "Extracting URLs from input",
    "Checking URLs (Safe Browsing + VirusTotal)",
    "Analyzing image with Gemini Vision",
    "Running behaviour engine & mismatch detector",
    "Deep text analysis with Gemini",
    "Computing unified verdict",
    "Preparing forensic narrative",
    "Saving results & notifying",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def get_risk_level(score: float) -> str:
    """Map numeric score to risk level string."""
    if score >= RISK_THRESHOLDS["critical"]:
        return "CRITICAL"
    if score >= RISK_THRESHOLDS["high"]:
        return "HIGH"
    if score >= RISK_THRESHOLDS["moderate"]:
        return "MODERATE"
    return "LOW"


def get_prevention_for_category(category: str) -> Dict[str, Any]:
    """Return prevention tips dict for category id."""
    return PREVENTION_TIPS.get(
        category,
        PREVENTION_TIPS.get("phishing", {"title": "General Safety", "tips": ["Call 1930", "Visit cybercrime.gov.in"], "helpline": "1930"}),
    )


def official_db_json() -> List[Dict[str, Any]]:
    """Serialize Official India DB for API response."""
    result: List[Dict[str, Any]] = []
    for key, inst in OFFICIAL_INDIA_DB.items():
        result.append({
            "id": inst.id,
            "short_name": inst.short_name,
            "full_name": inst.full_name,
            "websites": inst.websites,
            "phones": inst.phones,
            "emails": inst.emails,
            "apps": inst.apps,
            "note": inst.note,
        })
    return result


def generate_scan_id() -> str:
    """Generate human-readable scan ID."""
    import uuid
    short = uuid.uuid4().hex[:8].upper()
    return f"SN-{short}"
