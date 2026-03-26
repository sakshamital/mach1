"""
================================================================================
PROJECT : your sentinel | INDIA CYBERCRIME INTELLIGENCE ENGINE
VERSION : 7.0.0 — COMPLETE INTEGRATED EDITION
================================================================================
ALL FEATURES:
  1.  Core Backend          — FastAPI + SQLite + OCR
  2.  Groq API              — Ultra-fast cloud AI (2-4 sec)
  3.  Vision AI             — Sees ANY image (diagrams, photos, screenshots)
  4.  Citizen Output        — Plain language, no jargon
  5.  Behaviour Engine      — 7 universal manipulation patterns
  6.  Emotional Detection   — Family impersonation, fake emergency
  7.  50-50 Verify Mode     — Honest uncertainty + verification guide
  8.  Community Learning    — Users confirm scams, system learns
  9.  Auto News Reading     — Reads cybercrime.gov.in + RBI alerts every 6h
  10. Pattern Mutation      — Detects evolved versions of known scams
  11. Official India DB     — 35+ real institutions (banks, govt, telecom)
  12. Mismatch Detector     — Fake number/website/email caught instantly
  13. Public News Board     — Latest scam news with prevention tips
  14. Push Notifications    — Real-time alerts for new scam patterns
  15. News Categorization   — Organized by scam type with severity rating
  16. Prevention Tips DB    — Curated safety advice per scam category

INSTALL:
  pip install fastapi uvicorn pydantic pytesseract pillow requests numpy beautifulsoup4 aiohttp

WINDOWS TESSERACT:
  Uncomment the tesseract path line in Section 1

RUN:
  python main.py
  Open: http://127.0.0.1:8000
================================================================================
"""

# ── Imports ───────────────────────────────────────────────────────────────────
import os, io, re, json, uuid, time, csv, logging, sqlite3
# Load .env file for local development (ignored in production)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not installed — using system env vars (Render/production)
import asyncio, hashlib, requests, uvicorn, pytesseract, numpy as np
import base64, html as html_lib
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from pydantic import BaseModel
from PIL import Image, ImageOps, ImageFilter, ImageEnhance
from fastapi import (FastAPI, UploadFile, File, Form,
                     HTTPException, BackgroundTasks, Request, Query, WebSocket, WebSocketDisconnect)
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

# ── Windows Tesseract path (uncomment if needed) ──────────────────────────────
# pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# ==============================================================================
# 1. DIRECTORIES & LOGGING
# ==============================================================================

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
VAULT_DIR = os.path.join(BASE_DIR, "sentinel_vault")
RPT_DIR   = os.path.join(VAULT_DIR, "exports")
DB_PATH   = os.path.join(VAULT_DIR, "sentinel.db")
for d in [VAULT_DIR, RPT_DIR]:
    os.makedirs(d, exist_ok=True)

fmt = logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s', '%H:%M:%S')
fh  = logging.FileHandler(os.path.join(VAULT_DIR, "sentinel.log"), encoding='utf-8')
sh  = logging.StreamHandler()
fh.setFormatter(fmt); sh.setFormatter(fmt)
logger = logging.getLogger("SENTINEL")
logger.setLevel(logging.INFO)
logger.addHandler(fh); logger.addHandler(sh)

# ==============================================================================
# 2. GROQ CONFIG
# Get free key at console.groq.com — paste below
# ==============================================================================

GROQ_API_KEY      = os.getenv("GROQ_API_KEY", "YOUR_GROQ_API_KEY_HERE")
GROQ_API_URL      = "https://api.groq.com/openai/v1/chat/completions"
GROQ_TEXT_MODEL   = "llama-3.1-8b-instant"
GROQ_VISION_MODEL = "meta-llama/llama-4-scout-17b-16e-instruct"

# ==============================================================================
# 3. OFFICIAL INDIA INSTITUTION DATABASE
# Any phone/website/email NOT in here = FAKE
# ==============================================================================

OFFICIAL_DB = {
    "SBI":        {"full_name":"State Bank of India",          "websites":["onlinesbi.sbi","sbi.co.in"],         "phones":["1800112211","18004253800","1800110009"], "emails":["@sbi.co.in"],           "note":"SBI never asks OTP over phone or WhatsApp"},
    "HDFC":       {"full_name":"HDFC Bank",                    "websites":["hdfcbank.com"],                       "phones":["18002026161","18002600"],                "emails":["@hdfcbank.com"],        "note":"HDFC never calls asking for card details"},
    "ICICI":      {"full_name":"ICICI Bank",                   "websites":["icicibank.com"],                      "phones":["18001080"],                              "emails":["@icicibank.com"],       "note":"ICICI never sends payment links on WhatsApp"},
    "AXIS":       {"full_name":"Axis Bank",                    "websites":["axisbank.com"],                       "phones":["18004195959"],                           "emails":["@axisbank.com"],        "note":""},
    "PNB":        {"full_name":"Punjab National Bank",         "websites":["pnbindia.in"],                        "phones":["18001802222"],                           "emails":["@pnb.co.in"],           "note":""},
    "BOB":        {"full_name":"Bank of Baroda",               "websites":["bankofbaroda.in"],                    "phones":["18005700"],                              "emails":["@bankofbaroda.com"],    "note":""},
    "KOTAK":      {"full_name":"Kotak Mahindra Bank",          "websites":["kotak.com","kotakbank.com"],          "phones":["18002740110"],                           "emails":["@kotak.com"],           "note":""},
    "INDUSIND":   {"full_name":"IndusInd Bank",                "websites":["indusind.com"],                       "phones":["18002741000"],                           "emails":["@indusind.com"],        "note":""},
    "RBI":        {"full_name":"Reserve Bank of India",        "websites":["rbi.org.in"],                         "phones":["14440","18002201080"],                   "emails":["@rbi.org.in"],          "note":"RBI NEVER calls citizens directly. Any RBI call is a scam."},
    "TRAI":       {"full_name":"TRAI",                         "websites":["trai.gov.in"],                        "phones":["1800110999"],                            "emails":["@trai.gov.in"],         "note":"TRAI never calls to say your number will be blocked. Always a scam."},
    "UIDAI":      {"full_name":"UIDAI (Aadhaar)",              "websites":["uidai.gov.in","myaadhaar.uidai.gov.in"],"phones":["1947"],                                "emails":["@uidai.gov.in"],        "note":"UIDAI never asks Aadhaar OTP over phone"},
    "INCOMETAX":  {"full_name":"Income Tax Department",        "websites":["incometax.gov.in"],                   "phones":["18001030025"],                           "emails":["@incometax.gov.in"],    "note":"IT dept sends notices only via registered post or official portal"},
    "CYBERCRIME": {"full_name":"National Cyber Crime Portal",  "websites":["cybercrime.gov.in"],                  "phones":["1930"],                                  "emails":["@cybercrime.gov.in"],   "note":"1930 is the ONLY official cyber crime helpline"},
    "SEBI":       {"full_name":"SEBI",                         "websites":["sebi.gov.in"],                        "phones":["18002667575"],                           "emails":["@sebi.gov.in"],         "note":"SEBI never calls to offer investment tips or schemes"},
    "NPCI":       {"full_name":"NPCI",                         "websites":["npci.org.in"],                        "phones":["18001201740"],                           "emails":["@npci.org.in"],         "note":"NPCI does not contact individuals directly"},
    "LIC":        {"full_name":"LIC India",                    "websites":["licindia.in"],                        "phones":["18004259876"],                           "emails":["@licindia.in"],         "note":"LIC never asks premium payment via UPI to personal numbers"},
    "IRDAI":      {"full_name":"IRDAI",                        "websites":["irdai.gov.in"],                       "phones":["155255"],                                "emails":["@irdai.gov.in"],        "note":""},
    "GOOGLEPAY":  {"full_name":"Google Pay",                   "websites":["pay.google.com"],                     "phones":[],                                        "emails":["@google.com"],          "note":"Google Pay has NO phone support. Any GPay caller is a scammer."},
    "PHONEPE":    {"full_name":"PhonePe",                      "websites":["phonepe.com"],                        "phones":["08068727374"],                           "emails":["@phonepe.com"],         "note":"PhonePe never asks for screen share"},
    "PAYTM":      {"full_name":"Paytm",                        "websites":["paytm.com"],                          "phones":["01204456456"],                           "emails":["@paytm.com"],           "note":""},
    "JIO":        {"full_name":"Reliance Jio",                 "websites":["jio.com"],                            "phones":["199","18008899999"],                     "emails":["@jio.com"],             "note":"Jio never asks OTP to upgrade SIM over phone"},
    "AIRTEL":     {"full_name":"Airtel",                       "websites":["airtel.in"],                          "phones":["121","198"],                             "emails":["@airtel.com"],          "note":""},
    "BSNL":       {"full_name":"BSNL",                         "websites":["bsnl.co.in"],                         "phones":["1800345150","1500"],                     "emails":["@bsnl.co.in"],          "note":""},
    "VI":         {"full_name":"Vi (Vodafone Idea)",           "websites":["myvi.in"],                            "phones":["199","18009009009"],                     "emails":["@vodafoneidea.com"],    "note":""},
    "AMAZON":     {"full_name":"Amazon India",                 "websites":["amazon.in"],                          "phones":["18003009009"],                           "emails":["@amazon.in","@amazon.com"],"note":"Amazon never asks OTP or remote access for refunds"},
    "FLIPKART":   {"full_name":"Flipkart",                     "websites":["flipkart.com"],                       "phones":["18002082020"],                           "emails":["@flipkart.com"],        "note":""},
    "FEDEX":      {"full_name":"FedEx India",                  "websites":["fedex.com"],                          "phones":["18002090123"],                           "emails":["@fedex.com"],           "note":"FedEx never asks customs duty via UPI — always a scam"},
    "DHL":        {"full_name":"DHL India",                    "websites":["dhl.com"],                            "phones":["18002003345"],                           "emails":["@dhl.com"],             "note":"DHL never asks payment via Google Pay or PhonePe"},
    "INDIAPOST":  {"full_name":"India Post",                   "websites":["indiapost.gov.in"],                   "phones":["18002666868"],                           "emails":["@indiapost.gov.in"],    "note":""},
    "MICROSOFT":  {"full_name":"Microsoft",                    "websites":["microsoft.com","support.microsoft.com"],"phones":["18004192323"],                         "emails":["@microsoft.com"],       "note":"Microsoft NEVER calls about virus/PC problems. Always a scam."},
    "APPLE":      {"full_name":"Apple India",                  "websites":["apple.com"],                          "phones":["0008000401966"],                         "emails":["@apple.com"],           "note":"Apple never calls about iCloud being hacked"},
    "NABARD":     {"full_name":"NABARD",                       "websites":["nabard.org"],                         "phones":["02226539895"],                           "emails":["@nabard.org"],          "note":""},
    "MEESHO":     {"full_name":"Meesho",                       "websites":["meesho.com"],                         "phones":["08061799600"],                           "emails":["@meesho.com"],          "note":""},
    "BHIM":       {"full_name":"BHIM UPI",                     "websites":["bhimupi.org.in"],                     "phones":["18001201740"],                           "emails":["@npci.org.in"],         "note":""},
}

OFFICIAL_DOMAINS = {w.lower() for d in OFFICIAL_DB.values() for w in d["websites"]}
OFFICIAL_PHONES  = {re.sub(r'\D','',p) for d in OFFICIAL_DB.values() for p in d["phones"]}
OFFICIAL_EMAILS  = {e.lower() for d in OFFICIAL_DB.values() for e in d["emails"]}

# ==============================================================================
# 4. PREVENTION TIPS DATABASE — per scam category (Feature 16)
# ==============================================================================

PREVENTION_TIPS = {
    "Banking / OTP Fraud": [
        "Never share OTP with anyone — your bank will NEVER ask for it",
        "Bank employees never call asking for card number, CVV or PIN",
        "If someone says your account is blocked — call your bank directly on the official number",
        "Always verify by calling your bank on the number printed on your debit card",
        "Enable SMS alerts for all transactions — report unknown transactions immediately",
    ],
    "TRAI / Number Blocking Scam": [
        "TRAI never calls citizens to say their number will be blocked",
        "If you get such a call — hang up immediately, it is 100% a scam",
        "Your telecom operator (Jio/Airtel/BSNL) will send written notice before disconnection",
        "Report fake TRAI calls to 1930 or cybercrime.gov.in",
    ],
    "Digital Arrest Scam": [
        "No government agency conducts 'digital arrest' over video call — this does not exist",
        "Real police, CBI, ED never ask you to stay on video call for hours",
        "If threatened with arrest — immediately call 112 (police) or a lawyer",
        "Do not transfer any money under any threat — it is always a scam",
        "Tell family members immediately if anyone threatens you this way",
    ],
    "Job / Employment Scam": [
        "Legitimate companies never ask for registration fees or security deposits",
        "Verify job offers by checking the company website directly",
        "Never pay money to get a job — real employers pay you, not the other way",
        "Check company on LinkedIn and official government job portals",
        "Part-time tasks that pay per click/like are always scams",
    ],
    "Investment / Ponzi Scheme": [
        "No investment gives guaranteed high returns — if it sounds too good, it is fake",
        "Never invest money based on WhatsApp groups or Telegram channels",
        "Check if the investment company is SEBI registered at sebi.gov.in",
        "Pig Butchering: scammers befriend you first, then lure into fake crypto investments",
        "Once money is sent to crypto — it is almost impossible to recover",
    ],
    "Family Impersonation / Hi Dad Scam": [
        "Always call back on the person's KNOWN saved number before sending money",
        "Ask a private question only the real person would know",
        "Never send money based on a message from an unknown number claiming to be family",
        "Real family members will understand if you take 5 minutes to verify",
        "QR codes always send money OUT — nobody sends money to you via QR",
    ],
    "Delivery / Customs Parcel Scam": [
        "FedEx, DHL and India Post never ask for customs duty via UPI or Google Pay",
        "Verify any delivery fee by calling the courier company on their official number",
        "Real customs clearance notices come via registered post — not WhatsApp calls",
        "Never pay 'import duty' to a personal UPI ID or mobile number",
    ],
    "KYC / Aadhaar Verification Scam": [
        "KYC updates are done through bank branches or official apps — never over phone",
        "UIDAI never calls asking for Aadhaar OTP — 1947 is only for genuine help",
        "Never share Aadhaar number, OTP or biometrics with unknown callers",
        "If your account is genuinely blocked — visit the bank branch in person",
    ],
    "Phishing / Credential Harvesting": [
        "Always check the website URL before entering any password or OTP",
        "Real bank websites end in .sbi, .hdfcbank.com etc — not random domains",
        "Never click links in SMS or WhatsApp to login to bank accounts",
        "Bookmark your bank's official website — use only that",
        "Enable two-factor authentication on all important accounts",
    ],
    "Screen Share / Remote Access Scam": [
        "Never install AnyDesk, TeamViewer or any app told by an unknown caller",
        "Once someone has screen access — they can see your OTP and steal money",
        "No bank, police or government office needs remote access to your phone",
        "If you already installed such an app — uninstall it immediately and change all passwords",
    ],
    "Lottery / Prize Fraud": [
        "You cannot win a lottery you never entered — it is always fake",
        "Any prize that requires you to pay fees first is a scam",
        "Real lotteries are notified via official government gazette — not SMS or WhatsApp",
        "Ignore all 'you have won' messages and delete them",
    ],
    "Loan App Fraud": [
        "Only use RBI-registered lending apps — check list at rbi.org.in",
        "Illegal loan apps charge 100-500% interest and harass contacts if you default",
        "Never give permission to access contacts/photos when applying for loan",
        "Report illegal loan apps to cybercrime.gov.in and RBI",
    ],
    "QR Code / UPI Overpayment Scam": [
        "Scanning a QR code ALWAYS sends money from you — never to you",
        "Anyone claiming to send you money via QR is lying — it is a scam",
        "If selling online, demand bank transfer — never scan QR from buyers",
        "OLX and other marketplace scams often use this trick on sellers",
    ],
    "Romantic / Honey-trap Scam": [
        "Be cautious of unknown people who become very friendly very quickly online",
        "Never send money to someone you have only met online",
        "Scammers create fake profiles with stolen photos — verify identity",
        "Military/army romance scams are extremely common — verify independently",
    ],
    "General Safety Tips": [
        "Save 1930 (Cyber Crime Helpline) in your phone right now",
        "Bookmark cybercrime.gov.in for reporting scams",
        "Tell elderly family members about common scam tricks regularly",
        "Never decide immediately — scammers want you to act fast before thinking",
        "When in doubt — ask a trusted family member or friend first",
        "No legitimate person will threaten you with arrest over phone — ever",
    ]
}

# ==============================================================================
# 5. HARDCODED SCAM NEWS DATABASE (Feature 13)
# Updated regularly — also supplemented by live scraping
# ==============================================================================

HARDCODED_NEWS = [
    {
        "id": "HN001",
        "title": "Digital Arrest Scam Surges — Fake CBI Officers Targeting Professionals",
        "summary": "Scammers posing as CBI/ED officers are calling people on video call, claiming they are under 'digital arrest' for money laundering. They demand lakhs in 'bail money'. This scam has caused losses of over ₹600 crore in 2024.",
        "category": "Digital Arrest Scam",
        "severity": "CRITICAL",
        "date": "2025-11-15",
        "source": "cybercrime.gov.in",
        "tips": PREVENTION_TIPS["Digital Arrest Scam"],
        "helpline": "1930",
        "tags": ["cbi", "ed", "digital arrest", "video call", "bail money"]
    },
    {
        "id": "HN002",
        "title": "Part-Time Job Scam on Telegram — Earn Per Like/Task Fraud",
        "summary": "Fraudsters advertise part-time jobs paying ₹500-2000 per task on Telegram and WhatsApp. After initial small payments to build trust, victims are asked to 'invest' for bigger tasks. Money is never returned.",
        "category": "Part Time Job / Task Scam",
        "severity": "HIGH",
        "date": "2025-11-10",
        "source": "cybercrime.gov.in",
        "tips": PREVENTION_TIPS["Job / Employment Scam"],
        "helpline": "1930",
        "tags": ["telegram", "part time", "task", "like", "earn from home"]
    },
    {
        "id": "HN003",
        "title": "TRAI Number Blocking Scam — Do Not Fall For It",
        "summary": "Fake TRAI officers are calling people claiming their mobile number will be blocked in 2 hours due to 'illegal activity'. They then connect the call to a fake 'cybercrime officer' who demands money. TRAI never makes such calls.",
        "category": "TRAI / Number Blocking Scam",
        "severity": "HIGH",
        "date": "2025-11-08",
        "source": "trai.gov.in",
        "tips": PREVENTION_TIPS["TRAI / Number Blocking Scam"],
        "helpline": "1930",
        "tags": ["trai", "number block", "sim block", "2 hours", "cybercrime officer"]
    },
    {
        "id": "HN004",
        "title": "FedEx/DHL Customs Scam — Parcel With Drugs or Cash Story",
        "summary": "Callers claiming to be from FedEx, DHL or Customs Department tell victims a parcel in their name contains drugs or counterfeit cash. They threaten arrest unless 'customs duty' is paid immediately via UPI.",
        "category": "Delivery / Customs Parcel Scam",
        "severity": "HIGH",
        "date": "2025-11-05",
        "source": "cybercrime.gov.in",
        "tips": PREVENTION_TIPS["Delivery / Customs Parcel Scam"],
        "helpline": "1930",
        "tags": ["fedex", "dhl", "customs", "parcel", "narcotics", "drugs"]
    },
    {
        "id": "HN005",
        "title": "Hi Dad / Hi Mum Scam — Family Impersonation via Unknown Number",
        "summary": "Scammers message people saying 'Hi beta/son, my phone broke, using friend's number, please send money for groceries/emergency'. This emotional scam tricks people using love and trust instead of fear.",
        "category": "Family Impersonation / Hi Dad Scam",
        "severity": "HIGH",
        "date": "2025-11-01",
        "source": "cybercrime.gov.in",
        "tips": PREVENTION_TIPS["Family Impersonation / Hi Dad Scam"],
        "helpline": "1930",
        "tags": ["hi son", "hi beta", "phone broke", "unknown number", "family", "emergency"]
    },
    {
        "id": "HN006",
        "title": "Pig Butchering Scam — Fake Crypto Investment Through Romance",
        "summary": "Scammers spend weeks or months befriending victims on dating apps or WhatsApp, building emotional trust. They then introduce a 'guaranteed profit' crypto trading platform. Victims invest lakhs before realizing it is fake.",
        "category": "Investment / Ponzi Scheme",
        "severity": "CRITICAL",
        "date": "2025-10-28",
        "source": "sebi.gov.in",
        "tips": PREVENTION_TIPS["Investment / Ponzi Scheme"],
        "helpline": "1930",
        "tags": ["crypto", "investment", "dating app", "guaranteed profit", "trading platform"]
    },
    {
        "id": "HN007",
        "title": "OTP Fraud — SBI/HDFC Impersonation Calls Increasing",
        "summary": "Fraudsters are calling people posing as SBI and HDFC bank executives, claiming the victim's account is about to be blocked. They convince the victim to share OTP for 'account reactivation'. This results in complete account emptying.",
        "category": "Banking / OTP Fraud",
        "severity": "CRITICAL",
        "date": "2025-10-25",
        "source": "rbi.org.in",
        "tips": PREVENTION_TIPS["Banking / OTP Fraud"],
        "helpline": "1800112211",
        "tags": ["sbi", "hdfc", "otp", "account blocked", "bank executive", "reactivation"]
    },
    {
        "id": "HN008",
        "title": "Fake Loan App Scam — Illegal Apps Harassing Borrowers",
        "summary": "Hundreds of illegal loan apps not registered with RBI are offering instant loans. They access contacts, photos and messages. When victims cannot repay the high interest, scammers send morphed images to contacts threatening exposure.",
        "category": "Loan App Fraud",
        "severity": "HIGH",
        "date": "2025-10-20",
        "source": "rbi.org.in",
        "tips": PREVENTION_TIPS["Loan App Fraud"],
        "helpline": "14440",
        "tags": ["loan app", "instant loan", "harassment", "morphed photo", "contacts"]
    },
    {
        "id": "HN009",
        "title": "QR Code Scam — Buyers Tricking OLX and Facebook Marketplace Sellers",
        "summary": "Scammers posing as buyers on OLX and Facebook Marketplace send QR codes to sellers claiming it will send payment. Scanning the QR code actually deducts money from the seller's account.",
        "category": "QR Code / UPI Scam",
        "severity": "HIGH",
        "date": "2025-10-15",
        "source": "cybercrime.gov.in",
        "tips": PREVENTION_TIPS["QR Code / UPI Overpayment Scam"],
        "helpline": "1930",
        "tags": ["qr code", "olx", "facebook", "seller", "marketplace", "scan"]
    },
    {
        "id": "HN010",
        "title": "Screen Share Scam — AnyDesk Fraud Targeting Senior Citizens",
        "summary": "Fraudsters calling as bank/Microsoft/insurance support ask elderly victims to install AnyDesk or QuickSupport for 'remote assistance'. Once access is granted, they transfer all funds from the bank account.",
        "category": "Screen Share / Remote Access Scam",
        "severity": "CRITICAL",
        "date": "2025-10-10",
        "source": "cybercrime.gov.in",
        "tips": PREVENTION_TIPS["Screen Share / Remote Access Scam"],
        "helpline": "1930",
        "tags": ["anydesk", "screen share", "remote access", "senior", "microsoft", "insurance"]
    },
    {
        "id": "HN011",
        "title": "KYC Fraud — Aadhaar Update Scam Via SMS Links",
        "summary": "Victims receive SMS claiming their bank KYC has expired with a link to update. The fake website collects Aadhaar, PAN, card details and OTP. Victims lose money within minutes of entering details.",
        "category": "KYC / Aadhaar Verification Scam",
        "severity": "HIGH",
        "date": "2025-10-05",
        "source": "uidai.gov.in",
        "tips": PREVENTION_TIPS["KYC / Aadhaar Verification Scam"],
        "helpline": "1947",
        "tags": ["kyc", "aadhaar", "sms link", "fake website", "pan", "expired"]
    },
    {
        "id": "HN012",
        "title": "Lottery Fraud — Fake KBC and Government Prize SMS",
        "summary": "People are receiving SMS claiming they won KBC lottery or a government prize of ₹25 lakh. To claim the prize, they are asked to pay 'processing fees' ranging from ₹5,000 to ₹50,000. No prize ever arrives.",
        "category": "Lottery / Prize Fraud",
        "severity": "MODERATE",
        "date": "2025-09-28",
        "source": "cybercrime.gov.in",
        "tips": PREVENTION_TIPS["Lottery / Prize Fraud"],
        "helpline": "1930",
        "tags": ["kbc", "lottery", "prize", "25 lakh", "processing fee", "sms"]
    },
    {
        "id": "HN013",
        "title": "Investment Scam — Fake SEBI-Registered Trading Groups on WhatsApp",
        "summary": "Scammers create WhatsApp groups claiming to be SEBI-registered advisors giving 'sure shot' stock tips. Early investors see small profits (planted by scammers). When larger amounts are invested, the group disappears.",
        "category": "Investment / Ponzi Scheme",
        "severity": "CRITICAL",
        "date": "2025-09-20",
        "source": "sebi.gov.in",
        "tips": PREVENTION_TIPS["Investment / Ponzi Scheme"],
        "helpline": "18002667575",
        "tags": ["sebi", "trading group", "whatsapp", "stock tips", "sure shot", "investment"]
    },
    {
        "id": "HN014",
        "title": "Romance Scam — Fake Army Officers Targeting Women on Facebook",
        "summary": "Fraudsters create fake Facebook profiles of Indian Army or UN peacekeeping soldiers. After months of emotional relationship building, they request money for emergency medical treatment, customs fees for gifts, or travel costs to meet.",
        "category": "Romantic / Honey-trap Scam",
        "severity": "HIGH",
        "date": "2025-09-15",
        "source": "cybercrime.gov.in",
        "tips": PREVENTION_TIPS["Romantic / Honey-trap Scam"],
        "helpline": "1930",
        "tags": ["army", "soldier", "facebook", "romance", "gift", "medical emergency"]
    },
    {
        "id": "HN015",
        "title": "Electricity Bill Disconnection Scam — Urgent SMS Trick",
        "summary": "Victims receive SMS claiming their electricity connection will be cut in 2 hours for non-payment. A number is given to contact. The 'electricity officer' then asks for UPI payment to avoid disconnection.",
        "category": "Electricity / Utility Scam",
        "severity": "HIGH",
        "date": "2025-09-10",
        "source": "cybercrime.gov.in",
        "tips": ["Your electricity company always sends official notices — not SMS with phone numbers",
                 "Call your official electricity provider number from their website",
                 "Never pay electricity bills to a personal UPI number",
                 "Visit the electricity office in person if in doubt"],
        "helpline": "1930",
        "tags": ["electricity", "bill", "disconnect", "upi", "2 hours", "utility"]
    },
    {
        "id": "HN016",
        "title": "Phishing Site Alert — Fake SBI and HDFC Login Pages",
        "summary": "Multiple fake banking websites mimicking SBI (sbi-netbanking.xyz, sbi-update.in) and HDFC (hdfcbank-kyc.com) have been reported. These sites steal login credentials and OTP to drain accounts.",
        "category": "Phishing / Credential Harvesting",
        "severity": "CRITICAL",
        "date": "2025-09-05",
        "source": "cert-in.org.in",
        "tips": PREVENTION_TIPS["Phishing / Credential Harvesting"],
        "helpline": "1930",
        "tags": ["phishing", "fake website", "sbi", "hdfc", "login", "credentials"]
    },
    {
        "id": "HN017",
        "title": "Social Media Impersonation — Fake Customer Care on Twitter/X",
        "summary": "When customers tweet complaints to banks or companies, fake accounts reply first with a helpline number. Calling this number connects to scammers who ask for OTP and account details under the guise of resolving the complaint.",
        "category": "Social Media Impersonation",
        "severity": "HIGH",
        "date": "2025-08-30",
        "source": "cybercrime.gov.in",
        "tips": ["Never call numbers given by accounts replying to your public tweets/posts",
                 "Always find customer care numbers from the official company website",
                 "Check follower count and verified badge before trusting social media accounts",
                 "Banks never resolve issues over Twitter DM — visit branch or official app"],
        "helpline": "1930",
        "tags": ["twitter", "social media", "fake customer care", "complaint", "impersonation"]
    },
    {
        "id": "HN018",
        "title": "New Pattern — AI Voice Clone Scam Emerging in India",
        "summary": "Scammers are now using AI to clone the voice of a family member using even a 10-second voice sample from social media. They call relatives claiming emergency and demanding urgent money transfer. Verify by asking a question only the real person knows.",
        "category": "Family Impersonation / Hi Dad Scam",
        "severity": "CRITICAL",
        "date": "2025-11-18",
        "source": "cert-in.org.in",
        "tips": [
            "AI can now clone any voice from a 10-second sample — do not trust voice alone",
            "Always establish a family code word for emergencies that only real family knows",
            "Call back on the person's original saved number — not the number that called you",
            "Ask a deeply personal question only they would know",
            "Report AI voice scam attempts to cybercrime.gov.in immediately"
        ],
        "helpline": "1930",
        "tags": ["ai voice", "voice clone", "deepfake", "family emergency", "new pattern"]
    },
]

# ==============================================================================
# 6. SCAM TAXONOMY & BEHAVIOUR PATTERNS
# ==============================================================================

SCAM_TAXONOMY = [
    "Banking / OTP Fraud","Job / Employment Scam","KYC / Aadhaar Scam",
    "Lottery / Prize Fraud","Investment / Ponzi Scheme","Tech Support Scam",
    "Romantic / Honey-trap Scam","Government Impersonation",
    "Delivery / Customs Parcel Scam","Cryptocurrency Fraud",
    "Phishing / Credential Theft","Social Media Impersonation",
    "Loan App Fraud","Insurance Scam","TRAI / Number Blocking Scam",
    "Electricity / Utility Scam","Digital Arrest Scam",
    "Screen Share / Remote Access Scam","Fake Police / CBI / ED Scam",
    "Part Time Job / Task Scam","QR Code / UPI Scam",
    "Pig Butchering / Investment Scam","Family Impersonation / Hi Dad Scam",
    "Fake Emergency / Stranded Scam","NEW Unknown Pattern — Suspicious Behaviour"
]

BEHAVIOUR_PATTERNS = {
    "creates_fear": [
        'you will be arrested','you are arrested','will go to jail','case against you',
        'fir has been','case has been registered','legal action will','legal notice',
        'court summons','your account is blocked','account suspended','account disconnected',
        'account cancelled','account deactivated','penalty of rs','you will be fined',
        'illegal activity detected','cybercrime complaint','enforcement directorate',
        'central bureau','income tax raid','digital arrest','do not leave home',
        'trai will disconnect','sim will be blocked','number will be blocked',
        'blacklisted','account seized','narcotics found','drug trafficking',
        'money laundering case','your number will be','your account will be'
    ],
    "creates_urgency": [
        'immediately','right now','within 2 hours','within 24 hours',
        'today only','expires','last chance','act now','urgent','emergency',
        'asap','do not delay','final warning','last notice','deadline',
        'limited time','hurry','quickly','abhi karo','turant','jaldi karo'
    ],
    "promises_money": [
        'won','winner','prize','lottery','reward','cashback','refund','bonus',
        'free money','earn daily','earn from home','part time','work from home',
        'per day','per task','commission','profit','guaranteed return',
        'double your money','investment return','easy money','passive income',
        'ghar baithe kamao','daily income','weekly payout',
        'will double','it will double','doublr','doubler','doubles in',
        'double in','triple in','x2 in','x3 in','2x in','3x in',
        '120 in 12','100 in 24','500 in','1000 in','deposit and get',
        'deposit 50','deposit 100','deposit 200','invest 50','invest 100',
        'minimum deposit','send deposit','profit in minutes','profit in hours',
        'returns in minutes','returns guaranteed','instant profit',
        'double kar','paisa double','paise double','invest karo paisa'
    ],
    "asks_for_secrets": [
        'otp','pin','password','cvv','card number','account number',
        'aadhaar','pan card','date of birth','mother name',
        'share screen','anydesk','teamviewer','remote access',
        'install app','click link','scan qr','send screenshot',
        'verify your account','update kyc','re-kyc','full name and address'
    ],
    "impersonates_authority": [
        'rbi officer','sebi official','trai officer','uidai official','npci helpline',
        'government of india','prime minister office','ministry of','supreme court notice',
        'high court notice','cyber police','cbi officer','enforcement directorate',
        'income tax officer','income tax department','customs officer','customs department',
        'fedex helpline','dhl helpline','amazon helpline','amazon support',
        'flipkart helpline','sbi official','sbi customer care','hdfc customer care',
        'icici customer care','axis bank helpline','paytm support','google pay support',
        'phonepe support','microsoft support','apple support','lic agent','lic officer',
        'pm office','collector office','cyber cell','interpol','narcotics bureau',
        'reserve bank of india','central bureau of investigation'
    ],
    "isolates_victim": [
        'do not tell anyone','keep this confidential','do not share',
        'secret','between us','do not inform family','private matter',
        'do not contact bank','do not go to police','trust me',
        'only i can help you','do not discuss','kisi ko mat batao',
        'ghar mein mat batana','chup raho','family ko mat batana'
    ],
    "requests_payment": [
        'transfer money','send money','pay now','deposit','upi',
        'google pay','phonepe','paytm','neft','rtgs','bitcoin',
        'crypto','gift card','voucher','recharge','fees','charge',
        'processing fee','registration fee','security deposit',
        'advance payment','send rs','send inr','paisa bhejo',
        'paise transfer karo','account mein dalo','wire transfer'
    ]
}
BEHAVIOUR_WEIGHTS = {
    "creates_fear":22,"creates_urgency":18,"promises_money":30,
    "asks_for_secrets":25,"impersonates_authority":20,
    "isolates_victim":28,"requests_payment":30
}

EMOTIONAL_PATTERNS = {
    "claims_to_be_family": [
        'i am your father','i am your mother','i am your son',
        'i am your daughter','i am your brother','i am your sister',
        'this is dad','this is mom','this is papa','this is mummy',
        'its me dad','its me mom','hi son','hi beta','hi bete',
        'hi daughter','hi beti','your father here','papa here',
        'mummy here','main tera baap','main tumhara papa',
        'bhai bol raha hoon','didi bol rahi hoon','tera bhai'
    ],
    "claims_emergency": [
        'phone switched off','phone dead','lost my phone','new number',
        'phone chori','phone kho gaya','battery dead','phone broke',
        'using friend phone','borrowed phone','dont have my phone',
        'my number changed','new sim','temporarily using',
        'accident','hospital','emergency','stuck','stranded',
        'wallet lost','no cash','need help urgently','durghatna'
    ],
    "unknown_sender_payment": [
        'send money','do payment','transfer karo','paisa bhejo',
        'upi karo','google pay karo','phonepe karo','qr code',
        'scan karo','i will pay back','return kar dunga',
        'wapas de dunga','just this once','please help',
        'no one else to ask','you are the only one','abhi chahiye'
    ],
    "creates_sympathy": [
        'please help me','i need you','please beta','please son',
        'please daughter','only you can help','i am in trouble',
        'mujhe madad chahiye','please trust me','i can explain later',
        'dont ask questions now','just send','bahut zaruri hai'
    ]
}
EMOTIONAL_WEIGHTS = {
    "claims_to_be_family":35,"claims_emergency":20,
    "unknown_sender_payment":30,"creates_sympathy":25
}

MUTATION_TEMPLATES = [
    {"name":"KYC Verification Scam",     "must_have":["verify","account","update"],    "boost":25},
    {"name":"Number Blocking Scam",       "must_have":["block","number","hours"],       "boost":30},
    {"name":"Parcel Customs Scam",        "must_have":["parcel","customs","pay"],       "boost":35},
    {"name":"Digital Arrest Scam",        "must_have":["arrest","home","police"],       "boost":40},
    {"name":"Part-time Job Scam",         "must_have":["task","earn","daily"],          "boost":30},
    {"name":"Investment Return Scam",     "must_have":["invest","return","guaranteed"], "boost":35},
    {"name":"OTP Harvesting",             "must_have":["otp","share","verify"],         "boost":45},
    {"name":"Screen Share Scam",          "must_have":["screen","share","install"],     "boost":40},
    {"name":"Electricity Bill Scam",      "must_have":["electricity","bill","disconnect"],"boost":35},
    {"name":"Insurance Premium Scam",     "must_have":["insurance","premium","expire"], "boost":30},
    {"name":"Loan Approval Scam",         "must_have":["loan","approved","fee"],        "boost":35},
    {"name":"Fake Job Offer",             "must_have":["job","selected","registration"],"boost":30},
    {"name":"AI Voice Clone Emergency",   "must_have":["voice","emergency","transfer"], "boost":40},
    {"name":"Money Doubling Scam",        "must_have":["deposit","double","bonus"],     "boost":55},
    {"name":"Money Doubling Scam",        "must_have":["invest","double","minutes"],    "boost":55},
    {"name":"Money Doubling Scam",        "must_have":["deposit","bonus","minutes"],    "boost":55},
    {"name":"Fast Profit Scam",           "must_have":["deposit","profit","hours"],     "boost":50},
    {"name":"Pyramid Investment Scam",    "must_have":["invest","return","percent"],    "boost":45},
]

# ==============================================================================
# 7. DATABASE
# ==============================================================================

class SentinelDB:
    def _conn(self):
        c = sqlite3.connect(DB_PATH, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def __init__(self):
        conn = self._conn(); cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS scan_logs(
            scan_id TEXT PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            content_hash TEXT, risk_score INTEGER, confidence INTEGER,
            risk_level TEXT, output_mode TEXT, scam_type TEXT,
            summary TEXT, full_report TEXT, action_plan TEXT,
            metadata_json TEXT, input_preview TEXT)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS community_patterns(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT, verdict TEXT, pattern_hash TEXT UNIQUE,
            keywords TEXT, match_count INTEGER DEFAULT 1,
            confirmed_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS learned_patterns(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT, pattern TEXT, keywords TEXT,
            severity INTEGER DEFAULT 50,
            learned_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS mismatch_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT, institution TEXT, fake_value TEXT,
            real_values TEXT, mismatch_type TEXT,
            detected_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        # News board table — stores scraped + hardcoded news
        cur.execute('''CREATE TABLE IF NOT EXISTS news_board(
            id TEXT PRIMARY KEY,
            title TEXT, summary TEXT, category TEXT,
            severity TEXT, date TEXT, source TEXT,
            tips TEXT, helpline TEXT, tags TEXT,
            is_live INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        # Notification queue
        cur.execute('''CREATE TABLE IF NOT EXISTS notifications(
            id TEXT PRIMARY KEY,
            title TEXT, message TEXT, type TEXT,
            category TEXT, severity TEXT,
            read INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        conn.commit(); conn.close()
        logger.info("Database ready.")
        self._seed_news()

    def _seed_news(self):
        """Insert hardcoded news into DB if not already there."""
        conn = self._conn(); cur = conn.cursor()
        for item in HARDCODED_NEWS:
            cur.execute("INSERT OR IGNORE INTO news_board(id,title,summary,category,severity,date,source,tips,helpline,tags,is_live) VALUES(?,?,?,?,?,?,?,?,?,?,0)",
                (item["id"],item["title"],item["summary"],item["category"],
                 item["severity"],item["date"],item["source"],
                 json.dumps(item["tips"]),item["helpline"],
                 json.dumps(item["tags"])))
        conn.commit(); conn.close()

    def log_scan(self, scan_id, risk, conf, level, mode, stype,
                 summary, report, actions, raw, meta):
        try:
            conn = self._conn(); cur = conn.cursor()
            h = hashlib.sha256(raw.encode()).hexdigest()
            cur.execute('''INSERT OR REPLACE INTO scan_logs
                (scan_id,content_hash,risk_score,confidence,risk_level,output_mode,
                 scam_type,summary,full_report,action_plan,metadata_json,input_preview)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
                (scan_id,h,risk,conf,level,mode,stype,summary,report,
                 json.dumps(actions),json.dumps(meta),raw[:120]))
            conn.commit(); conn.close()
        except Exception as e: logger.error(f"DB write: {e}")

    def confirm_scam(self, scan_id, verdict, keywords):
        try:
            conn = self._conn(); cur = conn.cursor()
            ph = hashlib.md5(json.dumps(sorted(keywords)).encode()).hexdigest()
            cur.execute('''INSERT INTO community_patterns(scan_id,verdict,pattern_hash,keywords)
                VALUES(?,?,?,?) ON CONFLICT(pattern_hash)
                DO UPDATE SET match_count=match_count+1''',
                (scan_id,verdict,ph,json.dumps(keywords)))
            conn.commit(); conn.close()
        except Exception as e: logger.error(f"Confirm: {e}")

    def community_boost(self, text: str) -> int:
        conn = self._conn(); cur = conn.cursor()
        cur.execute("SELECT keywords,match_count FROM community_patterns WHERE verdict='scam' ORDER BY match_count DESC LIMIT 100")
        rows = cur.fetchall(); conn.close()
        tl = text.lower(); boost = 0
        for r in rows:
            try:
                kws = json.loads(r["keywords"])
                if kws and all(k.lower() in tl for k in kws):
                    boost += 20 * min(r["match_count"], 3)
            except: pass
        return min(boost, 40)

    def save_learned(self, source, pattern, keywords, severity):
        try:
            conn = self._conn(); cur = conn.cursor()
            cur.execute("INSERT INTO learned_patterns(source,pattern,keywords,severity) VALUES(?,?,?,?)",
                (source,pattern,keywords,severity))
            conn.commit(); conn.close()
        except Exception as e: logger.error(f"Learn: {e}")

    def get_learned(self):
        conn = self._conn(); cur = conn.cursor()
        cur.execute("SELECT pattern,keywords,severity FROM learned_patterns ORDER BY learned_at DESC LIMIT 200")
        rows = [dict(r) for r in cur.fetchall()]; conn.close(); return rows

    def log_mismatch(self, scan_id, inst, fake, real, mtype):
        try:
            conn = self._conn(); cur = conn.cursor()
            cur.execute("INSERT INTO mismatch_log(scan_id,institution,fake_value,real_values,mismatch_type) VALUES(?,?,?,?,?)",
                (scan_id,inst,fake,json.dumps(real),mtype))
            conn.commit(); conn.close()
        except Exception as e: logger.error(f"Mismatch log: {e}")

    def history(self, limit=20, offset=0):
        conn = self._conn(); cur = conn.cursor()
        cur.execute("SELECT * FROM scan_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?", (limit,offset))
        rows = [dict(r) for r in cur.fetchall()]; conn.close(); return rows

    def get_scan(self, scan_id):
        conn = self._conn(); cur = conn.cursor()
        cur.execute("SELECT * FROM scan_logs WHERE scan_id=?", (scan_id,))
        r = cur.fetchone(); conn.close(); return dict(r) if r else None

    def delete(self, scan_id):
        conn = self._conn(); cur = conn.cursor()
        cur.execute("DELETE FROM scan_logs WHERE scan_id=?", (scan_id,))
        aff = cur.rowcount; conn.commit(); conn.close(); return aff > 0

    def stats(self):
        conn = self._conn(); cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as t FROM scan_logs"); total = cur.fetchone()['t']
        cur.execute("SELECT COUNT(*) as h FROM scan_logs WHERE risk_level IN('HIGH','CRITICAL')"); high = cur.fetchone()['h']
        cur.execute("SELECT AVG(risk_score) as a FROM scan_logs"); avg = round(cur.fetchone()['a'] or 0,1)
        cur.execute("SELECT scam_type,COUNT(*) as c FROM scan_logs GROUP BY scam_type ORDER BY c DESC LIMIT 5"); top=[dict(r) for r in cur.fetchall()]
        cur.execute("SELECT COUNT(*) as cp FROM community_patterns WHERE verdict='scam'"); cp=cur.fetchone()['cp']
        cur.execute("SELECT COUNT(*) as lp FROM learned_patterns"); lp=cur.fetchone()['lp']
        cur.execute("SELECT COUNT(*) as nn FROM news_board"); nn=cur.fetchone()['nn']
        conn.close()
        return {"total_scans":total,"high_risk":high,"avg_risk":avg,"top_types":top,
                "community_patterns":cp,"learned_patterns":lp,"news_count":nn}

    # ── News Board Methods (Feature 13) ───────────────────────────────────────
    def get_news(self, limit=20, offset=0, category=None, severity=None) -> List[Dict]:
        conn = self._conn(); cur = conn.cursor()
        q = "SELECT * FROM news_board"
        params = []
        filters = []
        if category: filters.append("category=?"); params.append(category)
        if severity: filters.append("severity=?"); params.append(severity)
        if filters: q += " WHERE " + " AND ".join(filters)
        q += " ORDER BY date DESC, created_at DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        cur.execute(q, params)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        # Parse JSON fields
        for r in rows:
            try: r["tips"] = json.loads(r["tips"])
            except: r["tips"] = []
            try: r["tags"] = json.loads(r["tags"])
            except: r["tags"] = []
        return rows

    def save_news(self, item: Dict):
        try:
            conn = self._conn(); cur = conn.cursor()
            cur.execute('''INSERT OR REPLACE INTO news_board
                (id,title,summary,category,severity,date,source,tips,helpline,tags,is_live)
                VALUES(?,?,?,?,?,?,?,?,?,?,1)''',
                (item["id"],item["title"],item["summary"],item["category"],
                 item["severity"],item["date"],item["source"],
                 json.dumps(item.get("tips",[])),
                 item.get("helpline","1930"),
                 json.dumps(item.get("tags",[]))))
            conn.commit(); conn.close()
        except Exception as e: logger.error(f"Save news: {e}")

    def get_news_by_id(self, news_id: str) -> Optional[Dict]:
        conn = self._conn(); cur = conn.cursor()
        cur.execute("SELECT * FROM news_board WHERE id=?", (news_id,))
        r = cur.fetchone(); conn.close()
        if not r: return None
        row = dict(r)
        try: row["tips"] = json.loads(row["tips"])
        except: row["tips"] = []
        try: row["tags"] = json.loads(row["tags"])
        except: row["tags"] = []
        return row

    # ── Notification Methods (Feature 14) ─────────────────────────────────────
    def add_notification(self, title: str, message: str, ntype: str,
                         category: str = "", severity: str = "INFO"):
        try:
            conn = self._conn(); cur = conn.cursor()
            nid = f"NT-{uuid.uuid4().hex[:8].upper()}"
            cur.execute('''INSERT INTO notifications(id,title,message,type,category,severity)
                VALUES(?,?,?,?,?,?)''', (nid,title,message,ntype,category,severity))
            conn.commit(); conn.close()
            return nid
        except Exception as e: logger.error(f"Add notif: {e}"); return None

    def get_notifications(self, unread_only=False) -> List[Dict]:
        conn = self._conn(); cur = conn.cursor()
        if unread_only:
            cur.execute("SELECT * FROM notifications WHERE read=0 ORDER BY created_at DESC LIMIT 50")
        else:
            cur.execute("SELECT * FROM notifications ORDER BY created_at DESC LIMIT 100")
        rows = [dict(r) for r in cur.fetchall()]; conn.close(); return rows

    def mark_read(self, notif_id: str = None):
        conn = self._conn(); cur = conn.cursor()
        if notif_id:
            cur.execute("UPDATE notifications SET read=1 WHERE id=?", (notif_id,))
        else:
            cur.execute("UPDATE notifications SET read=1")
        conn.commit(); conn.close()

    def unread_count(self) -> int:
        conn = self._conn(); cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as c FROM notifications WHERE read=0")
        c = cur.fetchone()['c']; conn.close(); return c

db = SentinelDB()

# ==============================================================================
# 8. WEBSOCKET CONNECTION MANAGER (Feature 14 — Real-time notifications)
# ==============================================================================

class ConnectionManager:
    """Manages WebSocket connections for real-time push notifications."""
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        logger.info(f"[WS] Client connected. Total: {len(self.active)}")

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)
        logger.info(f"[WS] Client disconnected. Total: {len(self.active)}")

    async def broadcast(self, data: Dict):
        """Send notification to all connected clients."""
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    async def send_notification(self, title: str, message: str,
                                 ntype: str = "info", category: str = "",
                                 severity: str = "INFO"):
        """Save to DB and broadcast to all WebSocket clients."""
        nid = db.add_notification(title, message, ntype, category, severity)
        await self.broadcast({
            "event": "notification",
            "id": nid,
            "title": title,
            "message": message,
            "type": ntype,
            "category": category,
            "severity": severity,
            "timestamp": datetime.now().isoformat()
        })

ws_manager = ConnectionManager()

# ==============================================================================
# 9. LIVE NEWS SCRAPER (Feature 9 + 13)
# ==============================================================================

class NewsIntelligence:
    """
    Scrapes cybercrime.gov.in, RBI, CERT-IN, PIB every 6 hours.
    Saves new articles to news_board table.
    Sends real-time notification when new scam pattern is found.
    """
    last_run: datetime = None

    SOURCES = [
        {"url": "https://cybercrime.gov.in",              "name": "Cyber Crime Portal"},
        {"url": "https://www.rbi.org.in/scripts/Notifications.aspx", "name": "RBI Alerts"},
        {"url": "https://www.cert-in.org.in",             "name": "CERT-IN"},
        {"url": "https://pib.gov.in",                     "name": "PIB"},
    ]

    SCAM_KEYWORDS = [
        'fraud','scam','cyber crime','phishing','fake','impersonation',
        'arrest','otp','upi','warning','alert','cheating','victim',
        'helpline','advisory','caution','beware','complaint'
    ]

    @staticmethod
    async def run_if_due():
        now = datetime.now()
        if (NewsIntelligence.last_run and
                now - NewsIntelligence.last_run < timedelta(hours=6)):
            return
        NewsIntelligence.last_run = now
        logger.info("[NEWS] Starting auto news fetch...")
        await asyncio.to_thread(NewsIntelligence._fetch_all)

    @staticmethod
    def _fetch_all():
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            logger.warning("[NEWS] Install beautifulsoup4: pip install beautifulsoup4")
            return

        new_count = 0
        for src in NewsIntelligence.SOURCES:
            try:
                r = requests.get(src["url"], timeout=12,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
                if r.status_code != 200:
                    continue

                from bs4 import BeautifulSoup
                soup = BeautifulSoup(r.text, 'html.parser')

                # Extract meaningful text blocks
                blocks = []
                for tag in soup.find_all(['h1','h2','h3','h4','p','li','a']):
                    text = tag.get_text(strip=True)
                    if len(text) > 40:
                        blocks.append(text)

                for block in blocks[:60]:
                    tl = block.lower()
                    if not any(kw in tl for kw in NewsIntelligence.SCAM_KEYWORDS):
                        continue

                    # Determine severity
                    severity = "MODERATE"
                    if any(w in tl for w in ['critical','urgent','immediate','alert','warning']):
                        severity = "HIGH"
                    if any(w in tl for w in ['crore','lakh','arrest','digital arrest']):
                        severity = "CRITICAL"

                    # Determine category
                    category = "General Cyber Safety"
                    for cat_key, cat_name in [
                        (['otp','bank','account'],"Banking / OTP Fraud"),
                        (['digital arrest','cbi','ed '],"Digital Arrest Scam"),
                        (['investment','crypto','trading'],"Investment / Ponzi Scheme"),
                        (['trai','sim','number block'],"TRAI / Number Blocking Scam"),
                        (['parcel','customs','fedex','dhl'],"Delivery / Customs Parcel Scam"),
                        (['kyc','aadhaar','uidai'],"KYC / Aadhaar Scam"),
                        (['loan','app','lending'],"Loan App Fraud"),
                        (['qr','upi','payment'],"QR Code / UPI Scam"),
                        (['screen share','anydesk','remote'],"Screen Share / Remote Access Scam"),
                        (['job','task','earn','work from home'],"Part Time Job / Task Scam"),
                    ]:
                        if any(k in tl for k in cat_key):
                            category = cat_name; break

                    # Extract keywords for learned patterns
                    words = [w for w in re.findall(r'\b\w{5,}\b', tl)
                             if w not in {'these','those','their','there','where',
                                          'which','being','would','could','about',
                                          'have','from','they','with','this','that'}]

                    if len(words) >= 3:
                        db.save_learned(src["url"], block[:200],
                                        json.dumps(words[:5]), 60)

                    # Save as news item
                    news_id = f"LN-{hashlib.md5(block.encode()).hexdigest()[:8].upper()}"
                    news_item = {
                        "id": news_id,
                        "title": block[:100] + ("..." if len(block) > 100 else ""),
                        "summary": block[:400],
                        "category": category,
                        "severity": severity,
                        "date": datetime.now().strftime("%Y-%m-%d"),
                        "source": src["name"],
                        "tips": PREVENTION_TIPS.get(category, PREVENTION_TIPS["General Safety Tips"]),
                        "helpline": "1930",
                        "tags": words[:5]
                    }
                    db.save_news(news_item)
                    new_count += 1

                logger.info(f"[NEWS] Processed {src['url']} — {new_count} items saved")
            except Exception as e:
                logger.warning(f"[NEWS] Failed {src['url']}: {e}")

        if new_count > 0:
            logger.info(f"[NEWS] Total new items: {new_count}")

# ==============================================================================
# 10. MISMATCH DETECTOR
# ==============================================================================

class MismatchDetector:
    @staticmethod
    def extract(text):
        phones  = list(set(re.sub(r'\D','',p) for p in re.findall(r'(?:\+91[\s\-]?)?[6-9]\d{9}|\b1[89]00[\d\s\-]{6,12}', text)))
        domains = list(set(d.lower() for d in re.findall(r'(?:https?://)?(?:www\.)?([a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)', text)))
        emails  = list(set(e.lower() for e in re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', text)))
        return {"phones":phones, "domains":domains, "emails":emails}

    @staticmethod
    def check(text):
        tl = text.lower()
        ex = MismatchDetector.extract(text)
        findings=[]; score_boost=0; mismatches=[]

        for key, data in OFFICIAL_DB.items():
            name  = data["full_name"].lower()
            short = key.lower()
            if name not in tl and short not in tl: continue

            note = data.get("note","")
            real_phones = [re.sub(r'\D','',p) for p in data["phones"]]

            for ph in ex["phones"]:
                if ph not in real_phones and ph not in OFFICIAL_PHONES:
                    findings.append({"type":"FAKE PHONE","institution":data["full_name"],
                        "fake_value":ph,"real_values":data["phones"],
                        "message":f"Phone {ph} does NOT belong to {data['full_name']}. Real: {', '.join(data['phones']) or 'No public number'}"})
                    score_boost += 40; mismatches.append(f"Fake {data['full_name']} phone number")

            for dom in ex["domains"]:
                if dom in OFFICIAL_DOMAINS: continue
                if any(short in dom or name.split()[0] in dom for _ in [1]):
                    if not any(dom in w for w in data["websites"]):
                        findings.append({"type":"FAKE WEBSITE","institution":data["full_name"],
                            "fake_value":dom,"real_values":data["websites"],
                            "message":f"Website '{dom}' is NOT official. Real: {', '.join(data['websites'])}"})
                        score_boost += 50; mismatches.append(f"Fake {data['full_name']} website")

            for em in ex["emails"]:
                real_domains = data["emails"]
                if not any(em.endswith(rd.lstrip("@")) for rd in real_domains):
                    if any(short in em or name.split()[0].lower() in em for _ in [1]):
                        findings.append({"type":"FAKE EMAIL","institution":data["full_name"],
                            "fake_value":em,"real_values":real_domains,
                            "message":f"Email '{em}' is NOT from {data['full_name']}. Official: {', '.join(real_domains)}"})
                        score_boost += 45; mismatches.append(f"Fake {data['full_name']} email")

            if note:
                findings.append({"type":"WARNING","institution":data["full_name"],
                    "fake_value":"","real_values":[],"message":f"Note: {note}"})

        return {"findings":findings, "score_boost":min(score_boost,60),
                "mismatches":mismatches,
                "has_mismatch":any(f["type"]!="WARNING" for f in findings)}

# ==============================================================================
# 11. BEHAVIOUR ENGINE
# ==============================================================================

class BehaviourEngine:
    @staticmethod
    def scan(text):
        tl = text.lower(); score = 10
        beh_matched={}; emo_matched={}; fired=[]; mutations=[]

        for b, kws in BEHAVIOUR_PATTERNS.items():
            hits = [k for k in kws if k in tl]
            if hits:
                score += BEHAVIOUR_WEIGHTS[b]
                beh_matched[b] = hits
                fired.append(b.replace("_"," ").title())

        for p, kws in EMOTIONAL_PATTERNS.items():
            hits = [k for k in kws if k in tl]
            if hits:
                score += EMOTIONAL_WEIGHTS[p]
                emo_matched[p] = hits
                fired.append("⚠ " + p.replace("_"," ").title())

        for tmpl in MUTATION_TEMPLATES:
            if all(w in tl for w in tmpl["must_have"]):
                score += tmpl["boost"]
                mutations.append(tmpl["name"])
                fired.append(f"📍 {tmpl['name']}")

        output_mode = "SCAM"
        is_emotional = bool(emo_matched)

        if emo_matched.get("claims_to_be_family") and (
            emo_matched.get("unknown_sender_payment") or beh_matched.get("requests_payment")):
            score += 40; fired.append("🚨 FAMILY IMPERSONATION + PAYMENT"); output_mode = "VERIFY_50_50"

        if emo_matched.get("claims_emergency") and (
            emo_matched.get("unknown_sender_payment") or beh_matched.get("requests_payment")):
            score += 30; fired.append("🚨 FAKE EMERGENCY + PAYMENT"); output_mode = "VERIFY_50_50"

        if is_emotional and score < 60: output_mode = "VERIFY_50_50"

        n = len(beh_matched)
        if n >= 3: score += 15
        if n >= 5: score += 15

        # Anti-false-positive guard:
        # If only 1 or 0 behaviours fire with very few keyword hits
        # and no emotional/mutation signals — cap at LOW.
        # Prevents short words inside educational/image text from inflating risk.
        if n <= 1 and not emo_matched and not mutations:
            total_hits = sum(len(v) for v in beh_matched.values())
            if total_hits <= 2:
                score = min(score, 20)

        all_triggers = list({k for v in {**beh_matched,**emo_matched}.values() for k in v})
        return {"score":min(score,99),"fired":list(set(fired)),
                "beh_matched":beh_matched,"emo_matched":emo_matched,
                "mutations":mutations,"is_emotional":is_emotional,
                "output_mode":output_mode,"all_triggers":all_triggers}

    @staticmethod
    def context(scan):
        fired=scan.get("fired",[]); mutations=scan.get("mutations",[])
        is_emotional=scan.get("is_emotional",False)
        if not fired and not mutations: return "No manipulation techniques detected."
        lines=["MANIPULATION TECHNIQUES FOUND:"]
        mapping={
            "Creates Fear":"Tries to SCARE (arrest/block/legal action)",
            "Creates Urgency":"Creates TIME PRESSURE to stop clear thinking",
            "Promises Money":"PROMISES money/reward/income",
            "Asks For Secrets":"ASKS for OTP/PIN/Aadhaar/screen access",
            "Impersonates Authority":"PRETENDS to be bank/government/company",
            "Isolates Victim":"Tells victim KEEP SILENT from family/police",
            "Requests Payment":"DEMANDS MONEY via UPI/transfer/crypto",
            "Claims To Be Family":"Unknown number CLAIMS TO BE family — HIGH RED FLAG",
            "Claims Emergency":"Creates FAKE EMERGENCY (phone dead/accident)",
            "Unknown Sender Payment":"Unknown person demanding IMMEDIATE PAYMENT",
            "Creates Sympathy":"Uses EMOTIONAL BLACKMAIL",
        }
        for f in fired:
            clean=f.replace("⚠ ","").replace("🚨 ","").replace("📍 ","")
            lines.append(f"  - {mapping.get(clean,clean)}")
        if mutations: lines.append(f"\nEVOLVED PATTERNS: {', '.join(mutations)}")
        if is_emotional:
            lines += ["\nSPECIAL: Uses EMOTIONAL/RELATIONSHIP manipulation.",
                      "Sender may claim to be family/friend to gain trust.",
                      "RULE: Always verify by calling them on their KNOWN number first."]
        return "\n".join(lines)

# ==============================================================================
# 12. IMAGE PROCESSOR
# ==============================================================================

class ImageProcessor:
    @staticmethod
    def validate(fb, ct):
        if len(fb)/(1024*1024) > 10: raise HTTPException(413,"Image too large. Max 10MB.")
        if not (ct or "").lower().startswith("image/"): raise HTTPException(415,f"Not an image: {ct}")

    @staticmethod
    def ocr(fb):
        try:
            img = Image.open(io.BytesIO(fb))
            if img.mode not in ('L','RGB','RGBA'): img = img.convert('RGB')
            img = ImageOps.grayscale(img)
            img = img.point(lambda px: 0 if px < 140 else 255)
            img = img.filter(ImageFilter.MedianFilter(3))
            img = ImageEnhance.Contrast(img).enhance(2.0)
            img = img.filter(ImageFilter.SHARPEN)
            return pytesseract.image_to_string(img, config='--oem 3 --psm 6').strip()
        except Exception as e:
            logger.error(f"OCR: {e}"); return ""

# ==============================================================================
# 13. GROQ AI ENGINE
# ==============================================================================

class SentinelAI:
    def is_online(self):
        try:
            r = requests.get("https://api.groq.com/openai/v1/models",
                headers={"Authorization":f"Bearer {GROQ_API_KEY}"}, timeout=3)
            return r.status_code == 200
        except: return False

    async def see_image(self, fb):
        b64 = base64.b64encode(fb).decode()
        hdrs = {"Authorization":f"Bearer {GROQ_API_KEY}","Content-Type":"application/json"}
        payload = {
            "model": GROQ_VISION_MODEL,
            "messages":[{"role":"user","content":[
                {"type":"image_url","image_url":{"url":f"data:image/jpeg;base64,{b64}"}},
                {"type":"text","text":(
                    "Describe this image carefully. "
                    "If it has text (SMS/WhatsApp/email) write ALL text word for word. "
                    "If it is a photo/diagram/document describe exactly what it shows. "
                    "Be specific — used to check for scams.")}
            ]}],
            "max_tokens":600,"temperature":0.1
        }
        try:
            r = await asyncio.to_thread(requests.post,GROQ_API_URL,headers=hdrs,json=payload,timeout=30)
            if r.status_code == 200:
                desc = r.json()["choices"][0]["message"]["content"]
                logger.info(f"[VISION] {desc[:80]}..."); return desc.strip()
            logger.error(f"[VISION] {r.status_code}"); return ""
        except Exception as e: logger.error(f"[VISION] {e}"); return ""

    async def analyse(self, evidence, beh_ctx, mis_ctx, output_mode, learned):
        learned_str = ""
        if learned:
            learned_str = "RECENTLY LEARNED FROM NEWS:\n"
            learned_str += "\n".join(f"  - {p['pattern'][:100]}" for p in learned[:5])

        verify_instr = ""
        if output_mode == "VERIFY_50_50":
            verify_instr = (
                "\nSPECIAL MODE — 50/50 VERIFY FIRST:\n"
                "Set risk_percentage=50, output_mode='VERIFY_50_50'.\n"
                "Tell person: call this same number back, ask a private question only real family knows.\n"
                "Never send money before voice verification.\n"
            )

        prompt = (
            "You are a scam protection helper for Indian citizens including village people.\n"
            "Use simple language. No technical words.\n\n"
            "RULES:\n"
            "1. Judge by MANIPULATION TECHNIQUES not just content.\n"
            "2. Unknown number + family claim + money request = suspicious (50-50).\n"
            "3. Mismatch between claimed institution and real contact = SCAM.\n"
            "4. New unknown patterns using fear/urgency/payment = still suspicious.\n"
            "5. Educational diagrams, textbook images, architecture charts, network diagrams = ALWAYS say NOT a scam, risk 0%.\n"
            "6. If the image shows a computer network diagram, flowchart, or textbook content — it is 100% safe. Return risk_percentage=0, scam_detected=false.\n"
            "7. Only flag as suspicious if there is a CLEAR and DIRECT manipulation technique present. Do not guess.\n"
            "8. MONEY DOUBLING: Any message saying 'deposit X and get 2X' or 'will double' or 'bonus in minutes' = CRITICAL scam, risk 90%+.\n"
            "9. CRITICAL: Analyse ONLY the evidence given below. Do NOT describe a previous image or assume. Your summary must match the exact text/image provided.\n"
            "10. If evidence contains investment promises with guaranteed returns in minutes/hours = Investment Fraud, risk 85%+.\n"
            f"{verify_instr}\n"
            f"{beh_ctx}\n\n"
            f"{mis_ctx}\n\n"
            f"{learned_str}\n\n"
            'Reply ONLY valid JSON:\n'
            '{"scam_detected":bool,"risk_percentage":int(0-100),"confidence":int(0-100),'
            '"output_mode":"SCAM or VERIFY_50_50 or SAFE",'
            '"scam_category":"simple name",'
            '"psychological_triggers":["warning signs in simple words"],'
            '"summary":"2-3 simple sentences — say clearly if scam/not/uncertain and why",'
            '"action_plan":["Step 1","Step 2","Step 3","Step 4"],'
            '"forensic_narrative":"MINIMUM 600 CHARACTERS in formal legal English for police submission. Cover: (1) Nature of Offence, (2) Modus Operandi of accused, (3) Psychological manipulation used, (4) Financial risk to victim, (5) Technical details found, (6) Relief requested from authorities. Formal language only."}\n\n'
            f"SCAN_ID: {uuid.uuid4().hex[:8]} | TIME: {datetime.now().isoformat()}\n"
            f"ANALYSE THIS SPECIFIC EVIDENCE ONLY — DO NOT DESCRIBE ANYTHING ELSE:\n"
            f"EVIDENCE:\n{evidence[:1500]}"
        )

        hdrs = {"Authorization":f"Bearer {GROQ_API_KEY}","Content-Type":"application/json"}
        payload = {
            "model": GROQ_TEXT_MODEL,
            "messages":[
                {"role":"system","content":"Scam detection assistant. Reply ONLY valid JSON."},
                {"role":"user","content":prompt}
            ],
            "temperature":0.1,"max_tokens":900,
            "response_format":{"type":"json_object"}
        }
        try:
            logger.info("[AI] Sending to Groq...")
            r = await asyncio.to_thread(requests.post,GROQ_API_URL,headers=hdrs,json=payload,timeout=20)
            if r.status_code == 429: await asyncio.sleep(2); return await self.analyse(evidence,beh_ctx,mis_ctx,output_mode,learned)
            if r.status_code != 200: logger.error(f"[AI] {r.status_code}"); return None
            result = json.loads(r.json()["choices"][0]["message"]["content"])
            logger.info("[AI] Done."); return result
        except Exception as e: logger.error(f"[AI] {e}"); return None

    @staticmethod
    def fallback():
        return {
            "scam_detected":False,"risk_percentage":0,"confidence":0,
            "output_mode":"SAFE","scam_category":"Could Not Check — Try Again",
            "psychological_triggers":[],
            "summary":"Our AI checker is not available. Please try again in a moment.",
            "action_plan":["Try again in a moment","Do NOT share OTP or bank details with anyone",
                           "Call 1930 — National Cyber Crime Helpline if urgent","Report at cybercrime.gov.in"],
            "forensic_narrative":"AI unavailable. Stay safe:\n1. Do not reply to suspicious messages\n2. Call 1930 for help"
        }

ai = SentinelAI()

# ==============================================================================
# 14. RISK CLASSIFICATION & REPORT EXPORTER
# ==============================================================================

def classify_risk(score, mode):
    if mode == "VERIFY_50_50": return "VERIFY FIRST","#f59e0b"
    if score <= 25: return "LOW","#22c55e"
    if score <= 50: return "MODERATE","#f59e0b"
    if score <= 75: return "HIGH","#f97316"
    return "CRITICAL","#ef4444"

class Exporter:
    @staticmethod
    def to_text(scan):
        """
        Generates a professional, police-grade complaint document
        ready to be submitted directly to cybercrime.gov.in or
        any police station in India.
        """
        now       = datetime.now()
        scan_id   = scan.get('scan_id', 'N/A')
        timestamp = scan.get('timestamp', now.isoformat())
        risk      = scan.get('risk_score', 0)
        level     = scan.get('risk_level', 'N/A')
        category  = scan.get('scam_type', 'N/A')
        mode      = scan.get('output_mode', 'N/A')
        summary   = scan.get('summary', 'N/A')
        report    = scan.get('full_report', 'N/A')
        preview   = scan.get('input_preview', 'N/A')

        try:
            actions = json.loads(scan.get('action_plan', '[]'))
        except:
            actions = []

        try:
            meta = json.loads(scan.get('metadata_json', '{}'))
        except:
            meta = {}

        # Format timestamp nicely
        try:
            dt = datetime.fromisoformat(timestamp)
            date_str = dt.strftime("%d %B %Y")
            time_str = dt.strftime("%I:%M %p")
            datetime_str = dt.strftime("%d/%m/%Y at %I:%M %p")
        except:
            date_str = date_str = "N/A"
            time_str = "N/A"
            datetime_str = timestamp

        divider  = "=" * 72
        section  = "-" * 72

        lines = [
            divider,
            "",
            "                    CYBER CRIME COMPLAINT REPORT",
            "          (Prepared for submission to cybercrime.gov.in)",
            "",
            divider,
            "",
            f"  REPORT REFERENCE  : {scan_id}",
            f"  DATE OF REPORT    : {date_str}",
            f"  TIME OF REPORT    : {time_str}",
            f"  PREPARED BY       : YOUR SENTINEL AI — Automated Forensic Analysis",
            f"  PORTAL            : cybercrime.gov.in",
            f"  HELPLINE          : 1930 (National Cyber Crime Helpline)",
            "",
            divider,
            "",
            "  SECTION 1 — NATURE AND CLASSIFICATION OF OFFENCE",
            "",
            section,
            "",
            f"  Offence Category  : {category}",
            f"  Threat Level      : {level}  ({risk}% Risk Score)",
            f"  Analysis Mode     : {mode}",
            f"  AI Confidence     : {scan.get('confidence', 'N/A')}",
            "",
            "  Brief Description of Offence:",
            "",
        ]

        # Wrap summary at 68 chars for readability
        words = summary.split()
        line_buf = "  "
        for w in words:
            if len(line_buf) + len(w) + 1 > 70:
                lines.append(line_buf)
                line_buf = "  " + w
            else:
                line_buf += (" " if line_buf != "  " else "") + w
        if line_buf.strip():
            lines.append(line_buf)

        lines += [
            "",
            divider,
            "",
            "  SECTION 2 — EVIDENCE SUBMITTED BY COMPLAINANT",
            "",
            section,
            "",
            "  The following suspicious content was submitted for forensic analysis:",
            "",
            f"  {preview[:300]}{'...' if len(preview) > 300 else ''}",
            "",
        ]

        # Technical indicators
        lines += [
            divider,
            "",
            "  SECTION 3 — TECHNICAL INDICATORS OF CRIME",
            "",
            section,
            "",
        ]

        urls    = meta.get('urls', [])
        phones  = meta.get('phones', [])
        upis    = meta.get('upi_ids', [])
        crypto  = meta.get('crypto', []) or meta.get('crypto_wallets', [])
        emails  = meta.get('emails', [])

        lines.append(f"  3.1  Suspicious URLs / Links Found    : {len(urls)}")
        for u in urls:
            lines.append(f"         → {u}")

        lines.append(f"  3.2  Phone Numbers Involved           : {len(phones)}")
        for p in phones:
            lines.append(f"         → {p}")

        lines.append(f"  3.3  UPI / Payment IDs Found          : {len(upis)}")
        for u in upis:
            lines.append(f"         → {u}")

        lines.append(f"  3.4  Cryptocurrency Wallets Found     : {len(crypto)}")
        for c in crypto:
            lines.append(f"         → {c}")

        lines.append(f"  3.5  Email Addresses Found            : {len(emails)}")
        for e in emails:
            lines.append(f"         → {e}")

        if not any([urls, phones, upis, crypto, emails]):
            lines.append("  No specific technical indicators were automatically extracted.")
            lines.append("  Refer to the evidence submitted in Section 2 above.")

        lines += [
            "",
            divider,
            "",
            "  SECTION 4 — DETAILED FORENSIC ANALYSIS",
            "             (For use by Investigating Officer)",
            "",
            section,
            "",
        ]

        # Wrap forensic report
        for para in report.split('\n'):
            if not para.strip():
                lines.append("")
                continue
            words2 = para.split()
            line_buf2 = "  "
            for w in words2:
                if len(line_buf2) + len(w) + 1 > 70:
                    lines.append(line_buf2)
                    line_buf2 = "  " + w
                else:
                    line_buf2 += (" " if line_buf2 != "  " else "") + w
            if line_buf2.strip():
                lines.append(line_buf2)

        lines += [
            "",
            divider,
            "",
            "  SECTION 5 — RECOMMENDED IMMEDIATE ACTIONS",
            "",
            section,
            "",
            "  The following steps are recommended for the complainant and the",
            "  Investigating Officer to take immediately:",
            "",
        ]
        for i, action in enumerate(actions, 1):
            lines.append(f"  {i:02d}. {action}")
        if not actions:
            lines.append("  01. Report this immediately at cybercrime.gov.in")
            lines.append("  02. Call 1930 — National Cyber Crime Helpline")
            lines.append("  03. Do not engage further with the suspect")
            lines.append("  04. Preserve all evidence (screenshots, call logs)")

        lines += [
            "",
            divider,
            "",
            "  SECTION 6 — APPLICABLE LAWS AND LEGAL PROVISIONS",
            "",
            section,
            "",
            "  This offence may be prosecuted under one or more of the following:",
            "",
            "  • Information Technology Act, 2000 — Section 66D",
            "    (Cheating by personation using computer resource)",
            "",
            "  • Information Technology Act, 2000 — Section 66C",
            "    (Identity theft / fraudulent use of electronic signature)",
            "",
            "  • Indian Penal Code — Section 420",
            "    (Cheating and dishonestly inducing delivery of property)",
            "",
            "  • Indian Penal Code — Section 415",
            "    (Cheating — causing damage to person deceived)",
            "",
            "  • Indian Penal Code — Section 384",
            "    (Punishment for extortion — if threats were involved)",
            "",
            "  • Indian Penal Code — Section 406",
            "    (Punishment for criminal breach of trust)",
            "",
            "  Note: Final determination of applicable sections rests with the",
            "  Investigating Officer and Public Prosecutor.",
            "",
            divider,
            "",
            "  SECTION 7 — DECLARATION",
            "",
            section,
            "",
            "  I hereby declare that the information provided in this complaint",
            "  is true and correct to the best of my knowledge and belief.",
            "  I understand that providing false information is a punishable",
            "  offence under the laws of India.",
            "",
            "  Complainant Signature : _______________________________",
            "",
            "  Full Name             : _______________________________",
            "",
            "  Address               : _______________________________",
            "",
            "                          _______________________________",
            "",
            "  Mobile Number         : _______________________________",
            "",
            "  Aadhaar / ID Number   : _______________________________",
            "",
            "  Date                  : _______________________________",
            "",
            divider,
            "",
            "  FOR OFFICIAL USE — POLICE / CYBERCRIME CELL",
            "",
            section,
            "",
            "  Complaint Received By  : _______________________________",
            "  Designation            : _______________________________",
            "  Date & Time of Receipt : _______________________________",
            "  FIR / Complaint No.    : _______________________________",
            "  Police Station         : _______________________________",
            "  District               : _______________________________",
            "",
            divider,
            "",
            "  GENERATED BY  : YOUR SENTINEL v7.0 — AI Cybercrime Intelligence",
            "  REPORT REF    : " + scan_id,
            "  GENERATED ON  : " + datetime_str,
            "  PORTAL        : cybercrime.gov.in",
            "  HELPLINE      : 1930 (Available 24x7)",
            "",
            "  *** This report is system-generated. For official complaint, please",
            "      fill in the Complainant details in Section 7 above and submit",
            "      at your nearest police station or at cybercrime.gov.in ***",
            "",
            divider,
        ]

        return "\n".join(lines)

    @staticmethod
    def save(scan_id, content):
        fn = f"{scan_id}_CyberCrime_Complaint_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        fp = os.path.join(RPT_DIR, fn)
        with open(fp, 'w', encoding='utf-8') as f:
            f.write(content)
        return fp

# ==============================================================================
# 15. PYDANTIC MODELS
# ==============================================================================

class ScanOutput(BaseModel):
    scan_id:str; timestamp:str; risk_percentage:str; risk_level:str
    confidence:str; output_mode:str; is_scam:bool; category:str
    summary:str; triggers:List[str]; forensic_report:str
    metadata:Dict[str,List[str]]; action:List[str]
    mismatches:List[str]; verification_guide:Optional[str]=None
    mismatch_details:List[Dict]=[]

class ConfirmReq(BaseModel):
    scan_id:str; verdict:str; keywords:List[str]=[]

class NotifMarkReq(BaseModel):
    notif_id:Optional[str]=None   # None = mark all read

# ==============================================================================
# 16. FASTAPI APP & MIDDLEWARE
# ==============================================================================

app = FastAPI(title="Your Sentinel",version="7.0.0",
              docs_url="/api/docs",redoc_url="/api/redoc")

app.add_middleware(CORSMiddleware,allow_origins=["*"],
                   allow_credentials=True,allow_methods=["*"],allow_headers=["*"])

@app.middleware("http")
async def timer(req,call_next):
    t=time.time(); r=await call_next(req)
    r.headers["X-Process-Time"]=str(round(time.time()-t,3)); return r

# ==============================================================================
# 17. WEBSOCKET ENDPOINT (Feature 14 — Real-time notifications)
# ==============================================================================

@app.websocket("/ws/notifications")
async def websocket_notifications(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Send unread count immediately on connect
        unread = db.unread_count()
        await websocket.send_json({
            "event": "connected",
            "unread_count": unread,
            "message": "Connected to Sentinel notification stream"
        })
        # Keep connection alive
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"event":"pong","timestamp":datetime.now().isoformat()})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

# ==============================================================================
# 18. MAIN SCAN ENDPOINT
# ==============================================================================

@app.get("/",include_in_schema=False)
async def ui():
    # Use absolute path so it works both locally and on Render
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
    return FileResponse(html_path)

@app.post("/analyze",response_model=ScanOutput,tags=["Analysis"])
async def scan_evidence(
    background_tasks: BackgroundTasks,
    text: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None)
):
    t0=time.time(); scan_id=f"SN-{uuid.uuid4().hex[:8].upper()}"
    logger.info(f"[SCAN] {scan_id}")
    combined = text.strip() if text else ""

    # Auto news every 6h
    background_tasks.add_task(NewsIntelligence.run_if_due)

    # Vision AI → OCR fallback
    if file:
        fb = await file.read()
        ImageProcessor.validate(fb, file.content_type or "")
        vision = await ai.see_image(fb)
        if vision:
            combined += f"\n\n[IMAGE CONTENT]:\n{vision}"
        else:
            ocr = ImageProcessor.ocr(fb)
            combined += f"\n\n[IMAGE TEXT]:\n{ocr}" if ocr and len(ocr)>10 else "\n\n[IMAGE]: Uploaded."

    if not combined.strip(): raise HTTPException(400,"No evidence provided.")

    # Mismatch check
    mis = MismatchDetector.check(combined)
    mis_ctx = ""
    if mis["findings"]:
        mis_ctx = "OFFICIAL DB FINDINGS:\n" + "\n".join(f["message"] for f in mis["findings"])

    # Behaviour + emotional + mutation
    beh = BehaviourEngine.scan(combined)
    beh_ctx = BehaviourEngine.context(beh)
    output_mode = beh["output_mode"]
    if mis["has_mismatch"]: output_mode = "SCAM"

    # Community + learned
    com_boost = db.community_boost(combined)
    learned = db.get_learned()

    # Groq AI
    ai_data = await ai.analyse(combined, beh_ctx, mis_ctx, output_mode, learned)
    if not ai_data: ai_data = SentinelAI.fallback()

    # Final score
    ai_score=ai_data.get("risk_percentage",0); beh_score=beh["score"]
    mis_boost=mis["score_boost"]
    final = 50 if output_mode=="VERIFY_50_50" else min(max(ai_score,beh_score)+mis_boost+com_boost,99)
    risk_level,_ = classify_risk(final,output_mode)

    # Verification guide
    verify_guide = None
    if output_mode == "VERIFY_50_50":
        verify_guide = (
            "HOW TO VERIFY IN 60 SECONDS:\n\n"
            "Step 1 — Call this SAME number back right now.\n"
            "Step 2 — Is it really your family member's voice?\n"
            "Step 3 — Ask a PRIVATE question only they would know.\n"
            "Step 4 — If they cannot answer → SCAMMER. Hang up immediately.\n"
            "Step 5 — NEVER send money or scan QR before this verification.\n\n"
            "A real family member will understand why you are asking."
        )

    # Indicators
    meta = {
        "urls":    list(set(re.findall(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',combined))),
        "phones":  list(set(re.findall(r'(?:\+91[\s\-]?)?[6-9]\d{9}|\b1[89]00[\d\s\-]{6,}',combined))),
        "upi_ids": list(set(re.findall(r'[a-zA-Z0-9.\-_]{2,64}@(?:okaxis|okhdfcbank|okicici|oksbi|ybl|upi|paytm|gpay|phonepe|apl)',combined))),
        "crypto":  list(set(re.findall(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[qp][a-z0-9]{38,58}',combined))),
        "emails":  list(set(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',combined))),
    }
    triggers = list(set(
        ai_data.get("psychological_triggers",[]) +
        beh.get("all_triggers",[]) + mis.get("mismatches",[])
    ))

    result = ScanOutput(
        scan_id=scan_id, timestamp=datetime.now().isoformat(),
        risk_percentage=f"{final}%", risk_level=risk_level,
        confidence=f"{ai_data.get('confidence',0)}%",
        output_mode=output_mode,
        is_scam=ai_data.get("scam_detected",False),
        category=ai_data.get("scam_category","Unknown"),
        summary=ai_data.get("summary",""),
        triggers=triggers,
        forensic_report=ai_data.get("forensic_narrative",""),
        metadata=meta, action=ai_data.get("action_plan",[]),
        mismatches=mis.get("mismatches",[]),
        verification_guide=verify_guide,
        mismatch_details=[f for f in mis["findings"] if f["type"]!="WARNING"]
    )

    # Send real-time notification for high-risk scans
    if final >= 75:
        background_tasks.add_task(
            ws_manager.send_notification,
            f"⚠ High Risk Scan Detected",
            f"Scan {scan_id} — {result.category} — {final}% risk",
            "danger", result.category, "CRITICAL"
        )
    elif output_mode == "VERIFY_50_50":
        background_tasks.add_task(
            ws_manager.send_notification,
            "⚡ Verification Required",
            f"Scan {scan_id} — Possible family impersonation. Please verify before sending money.",
            "warn", result.category, "HIGH"
        )

    for f in mis["findings"]:
        if f["type"]!="WARNING":
            background_tasks.add_task(db.log_mismatch,scan_id,
                f["institution"],f["fake_value"],f["real_values"],f["type"])

    background_tasks.add_task(
        db.log_scan,scan_id,final,ai_data.get("confidence",0),
        risk_level,output_mode,result.category,result.summary,
        result.forensic_report,result.action,combined,meta
    )

    logger.info(f"[SCAN] {scan_id} done {round(time.time()-t0,2)}s | {risk_level} {final}%")
    return result

# ==============================================================================
# 19. NEWS BOARD ENDPOINTS (Feature 13)
# ==============================================================================

@app.get("/news",tags=["News Board"])
async def get_news(
    limit:    int = Query(20,ge=1,le=100),
    offset:   int = Query(0,ge=0),
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None)
):
    """Get scam news with optional filters by category and severity."""
    return db.get_news(limit=limit, offset=offset, category=category, severity=severity)

@app.get("/news/latest",tags=["News Board"])
async def latest_news():
    """Get the 5 most recent scam alerts — used for ticker/notifications."""
    return db.get_news(limit=5)

@app.get("/news/ticker",tags=["News Board"])
async def news_ticker():
    """Get news titles for the scrolling ticker bar."""
    news = db.get_news(limit=15)
    return [{"id":n["id"],"title":n["title"],"severity":n["severity"],"category":n["category"]} for n in news]

@app.get("/news/{news_id}",tags=["News Board"])
async def get_news_item(news_id: str):
    """Get a single news item with full tips."""
    item = db.get_news_by_id(news_id)
    if not item: raise HTTPException(404,"News item not found")
    return item

@app.get("/news/category/{category}",tags=["News Board"])
async def news_by_category(category: str, limit: int = Query(10,ge=1,le=50)):
    """Get news filtered by scam category."""
    return db.get_news(limit=limit, category=category)

@app.get("/prevention-tips",tags=["News Board"])
async def prevention_tips(category: Optional[str] = Query(None)):
    """Get prevention tips — all categories or specific one."""
    if category and category in PREVENTION_TIPS:
        return {"category":category,"tips":PREVENTION_TIPS[category]}
    return PREVENTION_TIPS

@app.get("/prevention-tips/{category}",tags=["News Board"])
async def prevention_tips_category(category: str):
    """Get tips for a specific scam category."""
    tips = PREVENTION_TIPS.get(category, PREVENTION_TIPS["General Safety Tips"])
    return {"category":category,"tips":tips}

@app.post("/news/refresh",tags=["News Board"])
async def refresh_news(background_tasks: BackgroundTasks):
    """Manually trigger news refresh from cybercrime.gov.in and RBI."""
    background_tasks.add_task(NewsIntelligence._fetch_all)
    return {"message":"News refresh started in background. Check /news in 30 seconds."}

# ==============================================================================
# 20. NOTIFICATION ENDPOINTS (Feature 14)
# ==============================================================================

@app.get("/notifications",tags=["Notifications"])
async def get_notifications(unread_only: bool = Query(False)):
    """Get all notifications or only unread ones."""
    return db.get_notifications(unread_only=unread_only)

@app.get("/notifications/unread-count",tags=["Notifications"])
async def unread_count():
    """Get count of unread notifications — used for bell badge."""
    return {"count": db.unread_count()}

@app.post("/notifications/mark-read",tags=["Notifications"])
async def mark_notifications_read(req: NotifMarkReq):
    """Mark one or all notifications as read."""
    db.mark_read(req.notif_id)
    return {"message":"Notifications marked as read"}

@app.post("/notifications/test",tags=["Notifications"])
async def test_notification():
    """Send a test notification to all connected WebSocket clients."""
    await ws_manager.send_notification(
        "🛡️ Sentinel Active",
        "Your Sentinel is watching. Stay safe from scams.",
        "info", "System", "INFO"
    )
    return {"message":"Test notification sent"}

# ==============================================================================
# 21. COMMUNITY & UTILITY ENDPOINTS
# ==============================================================================

@app.post("/confirm",tags=["Community"])
async def confirm(req: ConfirmReq):
    r = db.get_scan(req.scan_id)
    if not r: raise HTTPException(404,"Scan not found")
    kws = req.keywords or re.findall(r'\b\w{4,}\b',r.get('input_preview','').lower())[:8]
    db.confirm_scam(req.scan_id, req.verdict, kws)
    # Notify all clients when community confirms a scam
    if req.verdict == "scam":
        await ws_manager.send_notification(
            "📢 Community Alert",
            f"A new scam pattern was confirmed by the community. System has learned.",
            "warn", "Community Learning", "HIGH"
        )
    return {"message":f"Thank you! Verdict '{req.verdict}' saved. This helps protect other citizens."}

@app.get("/history",tags=["Vault"])
async def history(limit:int=Query(20,ge=1,le=100), offset:int=Query(0,ge=0)):
    return db.history(limit,offset)

@app.get("/scan/{scan_id}",tags=["Vault"])
async def get_scan(scan_id:str):
    r=db.get_scan(scan_id)
    if not r: raise HTTPException(404,"Not found"); return r

@app.delete("/scan/{scan_id}",tags=["Vault"])
async def del_scan(scan_id:str):
    if not db.delete(scan_id): raise HTTPException(404,"Not found")
    return {"message":f"{scan_id} deleted"}

@app.get("/export/{scan_id}",tags=["Export"])
async def export(scan_id:str):
    r=db.get_scan(scan_id)
    if not r: raise HTTPException(404,"Not found")
    report_text = Exporter.to_text(r)
    # Save to disk as backup
    Exporter.save(scan_id, report_text)
    # Return as downloadable plain text with proper CORS-friendly headers
    from fastapi.responses import Response
    filename = f"{scan_id}_complaint_report.txt"
    return Response(
        content=report_text.encode('utf-8'),
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Expose-Headers": "Content-Disposition"
        }
    )

@app.get("/export-all",tags=["Export"])
async def export_all():
    rows=db.history(1000)
    out=io.StringIO()
    if rows:
        w=csv.DictWriter(out,fieldnames=rows[0].keys())
        w.writeheader(); w.writerows(rows)
    out.seek(0)
    return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",
        headers={"Content-Disposition":"attachment; filename=sentinel_history.csv"})

@app.get("/stats",tags=["Analytics"])
async def stats(): return db.stats()

@app.get("/official-db",tags=["Intelligence"])
async def official_db():
    return {k:{"full_name":v["full_name"],"websites":v["websites"],
               "phones":v["phones"],"note":v["note"]} for k,v in OFFICIAL_DB.items()}

@app.get("/learned-patterns",tags=["Intelligence"])
async def learned(): return db.get_learned()

@app.get("/health",tags=["System"])
async def health():
    ai_ok=ai.is_online()
    try: vkb=sum(os.path.getsize(os.path.join(dp,f)) for dp,_,fs in os.walk(VAULT_DIR) for f in fs)/1024
    except: vkb=0
    news_count = len(db.get_news(limit=1000))
    return {
        "status":"Active","version":"7.0.0",
        "ai_core":"Online" if ai_ok else "Offline",
        "text_model":GROQ_TEXT_MODEL,"vision_model":GROQ_VISION_MODEL,
        "database":"Connected" if os.path.exists(DB_PATH) else "Error",
        "official_institutions":len(OFFICIAL_DB),
        "behaviour_patterns":len(BEHAVIOUR_PATTERNS)+len(EMOTIONAL_PATTERNS),
        "mutation_templates":len(MUTATION_TEMPLATES),
        "news_articles":news_count,
        "prevention_categories":len(PREVENTION_TIPS),
        "ws_clients":len(ws_manager.active),
        "vault_kb":round(vkb,2),
        "timestamp":datetime.now().isoformat()
    }

# ==============================================================================
# 22. STARTUP BANNER
# ==============================================================================

if __name__ == "__main__":
    import os
    # Render provides the PORT as an environment variable
    port = int(os.environ.get("PORT", 8000)) 
    
    print(f"--- SENTINEL v8.5.0 DEPLOYED ON PORT {port} ---")
    
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=port, 
        reload=False, 
        workers=2 # Reduced workers for Render's free tier RAM limits
    )
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║     🛡️   YOUR SENTINEL v7.0 — COMPLETE INTEGRATED EDITION          ║
╠══════════════════════════════════════════════════════════════════════╣
║  SCAN ENGINE:                                                        ║
║  ✅ Groq Vision AI      — sees ANY image                            ║
║  ✅ Behaviour Engine    — catches new scams by technique             ║
║  ✅ Emotional Detection — family impersonation / Hi Dad scam         ║
║  ✅ 50-50 Verify Mode   — voice verification guide                   ║
║  ✅ Official India DB   — 35+ institutions verified                  ║
║  ✅ Mismatch Detector   — fake numbers/websites caught instantly     ║
║  ✅ Community Learning  — users teach the system                     ║
║  ✅ Pattern Mutation    — evolved scam variants detected              ║
║                                                                      ║
║  NEWS & ALERTS:                                                      ║
║  ✅ Public News Board   — 18 hardcoded + live scraped articles       ║
║  ✅ Prevention Tips DB  — 15 categories of safety advice             ║
║  ✅ Auto News Reading   — cybercrime.gov.in every 6 hours            ║
║  ✅ Push Notifications  — real-time WebSocket alerts                 ║
║  ✅ News Ticker         — scrolling scam alerts on frontend          ║
║                                                                      ║
║  API ENDPOINTS:                                                      ║
║  POST /analyze          — scan a message or image                    ║
║  GET  /news             — scam news board                            ║
║  GET  /news/ticker      — ticker titles                              ║
║  GET  /prevention-tips  — safety tips per category                   ║
║  GET  /notifications    — notification history                       ║
║  WS   /ws/notifications — real-time push notifications              ║
║  GET  /official-db      — India institution database                 ║
║  GET  /health           — system status                              ║
║                                                                      ║
║  ADDRESS  : http://127.0.0.1:8000                                    ║
║  API DOCS : http://127.0.0.1:8000/api/docs                           ║
║  HELPLINE : 1930  |  cybercrime.gov.in                               ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    port = int(os.environ.get('PORT', 8000))
    uvicorn.run(app, host='0.0.0.0', port=port, log_level='info')