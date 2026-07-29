"""
YOUR SENTINEL v8.0 — Main FastAPI Application.

All REST endpoints, WebSocket notifications, 4-AI scan pipeline,
background tasks, static frontend serving, and system orchestration.
Includes detailed OpenAPI documentation, Pydantic validation schemas,
robust layered error handling, and administrative diagnostics.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import (
    BackgroundTasks,
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Ensure backend package on path
BACKEND_DIR = Path(__file__).resolve().parent
ROOT_DIR = BACKEND_DIR.parent
FRONTEND_DIR = ROOT_DIR / "frontend"
sys.path.insert(0, str(BACKEND_DIR))

import config
from ai.brain import SentinelBrain
from ai.report_gen import ReportGenerator
from ai.url_checker import URLChecker, UrlUtils
from ai.vision import GeminiVision
from database import db
from scrapers.news_scraper import HARDCODED_NEWS, run_full_scrape, seed_hardcoded_news
from api_routes import create_timing_middleware, router as extended_router
from utils.exporter import history_to_csv, scan_to_text

logging.basicConfig(
    level=logging.DEBUG if config.DEBUG else logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("SENTINEL.MAIN")

# ---------------------------------------------------------------------------
# Global services
# ---------------------------------------------------------------------------

sentinel_brain = SentinelBrain()
gemini_vision = GeminiVision()
url_checker = URLChecker()
report_generator = ReportGenerator()

ws_connections: Set[WebSocket] = set()
_scrape_task: Optional[asyncio.Task] = None

class ConnectionManager:
    """WebSocket connection manager for real-time notifications."""

    def __init__(self) -> None:
        self.active: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active.add(websocket)
        logger.info("WebSocket connected. Total: %d", len(self.active))

    def disconnect(self, websocket: WebSocket) -> None:
        self.active.discard(websocket)
        logger.info("WebSocket disconnected. Total: %d", len(self.active))

    async def broadcast(self, message: Dict[str, Any]) -> None:
        dead: List[WebSocket] = []
        payload = json.dumps(message, default=str)
        for ws in list(self.active):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

ws_manager = ConnectionManager()

# ---------------------------------------------------------------------------
# Pydantic Request & Response schemas with Field descriptions
# ---------------------------------------------------------------------------

class StandardResponse(BaseModel):
    success: bool = Field(..., description="Indicates if the operation succeeded")
    message: Optional[str] = Field(None, description="Detailed success or error message")

# Analyze schemas
class AnalyzeRequest(BaseModel):
    text: str = Field(..., max_length=50000, description="Raw text content to analyze for scams")

class BehaviorTriggers(BaseModel):
    pattern: str = Field(..., description="Manipulation pattern ID")
    label: str = Field(..., description="Human-readable pattern label")
    keywords: List[str] = Field(..., description="Matched keywords within target text")
    score: float = Field(..., description="Risk weight assigned to trigger")

class URLThreat(BaseModel):
    url: str = Field(..., description="Extracted URL target checked")
    domain: Optional[str] = Field(None, description="Extracted domain of target")
    is_malicious: bool = Field(..., description="Malicious flag indicator")
    threat_score: float = Field(..., description="Risk score percentage calculated")
    threat_types: List[str] = Field(..., description="List of safety threats matched")

class AnalyzeResponseData(BaseModel):
    scan_id: str = Field(..., description="Unique human-readable scan ID (SN-XXXXXXXX)")
    input_text: str = Field(..., description="Raw text processed")
    input_type: str = Field(..., description="Input source: 'text' or 'image'")
    has_image: bool = Field(..., description="Indicates if file upload was provided")
    image_filename: Optional[str] = Field(None, description="Uploaded filename if present")
    risk_score: float = Field(..., description="Final computed risk score percentage")
    risk_level: str = Field(..., description="Calculated risk severity label (LOW, MODERATE, HIGH, CRITICAL)")
    category: str = Field(..., description="Predicted scam taxonomy category ID")
    verdict: str = Field(..., description="Scam classification status: SAFE, SCAM, or VERIFY")
    is_scam: bool = Field(..., description="True if risk score is above safety threshold")
    verify_mode: bool = Field(..., description="True if 50-50 validation is recommended")
    behaviour_scores: Dict[str, float] = Field(..., description="Scores per manipulation pattern")
    behaviour_triggers: List[BehaviorTriggers] = Field(..., description="Detailed behavior matches")
    mutation_matches: List[Dict[str, Any]] = Field(..., description="Evolved scam pattern template matches")
    mismatch_alerts: List[Dict[str, Any]] = Field(..., description="Spoofed institution contact alerts")
    url_threats: List[URLThreat] = Field(..., description="Malware or phishing URL checks")
    extracted_urls: List[str] = Field(..., description="All extracted links from content")
    forensic_narrative: str = Field(..., description="Comprehensive legal case analysis")
    recommended_actions: List[str] = Field(..., description="Next steps to protect target victim")
    suspect_phone: Optional[str] = Field(None, description="Extracted suspect phone number")
    suspect_upi: Optional[str] = Field(None, description="Extracted suspect UPI payment address")
    suspect_website: Optional[str] = Field(None, description="Extracted suspect URL")
    summary: str = Field(..., description="Paragraph overview of scan findings")
    pipeline_duration_ms: int = Field(..., description="Execution duration in milliseconds")
    verify_steps: List[str] = Field(..., description="Step-by-step identity validation steps for VERIFY mode")
    prevention: Dict[str, Any] = Field(..., description="Prevention guides for the predicted category")

class AnalyzeResponse(BaseModel):
    success: bool = Field(..., description="Indicates if operation succeeded")
    data: AnalyzeResponseData = Field(..., description="Core scan analysis results payload")

# Scan retrieval schemas
class ScanSummary(BaseModel):
    scan_id: str = Field(..., description="Unique scan ID")
    risk_score: float = Field(..., description="Risk score percentage")
    risk_level: str = Field(..., description="Risk level")
    category: str = Field(..., description="Category ID")
    verdict: str = Field(..., description="Verdict classification")
    is_scam: bool = Field(..., description="Scam classification indicator")
    verify_mode: bool = Field(..., description="50-50 verification recommendation flag")
    summary: Optional[str] = Field(None, description="Overview narrative summary")
    created_at: str = Field(..., description="Scan log generation timestamp")

class HistoryResponse(BaseModel):
    success: bool = Field(..., description="Indicates success")
    data: List[ScanSummary] = Field(..., description="Page items of scan logs")
    total: int = Field(..., description="Total items matching filter")
    page: int = Field(..., description="Current request page index")
    per_page: int = Field(..., description="Items count per page requested")

class ScanRetrievalResponse(BaseModel):
    success: bool = Field(..., description="Operation success indicator")
    data: Dict[str, Any] = Field(..., description="Entire serialized scan payload")

# Report Generation schemas
class ReportGenerateRequest(BaseModel):
    scan_id: str = Field(..., description="Linked scan ID")
    victim_name: str = Field(..., description="Complainant's full name")
    victim_mobile: str = Field(..., description="Complainant's 10-digit mobile number")
    victim_email: Optional[str] = Field(None, description="Complainant's email address")
    victim_address: Optional[str] = Field(None, description="Complainant's residential address")
    victim_city: Optional[str] = Field(None, description="Complainant's city name")
    victim_state: Optional[str] = Field(None, description="Complainant's state or UT")
    victim_pin: Optional[str] = Field(None, description="Complainant's PIN code")
    id_proof_type: Optional[str] = Field(None, description="Identification proof type (e.g. Aadhaar)")
    id_proof_number: Optional[str] = Field(None, description="Identification proof number")
    incident_date: Optional[str] = Field(None, description="Date when scam occurred (YYYY-MM-DD)")
    incident_time: Optional[str] = Field(None, description="Time when scam occurred (HH:MM)")
    amount_lost: Optional[float] = Field(0.0, description="Amount lost in INR")
    payment_method: Optional[str] = Field(None, description="Payment channel (UPI, NEFT, RTGS, etc.)")
    incident_details: Optional[str] = Field(None, description="Detailed account of incident")
    suspect_phone: Optional[str] = Field(None, description="Suspect phone contact details")
    suspect_upi: Optional[str] = Field(None, description="Suspect UPI payment handle")
    suspect_website: Optional[str] = Field(None, description="Suspect website URL")
    suspect_details: Optional[str] = Field(None, description="Additional suspect details")

class ReportGenerateData(BaseModel):
    report_id: str = Field(..., description="Unique generated report ID (RP-XXXXXXXX)")
    complaint_preview: str = Field(..., description="Truncated plain text preview of the complaint")
    generated_by: str = Field(..., description="Generation backend method: 'groq' or 'template'")

class ReportGenerateResponse(BaseModel):
    success: bool = Field(..., description="Indicates operation success")
    data: ReportGenerateData = Field(..., description="Generated report data wrapper")

class ReportRetrievalResponse(BaseModel):
    success: bool = Field(..., description="Operation success status")
    data: Dict[str, Any] = Field(..., description="Full victim report database payload")

class ReportCheckResponse(BaseModel):
    success: bool = Field(..., description="Operation success status")
    exists: bool = Field(..., description="Indicates if a report already exists for the scan")
    data: Optional[Dict[str, Any]] = Field(None, description="Existing victim report database payload if available")

# News articles schemas
class NewsArticle(BaseModel):
    article_id: str = Field(..., description="Unique article ID")
    title: str = Field(..., description="Advisory title text")
    summary: Optional[str] = Field(None, description="Brief article summary")
    content: Optional[str] = Field(None, description="Full markdown description body")
    source: Optional[str] = Field(None, description="Publishing agency name")
    source_url: Optional[str] = Field(None, description="Reference link of source")
    category: Optional[str] = Field(None, description="Predicted category mapping")
    severity: str = Field(..., description="Article alert level")
    is_hardcoded: bool = Field(..., description="True if seeded from hardcoded list")
    published_at: Optional[str] = Field(None, description="Publish date timestamp")
    scraped_at: Optional[str] = Field(None, description="Scrape sync timestamp")

class NewsArticlesResponse(BaseModel):
    success: bool = Field(..., description="Operation success status")
    data: List[NewsArticle] = Field(..., description="Filtered list of news advisories")

class SingleArticleResponse(BaseModel):
    success: bool = Field(..., description="Operation success status")
    data: NewsArticle = Field(..., description="Complete news advisory details")
    prevention_tips: Dict[str, Any] = Field(..., description="Prevention tips associated with article category")

class TickerItem(BaseModel):
    article_id: str = Field(..., description="Article ID")
    title: str = Field(..., description="Article title")
    severity: str = Field(..., description="Alert severity level")

class TickerResponse(BaseModel):
    success: bool = Field(..., description="Operation success status")
    data: List[TickerItem] = Field(..., description="Scrolling ticker content list")

# Notification schemas
class NotificationRecord(BaseModel):
    notification_id: str = Field(..., description="Notification reference ID")
    type: str = Field(..., description="Category event ID")
    title: str = Field(..., description="Alert title header")
    message: Optional[str] = Field(None, description="Brief notification description")
    severity: str = Field(..., description="Alert severity level")
    is_read: bool = Field(..., description="Mark read status")
    scan_id: Optional[str] = Field(None, description="Linked scan reference ID")
    created_at: str = Field(..., description="Notification creation timestamp")

class NotificationsResponse(BaseModel):
    success: bool = Field(..., description="Operation success status")
    data: List[NotificationRecord] = Field(..., description="List of system notifications")

class UnreadCountResponse(BaseModel):
    success: bool = Field(..., description="Operation success status")
    count: int = Field(..., description="Number of unread notifications remaining")

# Community learning schemas
class CommunityPattern(BaseModel):
    pattern_hash: str = Field(..., description="Unique pattern hash code")
    text_sample: str = Field(..., description="Raw text sample matched")
    category: str = Field(..., description="Scam category taxonomy ID")
    confirmed_count: int = Field(..., description="Times confirmed by community")

class CommunityPatternsResponse(BaseModel):
    success: bool = Field(..., description="Operation success status")
    data: List[CommunityPattern] = Field(..., description="List of community confirmed scam patterns")

class LearnedPattern(BaseModel):
    source: str = Field(..., description="Source of advisory scraped")
    pattern_text: str = Field(..., description="Advisory text pattern")
    category: Optional[str] = Field(None, description="Target category classification")
    keywords: List[str] = Field(..., description="Key tokens extracted")
    severity: str = Field(..., description="Pattern severity level")

class LearnedPatternsResponse(BaseModel):
    success: bool = Field(..., description="Operation success status")
    data: List[LearnedPattern] = Field(..., description="List of automated patterns extracted from scrapers")

# Stats schemas
class StatRecord(BaseModel):
    count: int = Field(..., description="Numeric total value of target statistic")

class SystemStatsResponse(BaseModel):
    success: bool = Field(..., description="Operation success status")
    data: Dict[str, Any] = Field(..., description="Key-value stats data matching dashboard layout")

# Standalone URL verification schemas
class URLCheckRequest(BaseModel):
    url: str = Field(..., description="Target link to check")

class URLCheckResponse(BaseModel):
    success: bool = Field(..., description="Operation success status")
    data: URLThreat = Field(..., description="Calculated URL threat metrics")

class KnownThreatsResponse(BaseModel):
    success: bool = Field(..., description="Operation success status")
    data: List[Dict[str, Any]] = Field(..., description="Known malicious URLs in local database")

class ConfirmRequest(BaseModel):
    scan_id: str = Field(..., description="Linked scan ID")
    verdict: str = Field("SCAM", description="Scam confirmation verdict (SCAM/SAFE)")
    category: Optional[str] = Field(None, description="Scam category taxonomy ID")
    notes: Optional[str] = Field(None, description="User descriptive notes")

class MarkReadRequest(BaseModel):
    notification_ids: Optional[List[str]] = Field(None, description="List of specific notification IDs to mark as read. Null marks all as read.")

class NotificationTestRequest(BaseModel):
    title: str = Field("Test Notification", description="Notification title")
    message: str = Field("Your Sentinel test alert", description="Notification body content")
    severity: str = Field("MODERATE", description="Severity level")

# Administrative diagnostic schemas
class DiagnosticAICheck(BaseModel):
    available: bool = Field(..., description="System key and URL configure status")
    latency_ms: Optional[float] = Field(None, description="Round trip time response in milliseconds")

class DetailedHealthResponse(BaseModel):
    success: bool = Field(..., description="Operation status")
    timestamp: str = Field(..., description="Current UTC timestamp")
    database_ok: bool = Field(..., description="Database pool reachability status")
    ai_system_health: Dict[str, DiagnosticAICheck] = Field(..., description="Detailed availability and roundtrip latency per AI system")

class VersionResponse(BaseModel):
    success: bool = Field(..., description="Operation success")
    app_name: str = Field(..., description="System application name")
    version: str = Field(..., description="Core version number")
    tagline: str = Field(..., description="Marketing description")
    build_environment: str = Field(..., description="Execution environment context")

# ---------------------------------------------------------------------------
# Lifespan background task runner
# ---------------------------------------------------------------------------

async def _periodic_news_scrape() -> None:
    """Runs news scraper every 4 hours automatically to fetch RBS/CERT-IN/PIB advisories."""
    while True:
        try:
            logger.info("Triggering periodic background news scraping task...")
            await asyncio.sleep(config.NEWS_SCRAPE_INTERVAL_HOURS * 3600)
            if db.get_pool():
                await run_full_scrape(db.upsert_news_article, db.add_learned_pattern)
                await db.set_stat("news_articles", {"count": await db.count_news()})
                await _notify_all(
                    "news_update",
                    "News Refreshed",
                    "Latest cybercrime advisories from RBI and CERT-In have been synced.",
                    "MODERATE",
                )
                logger.info("Periodic scrape completed successfully and clients notified.")
        except asyncio.CancelledError:
            logger.info("Scraper background task cancelled.")
            break
        except Exception as exc:
            logger.error("Periodic news scrape background loop error: %s", exc, exc_info=True)

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _scrape_task
    logger.info("Starting %s v%s", config.APP_NAME, config.APP_VERSION)
    try:
        if config.DATABASE_URL:
            logger.info("Attempting to connect to PostgreSQL DSN: %s", config.DATABASE_URL.split("@")[-1])
            await db.init_db(config.DATABASE_URL)
        else:
            logger.error("DATABASE_URL variable not configured. Running degraded.")

        if db.get_pool():
            logger.info("Seeding static reference articles into the news board...")
            await seed_hardcoded_news(db.upsert_news_article)
            await db.set_stat("news_articles", {"count": await db.count_news()})
            _scrape_task = asyncio.create_task(_periodic_news_scrape())
            logger.info("Periodic advisory scraping task scheduled in background.")
    except Exception as exc:
        logger.error("Lifespan initialization error: %s", exc, exc_info=True)
    yield
    if _scrape_task:
        _scrape_task.cancel()
        try:
            await _scrape_task
        except asyncio.CancelledError:
            pass
    await db.close_db()
    logger.info("Sentinel shutdown complete.")

app = FastAPI(
    title=config.APP_NAME,
    version=config.APP_VERSION,
    description=config.APP_TAGLINE,
    lifespan=lifespan,
)

# Enable CORS for frontend cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.middleware("http")(create_timing_middleware())
app.include_router(extended_router)

# Mount frontend assets
if FRONTEND_DIR.exists():
    assets_dir = FRONTEND_DIR / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _notify_all(
    ntype: str,
    title: str,
    message: str,
    severity: str = "MODERATE",
    scan_id: Optional[str] = None,
    metadata: Optional[Dict] = None,
) -> None:
    """Create a database notification record and push to active WebSocket sessions."""
    notif_data = {
        "type": ntype,
        "title": title,
        "message": message,
        "severity": severity,
        "scan_id": scan_id,
        "metadata": metadata or {},
    }
    if db.get_pool():
        try:
            row = await db.create_notification(notif_data)
            notif_data["notification_id"] = row.get("notification_id")
            notif_data["created_at"] = str(row.get("created_at", ""))
            notif_data["is_read"] = False
            logger.debug("Notification %s stored in database.", notif_data["notification_id"])
        except Exception as exc:
            logger.error("Failed to write notification to database: %s", exc)
    await ws_manager.broadcast({"event": "notification", "data": notif_data})

def _serialize_row(row: Optional[Dict]) -> Optional[Dict]:
    """Ensure raw asyncpg row mapping translates dates and JSON payloads cleanly."""
    if not row:
        return None
    out: Dict[str, Any] = {}
    for k, v in row.items():
        if isinstance(v, datetime):
            out[k] = v.isoformat()
        elif isinstance(v, (dict, list)):
            out[k] = v
        else:
            out[k] = v
    return out

async def _run_pipeline(
    text: str,
    image_bytes: Optional[bytes] = None,
    image_filename: str = "",
    image_mime: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes the 4-AI model analysis pipeline.
    Order of execution:
      1. Extract all URLs from input
      2. AI 3 concurrently verifies link threat profiles
      3. AI 2 vision processes uploaded screenshot details
      4. AI 1 local scoring checks context boundaries and fraud mismatch details
      5. AI 2 runs deep text processing contextualized by AI 1/AI 3 findings
      6. AI 1 blends and normalizes risk scores for final unified decision
      7. Background tasks trigger AI 4 Groq forensic reports if needed
    """
    start = time.time()
    combined_text = text or ""

    # Step 1: Extract URLs
    logger.info("[PIPELINE STEP 1] Extracting URLs from source text content...")
    urls = UrlUtils.extract_urls(combined_text)
    logger.info("Found %d URLs for target check.", len(urls))

    # Step 2: AI 3
    logger.info("[PIPELINE STEP 2] Concurrently verifying link safety profiles via SafeBrowsing and VirusTotal...")
    url_results: List[Dict[str, Any]] = []
    if urls:
        url_results = await url_checker.check_urls_concurrent(
            urls,
            get_cache_fn=db.get_cached_url if db.get_pool() else None,
            cache_fn=db.cache_url if db.get_pool() else None,
        )

    # Step 3: AI 2 vision
    logger.info("[PIPELINE STEP 3] Analyzing image attachment via Gemini Vision...")
    vision_result: Dict[str, Any] = {}
    if image_bytes:
        vision_result = await gemini_vision.analyze_image(
            image_bytes, image_filename, image_mime
        )
        extracted = vision_result.get("extracted_text", "")
        if extracted:
            combined_text = f"{combined_text}\n{extracted}".strip()
            # Merge additional URLs found inside image OCR text
            image_urls = UrlUtils.extract_urls(extracted)
            urls = list(dict.fromkeys(urls + image_urls))
            # Scan new URLs
            if image_urls:
                new_urls_res = await url_checker.check_urls_concurrent(
                    image_urls,
                    get_cache_fn=db.get_cached_url if db.get_pool() else None,
                    cache_fn=db.cache_url if db.get_pool() else None,
                )
                url_results = url_results + new_urls_res

    # Step 4: AI 1 local
    logger.info("[PIPELINE STEP 4] Executing Behaviour Engine & Mismatch Detector checks...")
    local = await sentinel_brain.run_local_analysis(combined_text)

    # Step 5: AI 2 deep text
    logger.info("[PIPELINE STEP 5] Running deep contextual text check with Gemini model...")
    text_analysis = await gemini_vision.analyze_text_deep(
        combined_text, behaviour_context=local, url_context=url_results
    )

    # Step 6: Unified verdict
    logger.info("[PIPELINE STEP 6] Blending AI results to calculate unified risk profile...")
    unified = sentinel_brain.compute_unified_verdict(
        combined_text, local, vision_result or text_analysis, url_results
    )
    if text_analysis.get("category") and text_analysis["category"] != "unknown":
        unified["category"] = text_analysis["category"]
    if text_analysis.get("risk_score"):
        blend = (unified["risk_score"] + float(text_analysis["risk_score"])) / 2
        unified["risk_score"] = min(round(blend, 2), 100)
        unified["risk_level"] = config.get_risk_level(unified["risk_score"])

    suspect_phone = text_analysis.get("suspect_phone")
    suspect_upi = text_analysis.get("suspect_upi")
    suspect_website = text_analysis.get("suspect_website")

    duration_ms = int((time.time() - start) * 1000)
    scan_id = config.generate_scan_id()

    result = {
        "scan_id": scan_id,
        "input_text": combined_text[:config.MAX_SCAN_TEXT_LENGTH],
        "input_type": "image" if image_bytes else "text",
        "has_image": bool(image_bytes),
        "image_filename": image_filename or None,
        "risk_score": unified["risk_score"],
        "risk_level": unified["risk_level"],
        "category": unified["category"],
        "verdict": unified["verdict"],
        "is_scam": unified["is_scam"],
        "verify_mode": unified["verify_mode"],
        "behaviour_scores": local.get("behaviour", {}).get("scores", {}),
        "behaviour_triggers": local.get("behaviour", {}).get("triggers", []),
        "mutation_matches": local.get("mutations", []),
        "mismatch_alerts": local.get("mismatches", []),
        "url_threats": url_results,
        "extracted_urls": urls,
        "ai1_result": {"local": local, "unified": unified},
        "ai2_result": {"vision": vision_result, "text": text_analysis},
        "ai3_result": {"urls": url_results},
        "ai4_result": {},
        "unified_verdict": unified,
        "forensic_narrative": text_analysis.get("forensic_narrative", ""),
        "recommended_actions": unified.get("recommended_actions", []),
        "suspect_phone": suspect_phone,
        "suspect_upi": suspect_upi,
        "suspect_website": suspect_website,
        "summary": unified.get("summary", ""),
        "pipeline_duration_ms": duration_ms,
        "verify_steps": config.VERIFY_MODE_STEPS if unified.get("verify_mode") else [],
        "prevention": config.get_prevention_for_category(unified["category"]),
    }
    return result

async def _save_scan_background(scan_data: Dict[str, Any]) -> None:
    try:
        if db.get_pool():
            await db.create_scan(scan_data)
            await db.increment_stat("total_scans")
            if scan_data.get("is_scam"):
                await db.increment_stat("scams_detected")
            if scan_data.get("risk_level") == "CRITICAL":
                await db.increment_stat("critical_alerts")
            if scan_data.get("verify_mode"):
                await db.increment_stat("family_scams")
            for m in scan_data.get("mismatch_alerts", []):
                await db.log_mismatch({**m, "scan_id": scan_data["scan_id"]})
    except Exception as exc:
        logger.error("Background scan save failed for %s: %s", scan_data.get("scan_id"), exc)

async def _notify_scan_background(scan_data: Dict[str, Any]) -> None:
    try:
        score = scan_data.get("risk_score", 0)
        if score >= 75:
            await _notify_all(
                "critical_scan",
                "Critical Threat Detected",
                f"Scan {scan_data['scan_id']}: {score}% risk — {scan_data.get('category', '')}",
                "CRITICAL",
                scan_data["scan_id"],
            )
        if scan_data.get("verify_mode"):
            await _notify_all(
                "family_impersonation",
                "Verify Before Sending Money",
                "Possible family impersonation detected. Use voice verification.",
                "HIGH",
                scan_data["scan_id"],
            )
        for u in scan_data.get("url_threats", []):
            if u.get("is_malicious"):
                await _notify_all(
                    "url_threat",
                    "Malicious URL Detected",
                    f"Threat found: {u.get('url', '')[:80]}",
                    "CRITICAL",
                    scan_data["scan_id"],
                )
                break
    except Exception as exc:
        logger.error("Background notification trigger failed: %s", exc)

async def _generate_narrative_background(scan_id: str, scan_data: Dict[str, Any]) -> None:
    """Generates a detailed legal/forensic narrative summary in the background."""
    try:
        narrative = scan_data.get("forensic_narrative", "")
        # FIX #6: Trigger narrative generation for both is_scam=True AND verify_mode=True
        if report_generator.groq.available() and (scan_data.get("is_scam") or scan_data.get("verify_mode")):
            logger.info("Querying Groq in background for forensic narrative report generation...")
            prompt = (
                f"Write a 400-word forensic case summary for Indian cyber law enforcement. "
                f"Scam Category: {scan_data.get('category')}. Risk Score: {scan_data.get('risk_score')}%. "
                f"Original Message details: {(scan_data.get('input_text') or '')[:1800]}"
            )
            extra = await report_generator.groq.generate(prompt, max_tokens=1024)
            if extra:
                narrative = f"{narrative}\n\n{extra}".strip()
        if db.get_pool():
            await db.update_scan_narrative(
                scan_id, narrative, {"generated": True, "source": "groq_background"}
            )
            logger.info("Forensic report narrative updated in background database record.")
    except Exception as exc:
        logger.error("Background AI 4 narrative compilation error: %s", exc)

# ---------------------------------------------------------------------------
# SCAN ENDPOINTS
# ---------------------------------------------------------------------------

@app.post("/analyze/json", response_model=AnalyzeResponse)
async def analyze_json(
    body: AnalyzeRequest,
    background_tasks: BackgroundTasks,
):
    """
    JSON API scan endpoint. Processes pure text inputs.
    Runs complete 4-AI model analysis and triggers background statistics and alerts.
    """
    text_content = body.text.strip()
    if not text_content:
        logger.warning("Empty scan input text received.")
        raise HTTPException(status_code=400, detail="Input text content must not be blank.")
    
    try:
        # Run pipeline with safety timeout guard
        result = await asyncio.wait_for(_run_pipeline(text_content), timeout=60.0)
        
        # Remove volatile step fields before database serialization
        db_payload = {k: v for k, v in result.items() if k not in ("verify_steps", "prevention")}
        
        background_tasks.add_task(_save_scan_background, db_payload)
        background_tasks.add_task(_notify_scan_background, result)
        background_tasks.add_task(_generate_narrative_background, result["scan_id"], result)
        
        return {"success": True, "data": result}
    except asyncio.TimeoutError:
        logger.error("Pipeline timed out processing text scan.")
        raise HTTPException(status_code=504, detail="AI analysis pipeline request timed out. Please try again.")
    except Exception as exc:
        logger.error("Analyze JSON execution error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Pipeline exception: {str(exc)}")

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(
    background_tasks: BackgroundTasks,
    text: str = Form(""),
    file: Optional[UploadFile] = File(None),
):
    """
    Multipart/form-data upload scan endpoint. Supports text content, files (screenshots, SMS grabs), or both.
    Invokes the full 4-AI pipeline in background orchestration.
    """
    clean_text = text.strip()
    if not clean_text and not file:
        logger.warning("Blank multipart request rejected.")
        raise HTTPException(status_code=400, detail="Must provide either text body or screenshot file.")
    
    image_bytes = None
    image_filename = ""
    image_mime = None
    
    if file:
        image_bytes = await file.read()
        max_bytes = config.MAX_UPLOAD_SIZE_MB * 1024 * 1024
        if len(image_bytes) > max_bytes:
            logger.warning("File size limit exceeded: %d bytes.", len(image_bytes))
            raise HTTPException(status_code=413, detail=f"File exceeds limits. Max size: {config.MAX_UPLOAD_SIZE_MB}MB")
        image_filename = file.filename or "upload.jpg"
        image_mime = file.content_type

    try:
        result = await asyncio.wait_for(
            _run_pipeline(clean_text, image_bytes, image_filename, image_mime),
            timeout=75.0
        )
        
        db_payload = {k: v for k, v in result.items() if k not in ("verify_steps", "prevention")}
        
        background_tasks.add_task(_save_scan_background, db_payload)
        background_tasks.add_task(_notify_scan_background, result)
        background_tasks.add_task(_generate_narrative_background, result["scan_id"], result)
        
        return {"success": True, "data": result}
    except asyncio.TimeoutError:
        logger.error("Multipart pipeline execution timed out.")
        raise HTTPException(status_code=504, detail="Pipeline timed out processing media content.")
    except Exception as exc:
        logger.error("Multipart analyze execution error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal analysis failure: {str(exc)}")

@app.get("/scan/{scan_id}", response_model=ScanRetrievalResponse)
async def get_scan_endpoint(scan_id: str):
    """
    Fetch raw scan logs and analysis results from the database for a target ID.
    Validates scan ID format patterns before executing DB lookup.
    """
    if not re.match(r"^SN-[A-Z0-9]{8}$", scan_id):
        logger.warning("Invalid scan_id format input: %s", scan_id)
        raise HTTPException(status_code=400, detail="Invalid Scan ID format. Must match SN-XXXXXXXX.")
    
    try:
        row = await db.get_scan(scan_id) if db.get_pool() else None
        if not row:
            logger.warning("Scan record %s not found in logs database.", scan_id)
            raise HTTPException(status_code=404, detail="Scan record not found.")
        return {"success": True, "data": _serialize_row(row)}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Scan fetch error for %s: %s", scan_id, exc)
        raise HTTPException(status_code=500, detail=f"Database lookup exception: {str(exc)}")

@app.get("/history", response_model=HistoryResponse)
async def history(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    risk: Optional[str] = None,
):
    """
    Retrieve historical scan records list with support for pagination and risk level filtering.
    """
    try:
        if not db.get_pool():
            return {"success": True, "data": [], "total": 0, "page": page, "per_page": per_page}
        items, total = await db.list_scans(page, per_page, risk)
        serialized = [_serialize_row(i) for i in items]
        return {
            "success": True,
            "data": serialized,
            "total": total,
            "page": page,
            "per_page": per_page,
        }
    except Exception as exc:
        logger.error("History fetch error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Database history collection failed: {str(exc)}")

@app.delete("/scan/{scan_id}", response_model=StandardResponse)
async def delete_scan_endpoint(scan_id: str):
    """
    Permanently delete a scan log from the local database.
    """
    if not re.match(r"^SN-[A-Z0-9]{8}$", scan_id):
        raise HTTPException(status_code=400, detail="Invalid Scan ID structure.")
    
    try:
        if not db.get_pool():
            raise HTTPException(status_code=503, detail="Database connection pool offline.")
        ok = await db.delete_scan(scan_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Scan record not found or already deleted.")
        return {"success": True, "message": f"Scan record {scan_id} deleted successfully."}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Delete scan exception: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to purge scan record.")

@app.get("/export/{scan_id}")
async def export_scan(scan_id: str):
    """
    Download a structured forensic case summary text file (.txt format) for police reporting.
    """
    if not re.match(r"^SN-[A-Z0-9]{8}$", scan_id):
        raise HTTPException(status_code=400, detail="Invalid Scan ID target.")
        
    try:
        row = await db.get_scan(scan_id) if db.get_pool() else None
        if not row:
            raise HTTPException(status_code=404, detail="Target scan record not found.")
        content = scan_to_text(dict(row))
        return PlainTextResponse(
            content,
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.txt"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Export scan exception: %s", exc)
        raise HTTPException(status_code=500, detail="Export conversion failed.")

@app.get("/export-all")
async def export_all():
    """
    Export all scan metrics as a CSV document.
    """
    try:
        if not db.get_pool():
            raise HTTPException(status_code=503, detail="Database services offline.")
        items, _ = await db.list_scans(page=1, per_page=10000)
        csv_content = history_to_csv([dict(i) for i in items])
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="sentinel_history.csv"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("CSV bulk export error: %s", exc)
        raise HTTPException(status_code=500, detail="Bulk export execution failed.")

# ---------------------------------------------------------------------------
# REPORT ENDPOINTS
# ---------------------------------------------------------------------------

@app.post("/report/generate", response_model=ReportGenerateResponse)
async def report_generate(req: ReportGenerateRequest):
    """
    Generate a 7-section legal complaint document.
    Queries Groq Llama AI 4 or falls back to template structures.
    """
    if not re.match(r"^SN-[A-Z0-9]{8}$", req.scan_id) and req.scan_id != "SN-MANUAL":
        raise HTTPException(status_code=400, detail="Scan reference ID must be valid.")
        
    try:
        scan = None
        if db.get_pool():
            scan = await db.get_scan(req.scan_id)
            
        victim = req.model_dump()
        gen = await report_generator.generate_complaint(victim, dict(scan) if scan else None)
        report_id = f"RP-{uuid.uuid4().hex[:8].upper()}"
        
        report_data = {
            "report_id": report_id,
            "scan_id": req.scan_id if req.scan_id != "SN-MANUAL" else None,
            **victim,
            "complaint_text": gen["complaint_text"],
            "complaint_sections": gen["complaint_sections"],
            "generated_by": gen["generated_by"],
        }
        
        if db.get_pool():
            await db.create_report(report_data)
            await db.increment_stat("reports_generated")
            
        return {
            "success": True,
            "data": {
                "report_id": report_id,
                "complaint_preview": gen["complaint_text"][:2000],
                "generated_by": gen["generated_by"],
            },
        }
    except Exception as exc:
        logger.error("Report generate failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to generate complaint: {str(exc)}")

@app.get("/admin/reports")
async def get_admin_reports(request: Request):
    """
    Admin control endpoint to retrieve victim reports.
    Requires Basic authentication with username 'sakshamital' and password 'purva_1234'.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Basic "):
        raise HTTPException(status_code=401, detail="Unauthorized: Authentication required")
    try:
        import base64
        encoded = auth_header.split(" ")[1]
        decoded = base64.b64decode(encoded).decode("utf-8")
        if decoded != "sakshamital:purva_1234":
            raise HTTPException(status_code=401, detail="Unauthorized: Access denied")
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized: Bad token")

    if not db.get_pool():
        raise HTTPException(status_code=503, detail="Database offline.")
    
    try:
        reports = await db.list_reports(limit=100)
        serialized = [_serialize_row(r) for r in reports]
        return {"success": True, "data": serialized}
    except Exception as exc:
        logger.error("Admin reports fetch failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch reports from database")

@app.get("/report/{report_id}", response_model=ReportRetrievalResponse)
async def get_report_endpoint(report_id: str):
    """
    Fetch a compiled victim report by unique ID from the database cell.
    """
    if not re.match(r"^RP-[A-Z0-9]{8}$", report_id):
         raise HTTPException(status_code=400, detail="Invalid Report ID format.")
         
    try:
        if not db.get_pool():
            raise HTTPException(status_code=503, detail="Database offline.")
        row = await db.get_report(report_id)
        if not row:
            raise HTTPException(status_code=404, detail="Complaint report not found.")
        return {"success": True, "data": _serialize_row(row)}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Report retrieval failed: %s", exc)
        raise HTTPException(status_code=500, detail="Database report fetch failed.")

@app.get("/report/download/{report_id}")
async def download_report(report_id: str):
    """
    Retrieve and download the full plain text complaint file matching the legal format.
    """
    if not re.match(r"^RP-[A-Z0-9]{8}$", report_id):
         raise HTTPException(status_code=400, detail="Invalid Report ID.")
         
    try:
        if not db.get_pool():
            raise HTTPException(status_code=503, detail="Database offline.")
        row = await db.get_report(report_id)
        if not row:
            raise HTTPException(status_code=404, detail="Target report not found.")
        name = (row.get("victim_name") or "complaint").replace(" ", "_")
        filename = f"complaint_{name}_{report_id}.txt"
        return PlainTextResponse(
            row.get("complaint_text", ""),
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Report download file stream failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to compose file download stream.")

@app.get("/report/by-scan/{scan_id}", response_model=ReportCheckResponse)
async def report_by_scan(scan_id: str):
    """
    Check if a police complaint report was already generated for a scan.
    """
    if not re.match(r"^SN-[A-Z0-9]{8}$", scan_id):
         raise HTTPException(status_code=400, detail="Invalid Scan ID.")
         
    try:
        if not db.get_pool():
            return {"success": True, "exists": False, "data": None}
        row = await db.get_report_by_scan(scan_id)
        return {
            "success": True,
            "exists": row is not None,
            "data": _serialize_row(row) if row else None,
        }
    except Exception as exc:
        logger.error("Check report link exception: %s", exc)
        raise HTTPException(status_code=500, detail="Database link lookup failed.")

# ---------------------------------------------------------------------------
# NEWS ENDPOINTS
# ---------------------------------------------------------------------------

@app.get("/news", response_model=NewsArticlesResponse)
async def get_news(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, le=100),
):
    """
    Get scam prevention news advisories filtered by category and severity parameters.
    """
    try:
        if db.get_pool():
            articles = await db.list_news(category, severity, limit)
        else:
            articles = HARDCODED_NEWS[:limit]
        return {"success": True, "data": [_serialize_row(a) for a in articles]}
    except Exception as exc:
        logger.error("News load error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to fetch advisory list.")

@app.get("/news/ticker", response_model=TickerResponse)
async def news_ticker():
    """
    Get latest warning entries for layout banner scrolling ticker.
    """
    try:
        if db.get_pool():
            articles = await db.list_news(limit=15)
        else:
            articles = HARDCODED_NEWS
        ticker = [
            {
                "article_id": a.get("article_id"),
                "title": a.get("title"),
                "severity": a.get("severity", "MODERATE"),
            }
            for a in articles
        ]
        return {"success": True, "data": ticker}
    except Exception as exc:
        logger.error("Ticker pull failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to assemble ticker array.")

@app.get("/news/latest", response_model=NewsArticlesResponse)
async def news_latest():
    """
    Retrieve the top 5 warning bulletins.
    """
    try:
        if db.get_pool():
            articles = await db.list_news(limit=5)
        else:
            articles = HARDCODED_NEWS[:5]
        return {"success": True, "data": [_serialize_row(a) for a in articles]}
    except Exception as exc:
        logger.error("Latest news fetch error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to retrieve latest warnings.")

@app.get("/news/search", response_model=NewsArticlesResponse)
async def news_search(q: str = Query(..., min_length=2)):
    """
    Search historical advisories by title or description text keywords.
    """
    search_query = q.strip()
    if not search_query:
        raise HTTPException(status_code=400, detail="Search term must not be blank.")
        
    try:
        if db.get_pool():
            articles = await db.search_news(search_query)
        else:
            articles = [
                a for a in HARDCODED_NEWS
                if search_query.lower() in (a.get("title", "") + a.get("summary", "")).lower()
            ]
        return {"success": True, "data": articles}
    except Exception as exc:
        logger.error("News search query error: %s", exc)
        raise HTTPException(status_code=500, detail="Advisory database search failed.")

@app.post("/news/refresh", response_model=StandardResponse)
async def news_refresh(background_tasks: BackgroundTasks):
    """
    Trigger news board scrape sync task in background.
    """
    try:
        async def _do_scrape():
            if db.get_pool():
                result = await run_full_scrape(db.upsert_news_article, db.add_learned_pattern)
                await _notify_all("news_update", "News Refreshed", f"Scraped {result.get('scraped', 0)} articles")
        background_tasks.add_task(_do_scrape)
        return {"success": True, "message": "News refresh execution started in background."}
    except Exception as exc:
        logger.error("Refresh trigger error: %s", exc)
        raise HTTPException(status_code=500, detail="Scraper background task start failed.")

@app.get("/news/{article_id}", response_model=SingleArticleResponse)
async def get_news_item(article_id: str):
    """
    Retrieve single advisory details and its associated category prevention guides.
    """
    try:
        if db.get_pool():
            article = await db.get_news_article(article_id)
        else:
            article = next((a for a in HARDCODED_NEWS if a["article_id"] == article_id), None)
        if not article:
            raise HTTPException(status_code=404, detail="Advisory article not found.")
        tips = config.get_prevention_for_category(article.get("category", "phishing"))
        return {"success": True, "data": _serialize_row(article), "prevention_tips": tips}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Advisory retrieve exception: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to load article metadata.")

# ---------------------------------------------------------------------------
# NOTIFICATION ENDPOINTS
# ---------------------------------------------------------------------------

@app.get("/notifications", response_model=NotificationsResponse)
async def get_notifications(unread_only: bool = False, limit: int = 50):
    """
    Retrieve active user notification records list.
    """
    try:
        if not db.get_pool():
            return {"success": True, "data": []}
        items = await db.list_notifications(unread_only, limit)
        return {"success": True, "data": [_serialize_row(n) for n in items]}
    except Exception as exc:
        logger.error("Load notifications failed: %s", exc)
        raise HTTPException(status_code=500, detail="Database notification fetch failed.")

@app.get("/notifications/unread-count", response_model=UnreadCountResponse)
async def unread_count():
    """
    Get unread notification records count.
    """
    try:
        count = await db.unread_notification_count() if db.get_pool() else 0
        return {"success": True, "count": count}
    except Exception as exc:
        logger.error("Unread count lookup failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to query database unread metrics.")

@app.post("/notifications/mark-read", response_model=StandardResponse)
async def mark_read(req: MarkReadRequest):
    """
    Mark list of notifications as read. Providing null marks all database entries read.
    """
    try:
      if not db.get_pool():
          return {"success": True, "message": "Mark read complete (degraded)."}
      updated = await db.mark_notifications_read(req.notification_ids)
      return {"success": True, "message": f"Updated {updated} notification records."}
    except Exception as exc:
        logger.error("Mark read command failed: %s", exc)
        raise HTTPException(status_code=500, detail="Database write operation failed.")

@app.post("/notifications/test", response_model=StandardResponse)
async def test_notification(req: NotificationTestRequest):
    """
    Diagnostic endpoint to broadcast test WebSocket notifications.
    """
    try:
        await _notify_all("test", req.title, req.message, req.severity)
        return {"success": True, "message": "WebSocket broadcast test complete."}
    except Exception as exc:
        logger.error("Broadcast test failed: %s", exc)
        raise HTTPException(status_code=500, detail="Test socket emit failed.")

# ---------------------------------------------------------------------------
# COMMUNITY & URL ENDPOINTS
# ---------------------------------------------------------------------------

@app.post("/confirm", response_model=StandardResponse)
async def confirm_scam(req: ConfirmRequest, background_tasks: BackgroundTasks):
    """
    Submit user scam verification to the community pattern database.
    Increases local detection rates via matching keywords.
    """
    if not re.match(r"^SN-[A-Z0-9]{8}$", req.scan_id):
        raise HTTPException(status_code=400, detail="Invalid Scan ID.")
        
    try:
        scan = await db.get_scan(req.scan_id) if db.get_pool() else None
        text = (scan or {}).get("input_text", req.notes or "")
        category = req.category or (scan or {}).get("category", "unknown")
        
        if db.get_pool():
            await db.add_community_pattern(text, category, {"scan_id": req.scan_id, "verdict": req.verdict})
            await db.increment_stat("community_confirmations")
            
        background_tasks.add_task(
            _notify_all,
            "community_confirmation",
            "Community Confirmed Scam",
            f"New verified pattern added for classification: {category}",
            "MODERATE",
            req.scan_id,
        )
        return {"success": True, "message": "Thank you for confirming. Verification added to community database."}
    except Exception as exc:
        logger.error("Community confirm failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to commit community pattern verification.")

@app.get("/community-patterns", response_model=CommunityPatternsResponse)
async def community_patterns():
    """
    Fetch confirmed scam patterns reported by community.
    """
    try:
        patterns = await db.list_community_patterns() if db.get_pool() else []
        return {"success": True, "data": [_serialize_row(p) for p in patterns]}
    except Exception as exc:
        logger.error("Patterns collection failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to fetch community pattern records.")

@app.get("/learned-patterns", response_model=LearnedPatternsResponse)
async def learned_patterns():
    """
    Fetch patterns automatically parsed from scraper feeds.
    """
    try:
        patterns = await db.list_learned_patterns() if db.get_pool() else []
        return {"success": True, "data": [_serialize_row(p) for p in patterns]}
    except Exception as exc:
        logger.error("Learned pattern fetch failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to fetch auto-learned advisory patterns.")

@app.post("/check-url", response_model=URLCheckResponse)
async def check_url_endpoint(req: URLCheckRequest):
    """
    Verify single URL against SafeBrowsing and VirusTotal threat lists.
    """
    target_url = req.url.strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="URL must not be blank.")
        
    try:
        cached = await db.get_cached_url(target_url) if db.get_pool() else None
        result = await url_checker.check_url(target_url, cached)
        if db.get_pool() and not result.get("cached"):
            await db.cache_url({
                "url": target_url,
                "domain": result.get("domain"),
                "is_malicious": result.get("is_malicious"),
                "threat_score": result.get("threat_score"),
                "safe_browsing_result": result.get("safe_browsing", {}),
                "virustotal_result": result.get("virustotal", {}),
                "pattern_result": result.get("pattern", {}),
                "threat_types": result.get("threat_types", []),
            })
        return {"success": True, "data": result}
    except Exception as exc:
        logger.error("Link check failed: %s", exc)
        raise HTTPException(status_code=500, detail="Safe Browsing lookup failed.")

@app.get("/known-threats", response_model=KnownThreatsResponse)
async def known_threats(limit: int = 50):
    """
    Retrieve cached links verified as malicious by AI 3.
    """
    try:
        threats = await db.list_malicious_urls(limit) if db.get_pool() else []
        return {"success": True, "data": [_serialize_row(t) for t in threats]}
    except Exception as exc:
        logger.error("Threat fetch failure: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to fetch threat database.")

# ---------------------------------------------------------------------------
# SYSTEM ENDPOINTS
# ---------------------------------------------------------------------------

@app.get("/stats", response_model=SystemStatsResponse)
async def stats():
    """
    Get dashboard metrics including total scans and scam classifications.
    """
    try:
        data = await db.get_all_stats() if db.get_pool() else {
            "total_scans": {"count": 0},
            "scams_detected": {"count": 0},
        }
        return {"success": True, "data": data}
    except Exception as exc:
        logger.error("Stats compilation failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to compile dashboard metrics.")

@app.get("/official-db")
async def official_db():
    """
    Get official database of verified Indian institutes.
    """
    return {"success": True, "data": config.official_db_json()}

@app.get("/prevention-tips")
async def prevention_tips(category: Optional[str] = None):
    """
    Get category prevention guides.
    """
    if category:
        return {"success": True, "data": config.get_prevention_for_category(category)}
    return {"success": True, "data": config.PREVENTION_TIPS}

@app.get("/scam-categories")
async def scam_categories():
    """
    Get supported scam category list.
    """
    return {"success": True, "data": config.SCAM_CATEGORIES}

@app.get("/health")
async def health():
    """
    Get high-level status indicator checks.
    """
    try:
        db_ok = await db.health_check() if db.get_pool() else False
        return {
            "success": True,
            "status": "healthy" if db_ok or not db.get_pool() else "degraded",
            "version": config.APP_VERSION,
            "ai_status": {
                "ai_layer_1_huggingface": bool(sentinel_brain.hf.api_key and sentinel_brain.hf.api_key != "YOUR_KEY_HERE"),
                "ai_layer_2_gemini_flash": gemini_vision._available(),
                "ai_layer_3_url_checker": bool((url_checker.safe_browsing.api_key and url_checker.safe_browsing.api_key != "YOUR_KEY_HERE") or (url_checker.virustotal.api_key and url_checker.virustotal.api_key != "YOUR_KEY_HERE")),
                "ai_layer_4_groq_report": report_generator.groq.available(),
            },
            "database": db_ok,
            "websocket_connections": len(ws_manager.active),
        }
    except Exception as exc:
        return {"success": False, "status": "unhealthy", "error": str(exc)}

# ---------------------------------------------------------------------------
# ADMIN & DIAGNOSTIC ENDPOINTS (FIX #6)
# ---------------------------------------------------------------------------

@app.get("/health/detailed", response_model=DetailedHealthResponse)
async def health_detailed():
    """
    Admin diagnostic check. Verifies latency profile per AI API backend system.
    """
    db_ok = False
    if db.get_pool():
        try:
            db_ok = await db.health_check()
        except Exception:
            pass

    ai_systems = {
        "HuggingFace Classifier": {"key": sentinel_brain.hf.api_key, "check_fn": lambda: sentinel_brain.hf.classify("Test check payload.")},
        "Gemini Text Deep Analyser": {"key": gemini_vision.api_key, "check_fn": lambda: gemini_vision.analyze_text_deep("Verification check.")},
        "Google Safe Browsing": {"key": url_checker.safe_browsing.api_key, "check_fn": lambda: url_checker.safe_browsing.check("http://google.com")},
        "VirusTotal Lookups": {"key": url_checker.virustotal.api_key, "check_fn": lambda: url_checker.virustotal.check("http://google.com")},
        "Groq Llama Complaint Generator": {"key": report_generator.groq.api_key, "check_fn": lambda: report_generator.groq.generate("Write two words.", max_tokens=10)}
    }

    report: Dict[str, Any] = {}
    for name, data in ai_systems.items():
        is_configured = bool(data["key"] and data["key"] != "YOUR_KEY_HERE")
        latency = None
        if is_configured:
            start = time.perf_counter()
            try:
                # Add strict timeout to ping check
                await asyncio.wait_for(data["check_fn"](), timeout=5.0)
                latency = round((time.perf_counter() - start) * 1000, 2)
            except Exception:
                latency = -1.0 # Error pinging AI backend

        report[name] = {
            "available": is_configured and latency != -1.0,
            "latency_ms": latency if latency is not None else None
        }

    return {
        "success": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database_ok": db_ok,
        "ai_system_health": report
    }

@app.get("/version", response_model=VersionResponse)
async def get_version():
    """
    Retrieve build configuration versioning details.
    """
    return {
        "success": True,
        "app_name": config.APP_NAME,
        "version": config.APP_VERSION,
        "tagline": config.APP_TAGLINE,
        "build_environment": "production" if "production" in config.DATABASE_URL else "development"
    }

@app.get("/scan/{scan_id}/similar", response_model=List[ScanSummary])
async def get_similar_scans(scan_id: str, limit: int = Query(5, ge=1, le=20)):
    """
    Find other scan logs belonging to the same scam taxonomy classification category.
    """
    if not re.match(r"^SN-[A-Z0-9]{8}$", scan_id):
        raise HTTPException(status_code=400, detail="Invalid Scan ID format.")

    if not db.get_pool():
         raise HTTPException(status_code=503, detail="Database services offline.")

    try:
        scan = await db.get_scan(scan_id)
        if not scan:
             raise HTTPException(status_code=404, detail="Original scan record not found.")

        category = scan.get("category", "unknown")
        pool = db.get_pool()
        async with pool.acquire() as conn:
             rows = await conn.fetch(
                 """
                 SELECT scan_id, risk_score, risk_level, category, verdict,
                        is_scam, verify_mode, summary, created_at
                 FROM scan_logs
                 WHERE category = $1 AND scan_id != $2
                 ORDER BY created_at DESC LIMIT $3
                 """,
                 category, scan_id, limit
             )
        return [_serialize_row(r) for r in rows]
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to fetch similar scans for %s: %s", scan_id, exc)
        raise HTTPException(status_code=500, detail="Database query error fetching similarity mappings.")

# ---------------------------------------------------------------------------
# WEBSOCKET
# ---------------------------------------------------------------------------

@app.websocket("/ws/notifications")
async def websocket_notifications(websocket: WebSocket):
    """
    WebSocket connection endpoint. Maintains active session.
    Automatically responds to ping keepalives to prevent connection drop.
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.warning("WebSocket error connection state: %s", exc)
        ws_manager.disconnect(websocket)

# ---------------------------------------------------------------------------
# FRONTEND PAGES
# ---------------------------------------------------------------------------

@app.get("/")
async def serve_index():
    """Serve index.html landing page."""
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return PlainTextResponse("Your Sentinel API — frontend not found", status_code=404)

@app.get("/report")
async def serve_report_page():
    """Serve report.html police generator form page."""
    report_path = FRONTEND_DIR / "report.html"
    if report_path.exists():
        return FileResponse(str(report_path))
    raise HTTPException(404, "report.html not found")

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=config.HOST,
        port=config.PORT,
        reload=config.DEBUG,
    )
