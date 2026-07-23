"""
YOUR SENTINEL v8.0 — Main FastAPI Application.

All REST endpoints, WebSocket notifications, 4-AI scan pipeline,
background tasks, static frontend serving, and system orchestration.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from fastapi import (
    BackgroundTasks,
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
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
# Pydantic models
# ---------------------------------------------------------------------------


class AnalyzeRequest(BaseModel):
    text: str = Field(default="", max_length=50000)


class ReportGenerateRequest(BaseModel):
    scan_id: str
    victim_name: str
    victim_mobile: str
    victim_email: Optional[str] = None
    victim_address: Optional[str] = None
    victim_city: Optional[str] = None
    victim_state: Optional[str] = None
    victim_pin: Optional[str] = None
    id_proof_type: Optional[str] = None
    id_proof_number: Optional[str] = None
    incident_date: Optional[str] = None
    incident_time: Optional[str] = None
    amount_lost: Optional[float] = 0
    payment_method: Optional[str] = None
    incident_details: Optional[str] = None
    suspect_phone: Optional[str] = None
    suspect_upi: Optional[str] = None
    suspect_website: Optional[str] = None
    suspect_details: Optional[str] = None


class ConfirmRequest(BaseModel):
    scan_id: str
    verdict: str = "SCAM"
    category: Optional[str] = None
    notes: Optional[str] = None


class MarkReadRequest(BaseModel):
    notification_ids: Optional[List[str]] = None


class URLCheckRequest(BaseModel):
    url: str


class NotificationTestRequest(BaseModel):
    title: str = "Test Notification"
    message: str = "Your Sentinel test alert"
    severity: str = "MODERATE"


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


async def _periodic_news_scrape() -> None:
    while True:
        try:
            await asyncio.sleep(config.NEWS_SCRAPE_INTERVAL_HOURS * 3600)
            if db.get_pool():
                await run_full_scrape(db.upsert_news_article, db.add_learned_pattern)
                await db.set_stat("news_articles", {"count": await db.count_news()})
                await _notify_all(
                    "news_update",
                    "News Updated",
                    "Latest cybercrime advisories have been refreshed.",
                    "MODERATE",
                )
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("Periodic scrape error: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _scrape_task
    logger.info("Starting %s v%s", config.APP_NAME, config.APP_VERSION)
    try:
        if config.DATABASE_URL and "localhost" not in config.DATABASE_URL:
            await db.init_db(config.DATABASE_URL)
        else:
            try:
                await db.init_db(config.DATABASE_URL)
            except Exception as exc:
                logger.warning("DB init failed (running without DB): %s", exc)
        if db.get_pool():
            await seed_hardcoded_news(db.upsert_news_article)
            await db.set_stat("news_articles", {"count": await db.count_news()})
            _scrape_task = asyncio.create_task(_periodic_news_scrape())
    except Exception as exc:
        logger.error("Startup error: %s", exc)
    yield
    if _scrape_task:
        _scrape_task.cancel()
    await db.close_db()
    logger.info("Shutdown complete")


app = FastAPI(
    title=config.APP_NAME,
    version=config.APP_VERSION,
    description=config.APP_TAGLINE,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.middleware("http")(create_timing_middleware())
app.include_router(extended_router)

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
    """Create DB notification and broadcast via WebSocket."""
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
        except Exception as exc:
            logger.warning("create_notification: %s", exc)
    await ws_manager.broadcast({"event": "notification", "data": notif_data})


def _serialize_row(row: Optional[Dict]) -> Optional[Dict]:
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
    Full 4-AI pipeline in specified order:
    1. Extract URLs
    2. AI 3 URL check
    3. AI 2 vision (if image)
    4. AI 1 local behaviour + mismatch
    5. AI 2 deep text
    6. AI 1 unified verdict
    7. Prepare AI 4 context (narrative in background)
    """
    start = time.time()
    combined_text = text or ""

    # Step 1: Extract URLs
    urls = UrlUtils.extract_urls(combined_text)

    # Step 2: AI 3
    url_results: List[Dict[str, Any]] = []
    if urls:
        url_results = await url_checker.check_urls_concurrent(
            urls,
            get_cache_fn=db.get_cached_url if db.get_pool() else None,
            cache_fn=db.cache_url if db.get_pool() else None,
        )
        if db.get_pool():
            await db.increment_stat("urls_checked", len(urls))

    # Step 3: AI 2 vision
    vision_result: Dict[str, Any] = {}
    if image_bytes:
        vision_result = await gemini_vision.analyze_image(
            image_bytes, image_filename, image_mime
        )
        extracted = vision_result.get("extracted_text", "")
        if extracted:
            combined_text = f"{combined_text}\n{extracted}".strip()
            urls = list(dict.fromkeys(urls + UrlUtils.extract_urls(extracted)))
            if urls and not url_results:
                url_results = await url_checker.check_urls_concurrent(urls)

    # Step 4: AI 1 local
    local = await sentinel_brain.run_local_analysis(combined_text)

    # Step 5: AI 2 deep text
    ctx = gemini_vision.build_context_payload(local, url_results)
    text_analysis = await gemini_vision.analyze_text_deep(
        combined_text, behaviour_context=local, url_context=url_results
    )

    # Step 6: Unified verdict
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
        logger.error("save_scan_background: %s", exc)


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
        logger.error("notify_scan_background: %s", exc)


async def _generate_narrative_background(scan_id: str, scan_data: Dict[str, Any]) -> None:
    try:
        narrative = scan_data.get("forensic_narrative", "")
        if report_generator.groq.available() and scan_data.get("is_scam"):
            prompt = (
                f"Write 400 words forensic narrative for Indian cybercrime case. "
                f"Category: {scan_data.get('category')}. Risk: {scan_data.get('risk_score')}%. "
                f"Text: {(scan_data.get('input_text') or '')[:2000]}"
            )
            extra = await report_generator.groq.generate(prompt, max_tokens=1024)
            if extra:
                narrative = f"{narrative}\n\n{extra}"
        if db.get_pool():
            await db.update_scan_narrative(
                scan_id, narrative, {"generated": True, "source": "groq_background"}
            )
    except Exception as exc:
        logger.error("narrative_background: %s", exc)


# ---------------------------------------------------------------------------
# SCAN ENDPOINTS
# ---------------------------------------------------------------------------


@app.post("/analyze/json")
async def analyze_json(
    body: AnalyzeRequest,
    background_tasks: BackgroundTasks,
):
    """JSON body variant of main scan (text only, no file upload)."""
    try:
        if not body.text.strip():
            raise HTTPException(400, "text field is required")
        result = await _run_pipeline(body.text)
        db_payload = {k: v for k, v in result.items() if k not in ("verify_steps", "prevention")}
        background_tasks.add_task(_save_scan_background, db_payload)
        background_tasks.add_task(_notify_scan_background, result)
        background_tasks.add_task(_generate_narrative_background, result["scan_id"], result)
        return {"success": True, "data": result}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("analyze_json failed: %s", exc)
        raise HTTPException(500, f"Analysis failed: {exc}")


@app.post("/analyze")
async def analyze(
    background_tasks: BackgroundTasks,
    text: str = Form(""),
    file: Optional[UploadFile] = File(None),
):
    """Main scan endpoint — runs full 4-AI pipeline."""
    try:
        if not text and not file:
            raise HTTPException(400, "Provide text or image to analyze")
        image_bytes = None
        image_filename = ""
        image_mime = None
        if file:
            image_bytes = await file.read()
            if len(image_bytes) > config.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
                raise HTTPException(413, "File too large")
            image_filename = file.filename or "upload.jpg"
            image_mime = file.content_type
        result = await _run_pipeline(text, image_bytes, image_filename, image_mime)
        db_payload = {k: v for k, v in result.items() if k not in (
            "verify_steps", "prevention",
        )}
        background_tasks.add_task(_save_scan_background, db_payload)
        background_tasks.add_task(_notify_scan_background, result)
        background_tasks.add_task(_generate_narrative_background, result["scan_id"], result)
        return {"success": True, "data": result}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("analyze failed: %s", exc)
        raise HTTPException(500, f"Analysis failed: {exc}")


@app.get("/scan/{scan_id}")
async def get_scan_endpoint(scan_id: str):
    try:
        row = await db.get_scan(scan_id) if db.get_pool() else None
        if not row:
            raise HTTPException(404, "Scan not found")
        return {"success": True, "data": _serialize_row(row)}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.get("/history")
async def history(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    risk: Optional[str] = None,
):
    try:
        if not db.get_pool():
            return {"success": True, "data": [], "total": 0, "page": page}
        items, total = await db.list_scans(page, per_page, risk)
        return {
            "success": True,
            "data": [_serialize_row(i) for i in items],
            "total": total,
            "page": page,
            "per_page": per_page,
        }
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.delete("/scan/{scan_id}")
async def delete_scan_endpoint(scan_id: str):
    try:
        if not db.get_pool():
            raise HTTPException(503, "Database unavailable")
        ok = await db.delete_scan(scan_id)
        if not ok:
            raise HTTPException(404, "Scan not found")
        return {"success": True, "message": "Deleted"}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.get("/export/{scan_id}")
async def export_scan(scan_id: str):
    try:
        row = await db.get_scan(scan_id) if db.get_pool() else None
        if not row:
            raise HTTPException(404, "Scan not found")
        content = scan_to_text(dict(row))
        return PlainTextResponse(
            content,
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.txt"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.get("/export-all")
async def export_all():
    try:
        if not db.get_pool():
            raise HTTPException(503, "Database unavailable")
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
        raise HTTPException(500, str(exc))


# ---------------------------------------------------------------------------
# REPORT ENDPOINTS
# ---------------------------------------------------------------------------


@app.post("/report/generate")
async def report_generate(req: ReportGenerateRequest):
    try:
        scan = None
        if db.get_pool():
            scan = await db.get_scan(req.scan_id)
        victim = req.model_dump()
        gen = await report_generator.generate_complaint(victim, dict(scan) if scan else None)
        report_id = f"RP-{uuid.uuid4().hex[:8].upper()}"
        report_data = {
            "report_id": report_id,
            "scan_id": req.scan_id,
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
        logger.error("report_generate: %s", exc)
        raise HTTPException(500, str(exc))


@app.get("/report/{report_id}")
async def get_report_endpoint(report_id: str):
    try:
        if not db.get_pool():
            raise HTTPException(503, "Database unavailable")
        row = await db.get_report(report_id)
        if not row:
            raise HTTPException(404, "Report not found")
        return {"success": True, "data": _serialize_row(row)}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.get("/report/download/{report_id}")
async def download_report(report_id: str):
    try:
        if not db.get_pool():
            raise HTTPException(503, "Database unavailable")
        row = await db.get_report(report_id)
        if not row:
            raise HTTPException(404, "Report not found")
        name = (row.get("victim_name") or "complaint").replace(" ", "_")
        filename = f"complaint_{name}_{report_id}.txt"
        return PlainTextResponse(
            row.get("complaint_text", ""),
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.get("/report/by-scan/{scan_id}")
async def report_by_scan(scan_id: str):
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
        raise HTTPException(500, str(exc))


# ---------------------------------------------------------------------------
# NEWS ENDPOINTS
# ---------------------------------------------------------------------------


@app.get("/news")
async def get_news(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, le=100),
):
    try:
        if db.get_pool():
            articles = await db.list_news(category, severity, limit)
        else:
            articles = HARDCODED_NEWS[:limit]
        return {"success": True, "data": [_serialize_row(a) for a in articles]}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.get("/news/ticker")
async def news_ticker():
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
        raise HTTPException(500, str(exc))


@app.get("/news/latest")
async def news_latest():
    try:
        if db.get_pool():
            articles = await db.list_news(limit=5)
        else:
            articles = HARDCODED_NEWS[:5]
        return {"success": True, "data": [_serialize_row(a) for a in articles]}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.get("/news/search")
async def news_search(q: str = Query(..., min_length=2)):
    try:
        if db.get_pool():
            articles = await db.search_news(q)
        else:
            articles = [
                a for a in HARDCODED_NEWS
                if q.lower() in (a.get("title", "") + a.get("summary", "")).lower()
            ]
        return {"success": True, "data": articles}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/news/refresh")
async def news_refresh(background_tasks: BackgroundTasks):
    try:
        async def _do_scrape():
            if db.get_pool():
                result = await run_full_scrape(db.upsert_news_article, db.add_learned_pattern)
                await _notify_all("news_update", "News Refreshed", f"Scraped {result.get('scraped', 0)} articles")
        background_tasks.add_task(_do_scrape)
        return {"success": True, "message": "News refresh started in background"}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.get("/news/{article_id}")
async def get_news_item(article_id: str):
    try:
        if db.get_pool():
            article = await db.get_news_article(article_id)
        else:
            article = next((a for a in HARDCODED_NEWS if a["article_id"] == article_id), None)
        if not article:
            raise HTTPException(404, "Article not found")
        tips = config.get_prevention_for_category(article.get("category", "phishing"))
        return {"success": True, "data": _serialize_row(article), "prevention_tips": tips}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, str(exc))


# ---------------------------------------------------------------------------
# NOTIFICATION ENDPOINTS
# ---------------------------------------------------------------------------


@app.get("/notifications")
async def get_notifications(unread_only: bool = False, limit: int = 50):
    try:
        if not db.get_pool():
            return {"success": True, "data": []}
        items = await db.list_notifications(unread_only, limit)
        return {"success": True, "data": [_serialize_row(n) for n in items]}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.get("/notifications/unread-count")
async def unread_count():
    try:
        count = await db.unread_notification_count() if db.get_pool() else 0
        return {"success": True, "count": count}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/notifications/mark-read")
async def mark_read(req: MarkReadRequest):
    try:
        if not db.get_pool():
            return {"success": True, "updated": 0}
        updated = await db.mark_notifications_read(req.notification_ids)
        return {"success": True, "updated": updated}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/notifications/test")
async def test_notification(req: NotificationTestRequest):
    try:
        await _notify_all("test", req.title, req.message, req.severity)
        return {"success": True, "message": "Test notification sent"}
    except Exception as exc:
        raise HTTPException(500, str(exc))


# ---------------------------------------------------------------------------
# COMMUNITY & URL ENDPOINTS
# ---------------------------------------------------------------------------


@app.post("/confirm")
async def confirm_scam(req: ConfirmRequest, background_tasks: BackgroundTasks):
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
            f"Pattern added for category: {category}",
            "MODERATE",
            req.scan_id,
        )
        return {"success": True, "message": "Thank you — pattern added to community learning"}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.get("/community-patterns")
async def community_patterns():
    try:
        patterns = await db.list_community_patterns() if db.get_pool() else []
        return {"success": True, "data": [_serialize_row(p) for p in patterns]}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.get("/learned-patterns")
async def learned_patterns():
    try:
        patterns = await db.list_learned_patterns() if db.get_pool() else []
        return {"success": True, "data": [_serialize_row(p) for p in patterns]}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/check-url")
async def check_url_endpoint(req: URLCheckRequest):
    try:
        cached = await db.get_cached_url(req.url) if db.get_pool() else None
        result = await url_checker.check_url(req.url, cached)
        if db.get_pool() and not result.get("cached"):
            await db.cache_url({
                "url": req.url,
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
        raise HTTPException(500, str(exc))


@app.get("/known-threats")
async def known_threats(limit: int = 50):
    try:
        threats = await db.list_malicious_urls(limit) if db.get_pool() else []
        return {"success": True, "data": [_serialize_row(t) for t in threats]}
    except Exception as exc:
        raise HTTPException(500, str(exc))


# ---------------------------------------------------------------------------
# SYSTEM ENDPOINTS
# ---------------------------------------------------------------------------


@app.get("/stats")
async def stats():
    try:
        data = await db.get_all_stats() if db.get_pool() else {
            "total_scans": {"count": 0},
            "scams_detected": {"count": 0},
        }
        return {"success": True, "data": data}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.get("/official-db")
async def official_db():
    return {"success": True, "data": config.official_db_json()}


@app.get("/prevention-tips")
async def prevention_tips(category: Optional[str] = None):
    if category:
        return {"success": True, "data": config.get_prevention_for_category(category)}
    return {"success": True, "data": config.PREVENTION_TIPS}


@app.get("/scam-categories")
async def scam_categories():
    return {"success": True, "data": config.SCAM_CATEGORIES}


@app.get("/health")
async def health():
    try:
        db_ok = await db.health_check() if db.get_pool() else False
        return {
            "success": True,
            "status": "healthy" if db_ok or not db.get_pool() else "degraded",
            "version": config.APP_VERSION,
            "ai_status": {
                "ai1_huggingface": sentinel_brain.hf.api_key != "YOUR_KEY_HERE",
                "ai1_behaviour_engine": True,
                "ai1_mismatch_detector": True,
                "ai2_gemini": gemini_vision._available(),
                "ai3_safe_browsing": url_checker.safe_browsing.available(),
                "ai3_virustotal": url_checker.virustotal.available(),
                "ai3_pattern_fallback": True,
                "ai4_groq": report_generator.groq.available(),
            },
            "database": db_ok,
            "websocket_connections": len(ws_manager.active),
        }
    except Exception as exc:
        return {"success": False, "status": "unhealthy", "error": str(exc)}


# ---------------------------------------------------------------------------
# WEBSOCKET
# ---------------------------------------------------------------------------


@app.websocket("/ws/notifications")
async def websocket_notifications(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.warning("WebSocket error: %s", exc)
        ws_manager.disconnect(websocket)


# ---------------------------------------------------------------------------
# FRONTEND PAGES
# ---------------------------------------------------------------------------


@app.get("/")
async def serve_index():
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return PlainTextResponse("Your Sentinel API — frontend not found", status_code=404)


@app.get("/report")
async def serve_report_page():
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
