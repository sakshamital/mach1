"""
YOUR SENTINEL — Extended API routes and middleware helpers.

Supplementary endpoints: JSON analyze, batch URL check, scan search,
pipeline info, analytics, institution lookup, and request utilities.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from pydantic import BaseModel, Field

import config
from ai.url_checker import URLChecker, UrlUtils
from database import db

logger = logging.getLogger("SENTINEL.API_ROUTES")

router = APIRouter(tags=["Extended"])


class AnalyzeJSONRequest(BaseModel):
    text: str = Field(..., max_length=50000)


class BatchURLRequest(BaseModel):
    urls: List[str] = Field(..., min_length=1, max_length=20)


class ScanSearchQuery(BaseModel):
    q: str = Field(..., min_length=2)


# ---------------------------------------------------------------------------
# Pipeline & system info
# ---------------------------------------------------------------------------


@router.get("/pipeline/steps")
async def pipeline_steps() -> Dict[str, Any]:
    """Return ordered AI pipeline step labels for UI progress."""
    return {
        "success": True,
        "steps": config.PIPELINE_STEPS,
        "version": config.APP_VERSION,
    }


@router.get("/system/info")
async def system_info() -> Dict[str, Any]:
    """Application metadata and feature flags."""
    return {
        "success": True,
        "name": config.APP_NAME,
        "version": config.APP_VERSION,
        "tagline": config.APP_TAGLINE,
        "risk_thresholds": config.RISK_THRESHOLDS,
        "max_scan_text_length": config.MAX_SCAN_TEXT_LENGTH,
        "news_scrape_interval_hours": config.NEWS_SCRAPE_INTERVAL_HOURS,
        "institution_count": len(config.OFFICIAL_INDIA_DB),
        "scam_category_count": len(config.SCAM_CATEGORIES),
        "behaviour_pattern_count": len(config.BEHAVIOUR_PATTERNS),
        "mutation_template_count": len(config.MUTATION_TEMPLATES),
    }


@router.get("/official-db/{institution_id}")
async def official_institution(institution_id: str) -> Dict[str, Any]:
    """Single institution from Official India DB."""
    key = institution_id.upper()
    inst = config.OFFICIAL_INDIA_DB.get(key)
    if not inst:
        raise HTTPException(404, f"Institution '{institution_id}' not found")
    return {
        "success": True,
        "data": {
            "id": inst.id,
            "short_name": inst.short_name,
            "full_name": inst.full_name,
            "websites": inst.websites,
            "phones": inst.phones,
            "emails": inst.emails,
            "apps": inst.apps,
            "note": inst.note,
        },
    }


@router.get("/verify-guide")
async def verify_guide() -> Dict[str, Any]:
    """50-50 verify mode steps for family impersonation scams."""
    return {
        "success": True,
        "title": "50-50 Verify Mode",
        "steps": config.VERIFY_MODE_STEPS,
        "helpline": "1930",
    }


# ---------------------------------------------------------------------------
# Analytics (DB-backed when available)
# ---------------------------------------------------------------------------


@router.get("/analytics/summary")
async def analytics_summary() -> Dict[str, Any]:
    """Dashboard analytics aggregate."""
    try:
        stats = await db.get_all_stats() if db.get_pool() else {}
        return {
            "success": True,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "stats": stats,
            "categories_available": len(config.SCAM_CATEGORIES),
        }
    except Exception as exc:
        logger.error("analytics_summary: %s", exc)
        raise HTTPException(500, str(exc))


@router.get("/analytics/risk-distribution")
async def risk_distribution() -> Dict[str, Any]:
    """Count scans by risk level."""
    distribution = {"LOW": 0, "MODERATE": 0, "HIGH": 0, "CRITICAL": 0}
    if not db.get_pool():
        return {"success": True, "data": distribution, "source": "empty"}
    try:
        pool = db.get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT risk_level, COUNT(*) as cnt FROM scan_logs
                GROUP BY risk_level
                """
            )
            for row in rows:
                level = row["risk_level"] or "LOW"
                if level in distribution:
                    distribution[level] = row["cnt"]
        return {"success": True, "data": distribution}
    except Exception as exc:
        logger.error("risk_distribution: %s", exc)
        raise HTTPException(500, str(exc))


# ---------------------------------------------------------------------------
# Scan search & batch URL
# ---------------------------------------------------------------------------


@router.get("/scan/search")
async def search_scans(
    q: str = Query(..., min_length=2),
    limit: int = Query(20, le=50),
) -> Dict[str, Any]:
    """Search scan history by scan_id or summary text."""
    if not db.get_pool():
        return {"success": True, "data": [], "total": 0}
    try:
        pattern = f"%{q}%"
        pool = db.get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT scan_id, risk_score, risk_level, category, verdict,
                       is_scam, summary, created_at
                FROM scan_logs
                WHERE scan_id ILIKE $1 OR summary ILIKE $1 OR input_text ILIKE $1
                ORDER BY created_at DESC LIMIT $2
                """,
                pattern,
                limit,
            )
            data = [dict(r) for r in rows]
        return {"success": True, "data": data, "total": len(data)}
    except Exception as exc:
        logger.error("search_scans: %s", exc)
        raise HTTPException(500, str(exc))


@router.post("/check-urls/batch")
async def batch_check_urls(req: BatchURLRequest) -> Dict[str, Any]:
    """Check up to 20 URLs concurrently."""
    checker = URLChecker()
    results = await checker.check_urls_concurrent(
        req.urls[:20],
        get_cache_fn=db.get_cached_url if db.get_pool() else None,
        cache_fn=db.cache_url if db.get_pool() else None,
    )
    malicious = sum(1 for r in results if r.get("is_malicious"))
    return {
        "success": True,
        "data": results,
        "total": len(results),
        "malicious_count": malicious,
    }


@router.post("/extract-urls")
async def extract_urls_endpoint(req: AnalyzeJSONRequest) -> Dict[str, Any]:
    """Extract URLs from text without full scan."""
    urls = UrlUtils.extract_urls(req.text)
    return {"success": True, "urls": urls, "count": len(urls)}


# ---------------------------------------------------------------------------
# News helpers
# ---------------------------------------------------------------------------


@router.get("/news/categories")
async def news_categories() -> Dict[str, Any]:
    """Distinct news categories in database."""
    categories = list({c["id"] for c in config.SCAM_CATEGORIES})
    return {"success": True, "data": categories}


@router.get("/news/hardcoded")
async def news_hardcoded() -> Dict[str, Any]:
    """Return 18 seeded hardcoded articles (no DB required)."""
    from scrapers.news_scraper import HARDCODED_NEWS
    return {"success": True, "data": HARDCODED_NEWS, "count": len(HARDCODED_NEWS)}


# ---------------------------------------------------------------------------
# Community helpers
# ---------------------------------------------------------------------------


@router.get("/community/stats")
async def community_stats() -> Dict[str, Any]:
    """Community learning statistics."""
    if not db.get_pool():
        return {"success": True, "pattern_count": 0, "total_confirmations": 0}
    try:
        patterns = await db.list_community_patterns(limit=500)
        total_conf = sum(p.get("confirmed_count", 1) for p in patterns)
        return {
            "success": True,
            "pattern_count": len(patterns),
            "total_confirmations": total_conf,
            "top_patterns": [
                {
                    "category": p.get("category"),
                    "count": p.get("confirmed_count"),
                    "sample": (p.get("text_sample") or "")[:80],
                }
                for p in patterns[:5]
            ],
        }
    except Exception as exc:
        raise HTTPException(500, str(exc))


# ---------------------------------------------------------------------------
# Reports list
# ---------------------------------------------------------------------------


@router.get("/reports")
async def list_reports(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
) -> Dict[str, Any]:
    """List generated victim reports."""
    if not db.get_pool():
        return {"success": True, "data": [], "total": 0}
    try:
        offset = (page - 1) * per_page
        pool = db.get_pool()
        async with pool.acquire() as conn:
            total = await conn.fetchval("SELECT COUNT(*) FROM victim_reports")
            rows = await conn.fetch(
                """
                SELECT report_id, scan_id, victim_name, victim_mobile,
                       amount_lost, status, created_at
                FROM victim_reports ORDER BY created_at DESC
                LIMIT $1 OFFSET $2
                """,
                per_page,
                offset,
            )
        return {
            "success": True,
            "data": [dict(r) for r in rows],
            "total": int(total or 0),
            "page": page,
        }
    except Exception as exc:
        raise HTTPException(500, str(exc))


# ---------------------------------------------------------------------------
# Middleware factory
# ---------------------------------------------------------------------------


def create_timing_middleware():
    """Log request duration for monitoring."""

    async def timing_middleware(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - start) * 1000
        if not request.url.path.startswith("/assets"):
            logger.debug(
                "%s %s -> %s (%.1fms)",
                request.method,
                request.url.path,
                response.status_code,
                elapsed_ms,
            )
        response.headers["X-Response-Time-Ms"] = f"{elapsed_ms:.1f}"
        response.headers["X-Sentinel-Version"] = config.APP_VERSION
        return response

    return timing_middleware
