"""
YOUR SENTINEL — Async PostgreSQL database layer.

Provides connection pool management and complete CRUD operations
for all tables: scan_logs, victim_reports, known_urls, community_patterns,
learned_patterns, news_articles, notifications, mismatch_log, system_stats.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import asyncpg

from database.models import SCHEMA_SQL

logger = logging.getLogger("SENTINEL.DATABASE")

_pool: Optional[asyncpg.Pool] = None


async def init_db(database_url: str) -> asyncpg.Pool:
    """Initialize connection pool and ensure schema exists."""
    global _pool
    try:
        dsn = database_url
        if dsn.startswith("postgres://"):
            dsn = dsn.replace("postgres://", "postgresql://", 1)
        _pool = await asyncpg.create_pool(
            dsn,
            min_size=1,
            max_size=10,
            command_timeout=60,
        )
        async with _pool.acquire() as conn:
            await conn.execute(SCHEMA_SQL)
        logger.info("Database pool initialized and schema applied")
        return _pool
    except Exception as exc:
        logger.error("Database init failed: %s", exc)
        raise


async def close_db() -> None:
    """Close connection pool."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None
        logger.info("Database pool closed")


def get_pool() -> Optional[asyncpg.Pool]:
    return _pool


async def health_check() -> bool:
    """Return True if database is reachable."""
    if not _pool:
        return False
    try:
        async with _pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return True
    except Exception as exc:
        logger.warning("DB health check failed: %s", exc)
        return False


def _json(val: Any) -> str:
    return json.dumps(val if val is not None else {})


# ---------------------------------------------------------------------------
# Scan logs
# ---------------------------------------------------------------------------


async def create_scan(data: Dict[str, Any]) -> Dict[str, Any]:
    """Insert new scan log record."""
    if not _pool:
        raise RuntimeError("Database not initialized")
    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO scan_logs (
                    scan_id, input_text, input_type, has_image, image_filename,
                    risk_score, risk_level, category, verdict, is_scam, verify_mode,
                    behaviour_scores, behaviour_triggers, mutation_matches,
                    mismatch_alerts, url_threats, extracted_urls,
                    ai1_result, ai2_result, ai3_result, ai4_result,
                    unified_verdict, forensic_narrative, recommended_actions,
                    suspect_phone, suspect_upi, suspect_website, summary,
                    pipeline_duration_ms
                ) VALUES (
                    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,
                    $12::jsonb,$13::jsonb,$14::jsonb,$15::jsonb,$16::jsonb,$17::jsonb,
                    $18::jsonb,$19::jsonb,$20::jsonb,$21::jsonb,
                    $22::jsonb,$23,$24::jsonb,$25,$26,$27,$28,$29
                ) RETURNING *
                """,
                data.get("scan_id"),
                data.get("input_text"),
                data.get("input_type", "text"),
                data.get("has_image", False),
                data.get("image_filename"),
                data.get("risk_score", 0),
                data.get("risk_level", "LOW"),
                data.get("category", "unknown"),
                data.get("verdict", "UNKNOWN"),
                data.get("is_scam", False),
                data.get("verify_mode", False),
                _json(data.get("behaviour_scores", {})),
                _json(data.get("behaviour_triggers", [])),
                _json(data.get("mutation_matches", [])),
                _json(data.get("mismatch_alerts", [])),
                _json(data.get("url_threats", [])),
                _json(data.get("extracted_urls", [])),
                _json(data.get("ai1_result", {})),
                _json(data.get("ai2_result", {})),
                _json(data.get("ai3_result", {})),
                _json(data.get("ai4_result", {})),
                _json(data.get("unified_verdict", {})),
                data.get("forensic_narrative"),
                _json(data.get("recommended_actions", [])),
                data.get("suspect_phone"),
                data.get("suspect_upi"),
                data.get("suspect_website"),
                data.get("summary"),
                data.get("pipeline_duration_ms", 0),
            )
            return dict(row)
    except Exception as exc:
        logger.error("create_scan failed: %s", exc)
        raise


async def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    if not _pool:
        return None
    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM scan_logs WHERE scan_id = $1", scan_id
            )
            return dict(row) if row else None
    except Exception as exc:
        logger.error("get_scan failed: %s", exc)
        return None


async def delete_scan(scan_id: str) -> bool:
    if not _pool:
        return False
    try:
        async with _pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM scan_logs WHERE scan_id = $1", scan_id
            )
            return result == "DELETE 1"
    except Exception as exc:
        logger.error("delete_scan failed: %s", exc)
        return False


async def list_scans(
    page: int = 1,
    per_page: int = 20,
    risk_filter: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    if not _pool:
        return [], 0
    offset = (page - 1) * per_page
    try:
        async with _pool.acquire() as conn:
            where = ""
            params: List[Any] = []
            if risk_filter:
                where = "WHERE risk_level = $1"
                params.append(risk_filter.upper())
            count_q = f"SELECT COUNT(*) FROM scan_logs {where}"
            total = await conn.fetchval(count_q, *params)
            params.extend([per_page, offset])
            limit_idx = len(params) - 1
            offset_idx = len(params)
            q = f"""
                SELECT scan_id, risk_score, risk_level, category, verdict,
                       is_scam, verify_mode, summary, created_at
                FROM scan_logs {where}
                ORDER BY created_at DESC
                LIMIT ${limit_idx} OFFSET ${offset_idx}
            """
            if not risk_filter:
                rows = await conn.fetch(
                    "SELECT scan_id, risk_score, risk_level, category, verdict, "
                    "is_scam, verify_mode, summary, created_at FROM scan_logs "
                    "ORDER BY created_at DESC LIMIT $1 OFFSET $2",
                    per_page, offset,
                )
            else:
                rows = await conn.fetch(q, *params)
            return [dict(r) for r in rows], int(total or 0)
    except Exception as exc:
        logger.error("list_scans failed: %s", exc)
        return [], 0


async def update_scan_narrative(scan_id: str, narrative: str, ai4: Dict) -> None:
    if not _pool:
        return
    try:
        async with _pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE scan_logs SET forensic_narrative = $1, ai4_result = $2::jsonb,
                updated_at = NOW() WHERE scan_id = $3
                """,
                narrative, _json(ai4), scan_id,
            )
    except Exception as exc:
        logger.error("update_scan_narrative failed: %s", exc)


# ---------------------------------------------------------------------------
# Victim reports
# ---------------------------------------------------------------------------


async def create_report(data: Dict[str, Any]) -> Dict[str, Any]:
    if not _pool:
        raise RuntimeError("Database not initialized")
    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO victim_reports (
                    report_id, scan_id, victim_name, victim_mobile, victim_email,
                    victim_address, victim_city, victim_state, victim_pin,
                    id_proof_type, id_proof_number, incident_date, incident_time,
                    amount_lost, payment_method, incident_details,
                    suspect_phone, suspect_upi, suspect_website, suspect_details,
                    complaint_text, complaint_sections, generated_by, status
                ) VALUES (
                    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
                    $17,$18,$19,$20,$21,$22::jsonb,$23,$24
                ) RETURNING *
                """,
                data["report_id"], data.get("scan_id"), data["victim_name"],
                data["victim_mobile"], data.get("victim_email"),
                data.get("victim_address"), data.get("victim_city"),
                data.get("victim_state"), data.get("victim_pin"),
                data.get("id_proof_type"), data.get("id_proof_number"),
                data.get("incident_date"), data.get("incident_time"),
                data.get("amount_lost", 0), data.get("payment_method"),
                data.get("incident_details"), data.get("suspect_phone"),
                data.get("suspect_upi"), data.get("suspect_website"),
                data.get("suspect_details"), data.get("complaint_text"),
                _json(data.get("complaint_sections", {})),
                data.get("generated_by", "groq"), data.get("status", "generated"),
            )
            return dict(row)
    except Exception as exc:
        logger.error("create_report failed: %s", exc)
        raise


async def get_report(report_id: str) -> Optional[Dict[str, Any]]:
    if not _pool:
        return None
    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM victim_reports WHERE report_id = $1", report_id
            )
            return dict(row) if row else None
    except Exception as exc:
        logger.error("get_report failed: %s", exc)
        return None


async def get_report_by_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    if not _pool:
        return None
    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM victim_reports WHERE scan_id = $1 ORDER BY created_at DESC LIMIT 1",
                scan_id,
            )
            return dict(row) if row else None
    except Exception as exc:
        logger.error("get_report_by_scan failed: %s", exc)
        return None


async def list_reports(limit: int = 100) -> List[Dict[str, Any]]:
    if not _pool:
        return []
    try:
        async with _pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM victim_reports ORDER BY created_at DESC LIMIT $1",
                limit,
            )
            return [dict(r) for r in rows]
    except Exception as exc:
        logger.error("list_reports failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Known URLs
# ---------------------------------------------------------------------------


def url_hash(url: str) -> str:
    return hashlib.sha256(url.strip().lower().encode()).hexdigest()


async def get_cached_url(url: str) -> Optional[Dict[str, Any]]:
    if not _pool:
        return None
    try:
        h = url_hash(url)
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM known_urls WHERE url_hash = $1 AND (expires_at IS NULL OR expires_at > NOW())",
                h,
            )
            if row:
                await conn.execute(
                    "UPDATE known_urls SET hit_count = hit_count + 1 WHERE url_hash = $1", h
                )
            return dict(row) if row else None
    except Exception as exc:
        logger.error("get_cached_url failed: %s", exc)
        return None


async def cache_url(data: Dict[str, Any], ttl_days: int = 7) -> Dict[str, Any]:
    if not _pool:
        raise RuntimeError("Database not initialized")
    url = data["url"]
    h = url_hash(url)
    expires = datetime.now(timezone.utc) + timedelta(days=ttl_days)
    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO known_urls (
                    url_hash, url, domain, is_malicious, threat_score,
                    safe_browsing_result, virustotal_result, pattern_result,
                    threat_types, expires_at
                ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb,$10)
                ON CONFLICT (url_hash) DO UPDATE SET
                    is_malicious = EXCLUDED.is_malicious,
                    threat_score = EXCLUDED.threat_score,
                    safe_browsing_result = EXCLUDED.safe_browsing_result,
                    virustotal_result = EXCLUDED.virustotal_result,
                    pattern_result = EXCLUDED.pattern_result,
                    threat_types = EXCLUDED.threat_types,
                    checked_at = NOW(),
                    expires_at = EXCLUDED.expires_at,
                    hit_count = known_urls.hit_count + 1
                RETURNING *
                """,
                h, url, data.get("domain"), data.get("is_malicious", False),
                data.get("threat_score", 0),
                _json(data.get("safe_browsing_result", {})),
                _json(data.get("virustotal_result", {})),
                _json(data.get("pattern_result", {})),
                _json(data.get("threat_types", [])),
                expires,
            )
            return dict(row)
    except Exception as exc:
        logger.error("cache_url failed: %s", exc)
        raise


async def list_malicious_urls(limit: int = 50) -> List[Dict[str, Any]]:
    if not _pool:
        return []
    try:
        async with _pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT url, domain, threat_score, threat_types, checked_at "
                "FROM known_urls WHERE is_malicious = TRUE ORDER BY checked_at DESC LIMIT $1",
                limit,
            )
            return [dict(r) for r in rows]
    except Exception as exc:
        logger.error("list_malicious_urls failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Community & learned patterns
# ---------------------------------------------------------------------------


async def add_community_pattern(text: str, category: str, metadata: Dict) -> Dict[str, Any]:
    if not _pool:
        raise RuntimeError("Database not initialized")
    h = hashlib.sha256(text.strip().lower()[:500].encode()).hexdigest()
    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO community_patterns (pattern_hash, text_sample, category, metadata)
                VALUES ($1, $2, $3, $4::jsonb)
                ON CONFLICT (pattern_hash) DO UPDATE SET
                    confirmed_count = community_patterns.confirmed_count + 1,
                    updated_at = NOW()
                RETURNING *
                """,
                h, text[:2000], category, _json(metadata),
            )
            return dict(row)
    except Exception as exc:
        logger.error("add_community_pattern failed: %s", exc)
        raise


async def list_community_patterns(limit: int = 100) -> List[Dict[str, Any]]:
    if not _pool:
        return []
    try:
        async with _pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM community_patterns ORDER BY confirmed_count DESC LIMIT $1", limit
            )
            return [dict(r) for r in rows]
    except Exception as exc:
        logger.error("list_community_patterns failed: %s", exc)
        return []


async def add_learned_pattern(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not _pool:
        return None
    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO learned_patterns (source, pattern_text, category, keywords, severity, metadata)
                VALUES ($1, $2, $3, $4::jsonb, $5, $6::jsonb) RETURNING *
                """,
                data.get("source", "news_scraper"), data["pattern_text"],
                data.get("category"), _json(data.get("keywords", [])),
                data.get("severity", "MODERATE"), _json(data.get("metadata", {})),
            )
            return dict(row)
    except Exception as exc:
        logger.error("add_learned_pattern failed: %s", exc)
        return None


async def list_learned_patterns(limit: int = 100) -> List[Dict[str, Any]]:
    if not _pool:
        return []
    try:
        async with _pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM learned_patterns ORDER BY created_at DESC LIMIT $1", limit
            )
            return [dict(r) for r in rows]
    except Exception as exc:
        logger.error("list_learned_patterns failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# News articles
# ---------------------------------------------------------------------------


async def upsert_news_article(data: Dict[str, Any]) -> Dict[str, Any]:
    if not _pool:
        raise RuntimeError("Database not initialized")
    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO news_articles (
                    article_id, title, summary, content, source, source_url,
                    category, severity, is_hardcoded, published_at, metadata
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)
                ON CONFLICT (article_id) DO UPDATE SET
                    title = EXCLUDED.title, summary = EXCLUDED.summary,
                    content = EXCLUDED.content, severity = EXCLUDED.severity,
                    scraped_at = NOW()
                RETURNING *
                """,
                data["article_id"], data["title"], data.get("summary"),
                data.get("content"), data.get("source"), data.get("source_url"),
                data.get("category"), data.get("severity", "MODERATE"),
                data.get("is_hardcoded", False), data.get("published_at"),
                _json(data.get("metadata", {})),
            )
            return dict(row)
    except Exception as exc:
        logger.error("upsert_news_article failed: %s", exc)
        raise


async def list_news(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    if not _pool:
        return []
    try:
        async with _pool.acquire() as conn:
            q = "SELECT * FROM news_articles WHERE 1=1"
            params: List[Any] = []
            idx = 1
            if category:
                q += f" AND category = ${idx}"
                params.append(category)
                idx += 1
            if severity:
                q += f" AND severity = ${idx}"
                params.append(severity.upper())
                idx += 1
            q += f" ORDER BY published_at DESC NULLS LAST, scraped_at DESC LIMIT ${idx}"
            params.append(limit)
            rows = await conn.fetch(q, *params)
            return [dict(r) for r in rows]
    except Exception as exc:
        logger.error("list_news failed: %s", exc)
        return []


async def get_news_article(article_id: str) -> Optional[Dict[str, Any]]:
    if not _pool:
        return None
    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM news_articles WHERE article_id = $1", article_id
            )
            return dict(row) if row else None
    except Exception as exc:
        logger.error("get_news_article failed: %s", exc)
        return None


async def search_news(query: str, limit: int = 20) -> List[Dict[str, Any]]:
    if not _pool:
        return []
    try:
        pattern = f"%{query}%"
        async with _pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM news_articles
                WHERE title ILIKE $1 OR summary ILIKE $1 OR content ILIKE $1
                ORDER BY published_at DESC NULLS LAST LIMIT $2
                """,
                pattern, limit,
            )
            return [dict(r) for r in rows]
    except Exception as exc:
        logger.error("search_news failed: %s", exc)
        return []


async def count_news() -> int:
    if not _pool:
        return 0
    try:
        async with _pool.acquire() as conn:
            return int(await conn.fetchval("SELECT COUNT(*) FROM news_articles") or 0)
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


async def create_notification(data: Dict[str, Any]) -> Dict[str, Any]:
    if not _pool:
        raise RuntimeError("Database not initialized")
    nid = data.get("notification_id") or f"NT-{uuid.uuid4().hex[:12].upper()}"
    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO notifications (
                    notification_id, type, title, message, severity, metadata, scan_id
                ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7) RETURNING *
                """,
                nid, data["type"], data["title"], data.get("message"),
                data.get("severity", "MODERATE"), _json(data.get("metadata", {})),
                data.get("scan_id"),
            )
            return dict(row)
    except Exception as exc:
        logger.error("create_notification failed: %s", exc)
        raise


async def list_notifications(
    unread_only: bool = False,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    if not _pool:
        return []
    try:
        async with _pool.acquire() as conn:
            if unread_only:
                rows = await conn.fetch(
                    "SELECT * FROM notifications WHERE is_read = FALSE "
                    "ORDER BY created_at DESC LIMIT $1", limit
                )
            else:
                rows = await conn.fetch(
                    "SELECT * FROM notifications ORDER BY created_at DESC LIMIT $1", limit
                )
            return [dict(r) for r in rows]
    except Exception as exc:
        logger.error("list_notifications failed: %s", exc)
        return []


async def unread_notification_count() -> int:
    if not _pool:
        return 0
    try:
        async with _pool.acquire() as conn:
            return int(
                await conn.fetchval(
                    "SELECT COUNT(*) FROM notifications WHERE is_read = FALSE"
                ) or 0
            )
    except Exception:
        return 0


async def mark_notifications_read(notification_ids: Optional[List[str]] = None) -> int:
    if not _pool:
        return 0
    try:
        async with _pool.acquire() as conn:
            if notification_ids:
                result = await conn.execute(
                    "UPDATE notifications SET is_read = TRUE WHERE notification_id = ANY($1::text[])",
                    notification_ids,
                )
            else:
                result = await conn.execute(
                    "UPDATE notifications SET is_read = TRUE WHERE is_read = FALSE"
                )
            return int(result.split()[-1]) if result else 0
    except Exception as exc:
        logger.error("mark_notifications_read failed: %s", exc)
        return 0


# ---------------------------------------------------------------------------
# Mismatch log
# ---------------------------------------------------------------------------


async def log_mismatch(data: Dict[str, Any]) -> None:
    if not _pool:
        return
    try:
        async with _pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO mismatch_log (
                    scan_id, mismatch_type, claimed_entity, claimed_value,
                    actual_entity, actual_value, severity, details
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
                """,
                data.get("scan_id"), data.get("mismatch_type"),
                data.get("claimed_entity"), data.get("claimed_value"),
                data.get("actual_entity"), data.get("actual_value"),
                data.get("severity", "HIGH"), _json(data.get("details", {})),
            )
    except Exception as exc:
        logger.error("log_mismatch failed: %s", exc)


# ---------------------------------------------------------------------------
# System stats
# ---------------------------------------------------------------------------


async def increment_stat(key: str, amount: int = 1) -> None:
    if not _pool:
        return
    try:
        async with _pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE system_stats SET
                    stat_value = jsonb_set(
                        COALESCE(stat_value, '{}'::jsonb),
                        '{count}',
                        to_jsonb(COALESCE((stat_value->>'count')::int, 0) + $2)
                    ),
                    updated_at = NOW()
                WHERE stat_key = $1
                """,
                key, amount,
            )
    except Exception as exc:
        logger.error("increment_stat failed: %s", exc)


async def get_all_stats() -> Dict[str, Any]:
    if not _pool:
        return {}
    try:
        async with _pool.acquire() as conn:
            rows = await conn.fetch("SELECT stat_key, stat_value, updated_at FROM system_stats")
            stats: Dict[str, Any] = {}
            for row in rows:
                val = row["stat_value"]
                if isinstance(val, str):
                    val = json.loads(val)
                stats[row["stat_key"]] = val
            scan_stats = await conn.fetchrow(
                """
                SELECT COUNT(*) as total,
                    COUNT(*) FILTER (WHERE is_scam) as scams,
                    COUNT(*) FILTER (WHERE risk_level = 'CRITICAL') as critical,
                    COUNT(*) FILTER (WHERE verify_mode) as verify
                FROM scan_logs
                """
            )
            if scan_stats:
                stats["live_total_scans"] = {"count": scan_stats["total"]}
                stats["live_scams_detected"] = {"count": scan_stats["scams"]}
                stats["live_critical"] = {"count": scan_stats["critical"]}
                stats["live_verify_mode"] = {"count": scan_stats["verify"]}
            cat_rows = await conn.fetch(
                """
                SELECT category, COUNT(*) as cnt FROM scan_logs
                WHERE is_scam = TRUE GROUP BY category ORDER BY cnt DESC LIMIT 10
                """
            )
            stats["top_categories"] = [
                {"category": r["category"], "count": r["cnt"]} for r in cat_rows
            ]
            return stats
    except Exception as exc:
        logger.error("get_all_stats failed: %s", exc)
        return {}


async def set_stat(key: str, value: Dict[str, Any]) -> None:
    if not _pool:
        return
    try:
        async with _pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO system_stats (stat_key, stat_value) VALUES ($1, $2::jsonb)
                ON CONFLICT (stat_key) DO UPDATE SET stat_value = $2::jsonb, updated_at = NOW()
                """,
                key, _json(value),
            )
    except Exception as exc:
        logger.error("set_stat failed: %s", exc)
