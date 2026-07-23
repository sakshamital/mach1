"""
YOUR SENTINEL — Export utilities.

scan_to_text() for single scan TXT export, history_to_csv() for bulk export.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("SENTINEL.EXPORTER")


def scan_to_text(scan: Dict[str, Any]) -> str:
    """Convert scan record to downloadable text report."""
    try:
        lines = [
            "=" * 70,
            "YOUR SENTINEL — SCAN ANALYSIS REPORT",
            "=" * 70,
            f"Scan ID: {scan.get('scan_id', 'N/A')}",
            f"Date: {scan.get('created_at', datetime.utcnow().isoformat())}",
            f"Risk Score: {scan.get('risk_score', 0)}%",
            f"Risk Level: {scan.get('risk_level', 'LOW')}",
            f"Category: {scan.get('category', 'unknown')}",
            f"Verdict: {scan.get('verdict', 'UNKNOWN')}",
            f"Is Scam: {scan.get('is_scam', False)}",
            f"Verify Mode: {scan.get('verify_mode', False)}",
            "",
            "SUMMARY",
            "-" * 40,
            scan.get("summary", ""),
            "",
            "INPUT TEXT",
            "-" * 40,
            (scan.get("input_text") or "")[:10000],
            "",
            "BEHAVIOUR TRIGGERS",
            "-" * 40,
            json.dumps(scan.get("behaviour_triggers", []), indent=2, ensure_ascii=False),
            "",
            "MISMATCH ALERTS",
            "-" * 40,
            json.dumps(scan.get("mismatch_alerts", []), indent=2, ensure_ascii=False),
            "",
            "URL THREATS",
            "-" * 40,
            json.dumps(scan.get("url_threats", []), indent=2, ensure_ascii=False),
            "",
            "RECOMMENDED ACTIONS",
            "-" * 40,
        ]
        for i, action in enumerate(scan.get("recommended_actions", []), 1):
            lines.append(f"  {i}. {action}")
        lines.extend([
            "",
            "FORENSIC NARRATIVE",
            "-" * 40,
            scan.get("forensic_narrative", "Not yet generated."),
            "",
            "=" * 70,
            "Report cybercrime: 1930 | https://cybercrime.gov.in",
            "=" * 70,
        ])
        return "\n".join(lines)
    except Exception as exc:
        logger.error("scan_to_text failed: %s", exc)
        return f"Export error: {exc}"


def history_to_csv(scans: List[Dict[str, Any]]) -> str:
    """Convert scan list to CSV string."""
    try:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "scan_id", "created_at", "risk_score", "risk_level",
            "category", "verdict", "is_scam", "verify_mode", "summary",
        ])
        for s in scans:
            writer.writerow([
                s.get("scan_id"),
                str(s.get("created_at", "")),
                s.get("risk_score"),
                s.get("risk_level"),
                s.get("category"),
                s.get("verdict"),
                s.get("is_scam"),
                s.get("verify_mode"),
                (s.get("summary") or "")[:500],
            ])
        return output.getvalue()
    except Exception as exc:
        logger.error("history_to_csv failed: %s", exc)
        return "scan_id,error\n,export failed\n"
