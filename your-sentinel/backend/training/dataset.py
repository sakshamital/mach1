"""
YOUR SENTINEL — User-editable training dataset.

Add custom scam/safe examples to MY_SCAM_EXAMPLES and MY_SAFE_EXAMPLES.
These are merged with scams.csv during model training.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("SENTINEL.TRAINING.DATASET")

# User-editable examples — add your own below
MY_SCAM_EXAMPLES: List[Dict[str, str]] = [
    {
        "text": "Your Sentinel test scam: Send 5000 to this UPI scammer@paytm immediately.",
        "category": "qr_upi",
        "language": "en",
        "severity": "HIGH",
    },
    {
        "text": "Beta turant 10000 bhejo, hospital mein admission hai - new number pe.",
        "category": "family_impersonation",
        "language": "hinglish",
        "severity": "CRITICAL",
    },
]

MY_SAFE_EXAMPLES: List[Dict[str, str]] = [
    {
        "text": "Your Sentinel: This is a normal message from your bank app about statement ready.",
        "category": "banking_otp",
        "language": "en",
        "severity": "LOW",
    },
    {
        "text": "Chai peene chaloge shaam ko? - Friend",
        "category": "unknown",
        "language": "hinglish",
        "severity": "LOW",
    },
]

DATA_DIR = Path(__file__).parent / "data"
DEFAULT_CSV = DATA_DIR / "scams.csv"


def load_csv(path: Path = DEFAULT_CSV) -> List[Dict[str, str]]:
    """Load scams.csv into list of dicts."""
    rows: List[Dict[str, str]] = []
    try:
        if not path.exists():
            logger.warning("CSV not found: %s", path)
            return rows
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(dict(row))
    except Exception as exc:
        logger.error("load_csv failed: %s", exc)
    return rows


def load_full_dataset() -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """Return (scam_examples, safe_examples) merged with user examples."""
    scams: List[Dict[str, str]] = []
    safes: List[Dict[str, str]] = []
    try:
        for row in load_csv():
            label = row.get("label", "SCAM").upper()
            entry = {
                "text": row.get("text", ""),
                "label": label,
                "category": row.get("category", "unknown"),
                "language": row.get("language", "en"),
                "severity": row.get("severity", "MODERATE"),
            }
            if label == "SAFE":
                safes.append(entry)
            else:
                scams.append(entry)
        for ex in MY_SCAM_EXAMPLES:
            scams.append({**ex, "label": "SCAM"})
        for ex in MY_SAFE_EXAMPLES:
            safes.append({**ex, "label": "SAFE"})
        logger.info("Dataset loaded: %d scams, %d safe", len(scams), len(safes))
    except Exception as exc:
        logger.error("load_full_dataset failed: %s", exc)
    return scams, safes


def to_huggingface_format(
    scams: List[Dict[str, str]],
    safes: List[Dict[str, str]],
) -> List[Dict[str, Any]]:
    """Convert to HuggingFace datasets format."""
    records: List[Dict[str, Any]] = []
    for item in scams:
        records.append({"text": item["text"], "label": 1})
    for item in safes:
        records.append({"text": item["text"], "label": 0})
    return records
