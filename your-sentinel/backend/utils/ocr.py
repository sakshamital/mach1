"""
YOUR SENTINEL — OCR Engine.

Wraps Tesseract OCR as fallback when Gemini Vision is unavailable.
"""

from __future__ import annotations

import io
import logging
from typing import Optional

logger = logging.getLogger("SENTINEL.OCR")


class OCREngine:
    """Extract text from images using Tesseract."""

    def __init__(self) -> None:
        self._available: Optional[bool] = None

    def _check_tesseract(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            import pytesseract
            pytesseract.get_tesseract_version()
            self._available = True
        except Exception:
            self._available = False
            logger.info("Tesseract not available — OCR disabled")
        return self._available

    def extract(self, image_bytes: bytes) -> str:
        if not self._check_tesseract():
            return ""
        try:
            from PIL import Image
            import pytesseract
            img = Image.open(io.BytesIO(image_bytes))
            text = pytesseract.image_to_string(img, lang="eng+hin")
            return text.strip()
        except Exception as exc:
            logger.warning("OCR extract failed: %s", exc)
            return ""
