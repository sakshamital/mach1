"""
YOUR SENTINEL — AI Model 2: Gemini Vision + Text Analysis.

Reads screenshots/images and performs deep text analysis with context
from AI 1 (behaviour) and AI 3 (URL threats).
"""

from __future__ import annotations

import base64
import json
import logging
import re
from typing import Any, Dict, List, Optional

import httpx

import config

logger = logging.getLogger("SENTINEL.AI.VISION")


class ImageProcessor:
    """Prepares images for Gemini Vision API."""

    SUPPORTED_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif", "image/bmp"}

    @staticmethod
    def to_base64(data: bytes, mime: str = "image/jpeg") -> str:
        return base64.standard_b64encode(data).decode("utf-8")

    @staticmethod
    def detect_mime(filename: str, content_type: Optional[str] = None) -> str:
        if content_type and content_type in ImageProcessor.SUPPORTED_TYPES:
            return content_type
        ext = filename.lower().split(".")[-1] if filename else "jpg"
        mapping = {
            "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
            "webp": "image/webp", "gif": "image/gif", "bmp": "image/bmp",
        }
        return mapping.get(ext, "image/jpeg")


class GeminiVision:
    """Gemini 2.0 Flash vision + 1.5 Flash text analysis."""

    def __init__(self) -> None:
        self.api_key = config.GEMINI_API_KEY
        self.vision_model = config.GEMINI_VISION_MODEL
        self.text_model = config.GEMINI_TEXT_MODEL
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models"

    def _available(self) -> bool:
        return bool(self.api_key and self.api_key != "YOUR_KEY_HERE")

    async def analyze_image(
        self,
        image_bytes: bytes,
        filename: str = "upload.jpg",
        mime: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self._available():
            return self._fallback_image(image_bytes, filename)
        try:
            mime_type = ImageProcessor.detect_mime(filename, mime)
            b64 = ImageProcessor.to_base64(image_bytes, mime_type)
            prompt = (
                "You are a cybercrime detection AI for India. Analyze this screenshot/message image. "
                "Return ONLY valid JSON with keys: risk_score (0-100), category (scam category id), "
                "extracted_text (all visible text), language (en/hi/hinglish), "
                "indicators (list of red flags), forensic_narrative (2-3 sentences), "
                "is_scam (boolean). Focus on Indian scams: OTP, UPI, digital arrest, KYC, parcel."
            )
            payload = {
                "contents": [{
                    "parts": [
                        {"text": prompt},
                        {"inline_data": {"mime_type": mime_type, "data": b64}},
                    ]
                }],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 2048},
            }
            url = f"{self.base_url}/{self.vision_model}:generateContent?key={self.api_key}"
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code != 200:
                    logger.warning("Gemini vision status %s", resp.status_code)
                    return self._fallback_image(image_bytes, filename)
                return self._parse_gemini_json(resp.json(), source="gemini_vision")
        except Exception as exc:
            logger.error("analyze_image failed: %s", exc)
            return self._fallback_image(image_bytes, filename)

    async def analyze_text_deep(
        self,
        text: str,
        behaviour_context: Optional[Dict] = None,
        url_context: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:
        if not self._available():
            return self._fallback_text(text, behaviour_context, url_context)
        try:
            ctx_parts = []
            if behaviour_context:
                ctx_parts.append(f"Behaviour analysis: {json.dumps(behaviour_context)[:1500]}")
            if url_context:
                ctx_parts.append(f"URL threats: {json.dumps(url_context)[:1000]}")
            context_block = "\n".join(ctx_parts) if ctx_parts else "No prior context."
            prompt = (
                f"You are an Indian cybercrime forensic AI. Analyze this message for scams.\n"
                f"Context from other AI modules:\n{context_block}\n\n"
                f"Message to analyze:\n{text[:8000]}\n\n"
                "Return ONLY valid JSON: risk_score (0-100), category (taxonomy id), "
                "verdict (SCAM/SAFE/VERIFY), indicators (list), forensic_narrative (paragraph), "
                "suspect_phone, suspect_upi, suspect_website (if found, else null), "
                "language, confidence (0-100)."
            )
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 2048},
            }
            url = f"{self.base_url}/{self.text_model}:generateContent?key={self.api_key}"
            async with httpx.AsyncClient(timeout=45.0) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code != 200:
                    return self._fallback_text(text, behaviour_context, url_context)
                return self._parse_gemini_json(resp.json(), source="gemini_text")
        except Exception as exc:
            logger.error("analyze_text_deep failed: %s", exc)
            return self._fallback_text(text, behaviour_context, url_context)

    def _parse_gemini_json(self, response: Dict, source: str = "gemini") -> Dict[str, Any]:
        try:
            candidates = response.get("candidates", [])
            if not candidates:
                raise ValueError("No candidates")
            text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            json_match = re.search(r"\{[\s\S]*\}", text)
            if json_match:
                parsed = json.loads(json_match.group())
                parsed["source"] = source
                parsed["risk_score"] = float(parsed.get("risk_score", 50))
                return parsed
        except Exception as exc:
            logger.warning("Parse gemini JSON: %s", exc)
        return {
            "source": source,
            "risk_score": 50.0,
            "category": "unknown",
            "forensic_narrative": "Automated analysis could not parse full response.",
            "indicators": [],
        }

    def _fallback_image(self, image_bytes: bytes, filename: str) -> Dict[str, Any]:
        try:
            from utils.ocr import OCREngine
            ocr = OCREngine()
            text = ocr.extract(image_bytes)
            return {
                "source": "ocr_fallback",
                "risk_score": 45.0 if text else 20.0,
                "category": "unknown",
                "extracted_text": text,
                "forensic_narrative": f"OCR extracted {len(text)} characters. Configure GEMINI_API_KEY for vision AI.",
                "indicators": ["ocr_only"],
                "is_scam": False,
            }
        except Exception as exc:
            logger.error("fallback image: %s", exc)
            return {
                "source": "fallback",
                "risk_score": 25.0,
                "category": "unknown",
                "extracted_text": "",
                "forensic_narrative": "Image received. Enable Gemini API for full analysis.",
                "indicators": [],
            }

    def _fallback_text(
        self,
        text: str,
        behaviour: Optional[Dict],
        urls: Optional[List[Dict]],
    ) -> Dict[str, Any]:
        score = 30.0
        if behaviour:
            score += behaviour.get("behaviour", {}).get("total_score", 0) * 0.5
        if urls:
            for u in urls:
                if u.get("is_malicious"):
                    score += 20
        indicators: List[str] = []
        for kw in ["otp", "urgent", "arrest", "lottery", "kyc", "upi", "digital arrest"]:
            if kw in text.lower():
                indicators.append(kw)
                score += 8
        return {
            "source": "local_fallback",
            "risk_score": min(score, 90),
            "category": "unknown",
            "verdict": "SCAM" if score >= 50 else "SAFE",
            "indicators": indicators,
            "forensic_narrative": "Local analysis performed. Configure GEMINI_API_KEY for deep AI analysis.",
            "confidence": 40,
        }

    def build_context_payload(
        self,
        local: Dict[str, Any],
        url_results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        return {
            "behaviour_triggers": local.get("behaviour", {}).get("triggers", []),
            "mismatches": local.get("mismatches", []),
            "family_impersonation": local.get("family_impersonation", False),
            "url_threats": [
                {"url": u.get("url"), "score": u.get("threat_score"), "malicious": u.get("is_malicious")}
                for u in url_results
            ],
        }
