"""
YOUR SENTINEL — AI Model 1: Sentinel Brain.

HuggingFace Indic-BERT classifier + BehaviourEngine + MismatchDetector.
Coordinates final unified verdict combining AI 2, AI 3, and local analysis.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import httpx

import config
from config import (
    ANTI_FP_KEYWORD_ONLY_CAP,
    BEHAVIOUR_PATTERNS,
    FAMILY_IMPERSONATION_PATTERNS,
    MUTATION_TEMPLATES,
    OFFICIAL_DOMAIN_ALIASES,
    OFFICIAL_INDIA_DB,
    get_risk_level,
)

logger = logging.getLogger("SENTINEL.AI.BRAIN")


class BehaviourEngine:
    """Detects 7 universal manipulation patterns in text."""

    def __init__(self) -> None:
        self.patterns = BEHAVIOUR_PATTERNS

    @staticmethod
    def _keyword_in_text(keyword: str, text_lower: str) -> bool:
        """Match keyword with word boundaries for short tokens to reduce false positives."""
        kw = keyword.lower().strip()
        if len(kw) <= 3:
            return bool(re.search(r"\b" + re.escape(kw) + r"\b", text_lower))
        return kw in text_lower

    def analyze(self, text: str) -> Dict[str, Any]:
        try:
            text_lower = text.lower()
            scores: Dict[str, float] = {}
            triggers: List[Dict[str, Any]] = []
            total = 0.0
            for pid, pdata in self.patterns.items():
                matched_kw: List[str] = []
                for kw in pdata.get("keywords_en", []) + pdata.get("keywords_hi", []):
                    if self._keyword_in_text(kw, text_lower):
                        matched_kw.append(kw)
                if matched_kw:
                    weight = float(pdata.get("weight", 10))
                    score = min(weight * len(matched_kw) * 0.4, weight * 2)
                    scores[pid] = round(score, 2)
                    total += score
                    triggers.append({
                        "pattern": pid,
                        "label": pdata.get("label", pid),
                        "keywords": matched_kw[:5],
                        "score": round(score, 2),
                    })
            return {
                "scores": scores,
                "triggers": triggers,
                "total_score": min(round(total, 2), 60.0),
            }
        except Exception as exc:
            logger.error("BehaviourEngine.analyze failed: %s", exc)
            return {"scores": {}, "triggers": [], "total_score": 0.0}


class MismatchDetector:
    """Detects fake official numbers, websites, emails."""

    PHONE_RE = re.compile(r"(?:\+91[\s-]?)?[6-9]\d{9}")
    URL_RE = re.compile(
        r"https?://[^\s<>\"']+|www\.[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z]{2,}",
        re.IGNORECASE,
    )
    EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

    def __init__(self) -> None:
        self.official_db = OFFICIAL_INDIA_DB
        self._build_phone_set()
        self._build_domain_set()

    def _build_phone_set(self) -> None:
        self.official_phones: Dict[str, str] = {}
        for inst_id, inst in self.official_db.items():
            for phone in inst.phones:
                normalized = re.sub(r"\D", "", phone)[-10:]
                if len(normalized) >= 10:
                    self.official_phones[normalized[-10:]] = inst_id

    def _build_domain_set(self) -> None:
        self.official_domains: Dict[str, str] = {}
        for inst_id, inst in self.official_db.items():
            for site in inst.websites:
                domain = self._extract_domain(site)
                if domain:
                    self.official_domains[domain] = inst_id

    def _extract_domain(self, url: str) -> str:
        url = url.lower().replace("https://", "").replace("http://", "").replace("www.", "")
        return url.split("/")[0].split("?")[0]

    def detect(self, text: str) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        try:
            text_lower = text.lower()
            claimed_entities = self._find_claimed_entities(text_lower)
            for phone_match in self.PHONE_RE.finditer(text):
                digits = re.sub(r"\D", "", phone_match.group())[-10:]
                if len(digits) != 10:
                    continue
                for entity_id in claimed_entities:
                    inst = self.official_db.get(entity_id)
                    if not inst:
                        continue
                    official_set = {re.sub(r"\D", "", p)[-10:] for p in inst.phones}
                    if official_set and digits not in official_set:
                        alerts.append({
                            "type": "fake_phone",
                            "claimed_entity": entity_id,
                            "claimed_value": phone_match.group(),
                            "actual_entity": entity_id,
                            "actual_value": ", ".join(inst.phones) or "No public phone",
                            "severity": "CRITICAL",
                            "message": f"Number {phone_match.group()} is NOT an official {inst.short_name} number.",
                            "note": inst.note,
                        })
            for url_match in self.URL_RE.finditer(text):
                url = url_match.group()
                domain = self._extract_domain(url)
                for entity_id in claimed_entities:
                    inst = self.official_db.get(entity_id)
                    if not inst:
                        continue
                    official_domains = [self._extract_domain(s) for s in inst.websites]
                    if official_domains and domain not in official_domains:
                        similar = self._is_typosquat(domain, official_domains)
                        if similar or domain not in self.official_domains:
                            alerts.append({
                                "type": "fake_website",
                                "claimed_entity": entity_id,
                                "claimed_value": url,
                                "actual_entity": entity_id,
                                "actual_value": ", ".join(inst.websites[:2]),
                                "severity": "CRITICAL" if similar else "HIGH",
                                "message": f"URL {url} does not match official {inst.short_name} websites.",
                                "note": inst.note,
                            })
            for email_match in self.EMAIL_RE.finditer(text):
                email = email_match.group().lower()
                domain = email.split("@")[-1]
                for entity_id in claimed_entities:
                    inst = self.official_db.get(entity_id)
                    if not inst:
                        continue
                    official_email_domains = [
                        e.split("@")[-1].lower() for e in inst.emails if "@" in e
                    ]
                    if official_email_domains and domain not in official_email_domains:
                        alerts.append({
                            "type": "fake_email",
                            "claimed_entity": entity_id,
                            "claimed_value": email,
                            "severity": "HIGH",
                            "message": f"Email {email} is not from official {inst.short_name}.",
                        })
        except Exception as exc:
            logger.error("MismatchDetector.detect failed: %s", exc)
        return alerts

    def _find_claimed_entities(self, text: str) -> List[str]:
        found: List[str] = []
        keywords = {
            "sbi": "SBI", "hdfc": "HDFC", "icici": "ICICI", "axis bank": "AXIS",
            "pnb": "PNB", "rbi": "RBI", "trai": "TRAI", "uidai": "UIDAI",
            "aadhaar": "UIDAI", "income tax": "INCOMETAX", "cyber crime": "CYBERCRIME",
            "google pay": "GOOGLEPAY", "gpay": "GOOGLEPAY", "phonepe": "PHONEPE",
            "paytm": "PAYTM", "amazon": "AMAZON", "flipkart": "FLIPKART",
            "microsoft": "MICROSOFT", "cbi": "CYBERCRIME", "customs": "CYBERCRIME",
            "fedex": "FEDEX", "dhl": "DHL", "lic": "LIC", "npci": "NPCI",
            "bhim": "BHIM", "jio": "JIO", "airtel": "AIRTEL", "bsnl": "BSNL",
        }
        for kw, eid in keywords.items():
            if kw in text and eid not in found:
                found.append(eid)
        for alias, eid in OFFICIAL_DOMAIN_ALIASES.items():
            if alias in text and eid not in found:
                found.append(eid)
        return found

    def _is_typosquat(self, domain: str, official: List[str]) -> bool:
        for off in official:
            if domain != off and (domain in off or off in domain):
                if abs(len(domain) - len(off)) <= 3:
                    return True
        return False


class HuggingFaceBrain:
    """Indic-BERT inference via HuggingFace API with local fallback."""

    def __init__(self) -> None:
        self.api_key = config.HUGGINGFACE_API_KEY
        self.model_url = config.HUGGINGFACE_INFERENCE_URL

    async def classify(self, text: str) -> Dict[str, Any]:
        if self.api_key == "YOUR_KEY_HERE" or not self.api_key:
            return self._local_classify(text)
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    self.model_url,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={"inputs": text[:512]},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return self._parse_hf_response(data)
                logger.warning("HF API status %s, using fallback", resp.status_code)
        except Exception as exc:
            logger.warning("HF classify failed: %s", exc)
        return self._local_classify(text)

    def _parse_hf_response(self, data: Any) -> Dict[str, Any]:
        try:
            if isinstance(data, list) and data:
                if isinstance(data[0], list):
                    data = data[0]
                best = max(data, key=lambda x: x.get("score", 0))
                label = best.get("label", "SCAM").upper()
                score = float(best.get("score", 0.5)) * 100
                is_scam = "SCAM" in label or "FRAUD" in label or label == "1"
                return {
                    "source": "huggingface",
                    "label": "SCAM" if is_scam else "SAFE",
                    "confidence": round(score, 2),
                    "raw": data,
                }
        except Exception as exc:
            logger.error("Parse HF response: %s", exc)
        return self._local_classify("")

    def _local_classify(self, text: str) -> Dict[str, Any]:
        scam_kw = ["otp", "urgent", "arrest", "lottery", "kyc", "digital arrest", "won prize"]
        text_l = text.lower()
        hits = sum(1 for k in scam_kw if k in text_l)
        conf = min(hits * 15, 85) if hits else 10
        return {
            "source": "local_fallback",
            "label": "SCAM" if hits >= 2 else "SAFE",
            "confidence": conf,
        }


class SentinelBrain:
    """AI 1 coordinator: behaviour + mismatch + HF + unified verdict."""

    def __init__(self) -> None:
        self.behaviour = BehaviourEngine()
        self.mismatch = MismatchDetector()
        self.hf = HuggingFaceBrain()

    def detect_family_impersonation(self, text: str) -> Tuple[bool, float, List[str]]:
        try:
            text_lower = text.lower()
            for fp in FAMILY_IMPERSONATION_PATTERNS:
                for pat in fp.get("patterns", []):
                    if re.search(pat, text_lower, re.IGNORECASE):
                        return True, float(fp.get("weight", 16)), fp.get("patterns", [])[:3]
        except Exception as exc:
            logger.error("family detection: %s", exc)
        return False, 0.0, []

    def detect_mutations(self, text: str) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        try:
            text_lower = text.lower()
            for tmpl in MUTATION_TEMPLATES:
                kw_hits = [
                    k for k in tmpl.get("keywords", [])
                    if BehaviourEngine._keyword_in_text(k, text_lower)
                ]
                if len(kw_hits) >= 2:
                    matches.append({
                        "id": tmpl["id"],
                        "name": tmpl["name"],
                        "keywords": kw_hits,
                        "base_risk": tmpl.get("base_risk", 70),
                    })
                elif len(kw_hits) == 1:
                    matches.append({
                        "id": tmpl["id"],
                        "name": tmpl["name"],
                        "keywords": kw_hits,
                        "base_risk": tmpl.get("base_risk", 70) * 0.6,
                    })
        except Exception as exc:
            logger.error("mutation detect: %s", exc)
        return matches

    async def run_local_analysis(self, text: str) -> Dict[str, Any]:
        try:
            behaviour = self.behaviour.analyze(text)
            mismatches = self.mismatch.detect(text)
            family, family_score, family_pats = self.detect_family_impersonation(text)
            mutations = self.detect_mutations(text)
            hf = await self.hf.classify(text)
            return {
                "behaviour": behaviour,
                "mismatches": mismatches,
                "family_impersonation": family,
                "family_score": family_score,
                "family_patterns": family_pats,
                "mutations": mutations,
                "hf_classification": hf,
            }
        except Exception as exc:
            logger.error("run_local_analysis: %s", exc)
            return {}

    def compute_unified_verdict(
        self,
        text: str,
        local: Dict[str, Any],
        vision: Optional[Dict[str, Any]] = None,
        url_results: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        try:
            score = 0.0
            signals: List[str] = []
            behaviour = local.get("behaviour", {})
            score += behaviour.get("total_score", 0)
            if behaviour.get("triggers"):
                signals.append("behaviour_patterns")

            mismatches = local.get("mismatches", [])
            if mismatches:
                score += min(len(mismatches) * 12, 35)
                signals.append("official_mismatch")

            if local.get("family_impersonation"):
                score += local.get("family_score", 16)
                signals.append("family_impersonation")

            mutations = local.get("mutations", [])
            for m in mutations:
                score += float(m.get("base_risk", 0)) * 0.15
            if mutations:
                signals.append("mutation_template")

            hf = local.get("hf_classification", {})
            if hf.get("label") == "SCAM":
                score += float(hf.get("confidence", 0)) * 0.25
                signals.append("hf_classifier")

            if vision:
                vscore = float(vision.get("risk_score", 0))
                score += vscore * 0.35
                if vscore > 30:
                    signals.append("gemini_vision")
                category = vision.get("category", "unknown")
            else:
                category = self._infer_category(text, local)

            if url_results:
                for ur in url_results:
                    if ur.get("is_malicious"):
                        score += float(ur.get("threat_score", 50)) * 0.2
                        signals.append("malicious_url")

            keyword_only = (
                len(signals) == 1
                and signals[0] in ("behaviour_patterns", "hf_classifier")
                and score < 30
            )
            if keyword_only:
                score = min(score, ANTI_FP_KEYWORD_ONLY_CAP)

            final_score = min(round(score, 2), 100.0)
            verify_mode = local.get("family_impersonation", False) and 40 <= final_score < 75
            is_scam = final_score >= config.RISK_THRESHOLDS["moderate"]
            verdict = "VERIFY" if verify_mode else ("SCAM" if is_scam else "SAFE")

            actions = self._recommended_actions(final_score, mismatches, url_results, verify_mode)

            return {
                "risk_score": final_score,
                "risk_level": config.get_risk_level(final_score),
                "category": category,
                "verdict": verdict,
                "is_scam": is_scam,
                "verify_mode": verify_mode,
                "signals": signals,
                "recommended_actions": actions,
                "summary": self._build_summary(final_score, verdict, category, mismatches),
            }
        except Exception as exc:
            logger.error("compute_unified_verdict: %s", exc)
            return {
                "risk_score": 0, "risk_level": "LOW", "category": "unknown",
                "verdict": "UNKNOWN", "is_scam": False, "verify_mode": False,
                "signals": [], "recommended_actions": [], "summary": "Analysis incomplete.",
            }

    def _infer_category(self, text: str, local: Dict) -> str:
        text_l = text.lower()
        if local.get("family_impersonation"):
            return "family_impersonation"
        if "digital arrest" in text_l or ("video call" in text_l and re.search(r"\bcbi\b", text_l)):
            return "digital_arrest"
        if "trai" in text_l or "sim block" in text_l:
            return "trai_block"
        if re.search(r"\botp\b", text_l) or ("account" in text_l and "block" in text_l):
            return "banking_otp"
        if "kyc" in text_l or "aadhaar" in text_l:
            return "kyc_aadhaar"
        if "lottery" in text_l or "won" in text_l:
            return "lottery_prize"
        if "parcel" in text_l or "customs" in text_l:
            return "delivery_customs"
        if mutations := local.get("mutations"):
            return mutations[0].get("id", "unknown").replace("money_doubling", "investment_ponzi")
        return "unknown"

    def _recommended_actions(
        self,
        score: float,
        mismatches: List,
        url_results: Optional[List],
        verify_mode: bool,
    ) -> List[str]:
        actions: List[str] = []
        if verify_mode:
            actions.extend(config.VERIFY_MODE_STEPS[:4])
        if score >= 75:
            actions.append("Do NOT send money or share OTP.")
            actions.append("Report immediately: Call 1930 or cybercrime.gov.in")
        if mismatches:
            actions.append("Official contact mismatch detected — use verified numbers only.")
        if url_results and any(u.get("is_malicious") for u in url_results):
            actions.append("Malicious URL detected — do not click any links.")
        if not actions:
            actions.append("Stay cautious. When in doubt, verify via official app or 1930.")
        return actions

    def _build_summary(
        self, score: float, verdict: str, category: str, mismatches: List
    ) -> str:
        parts = [f"Risk score {score}% — Verdict: {verdict}."]
        parts.append(f"Category: {category.replace('_', ' ').title()}.")
        if mismatches:
            parts.append(f"{len(mismatches)} official mismatch(es) detected.")
        return " ".join(parts)
