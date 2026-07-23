"""
YOUR SENTINEL — AI Model 4: Groq Llama Report Generator.

Generates 7-section professional police complaint documents
ready for cybercrime.gov.in submission.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

import config
from config import BNS_SECTIONS, IT_ACT_SECTIONS

logger = logging.getLogger("SENTINEL.AI.REPORT_GEN")


class ReportFormatter:
    """Formats 7-section complaint document structure."""

    SECTIONS = [
        "complainant_details",
        "nature_of_offence",
        "suspect_information",
        "forensic_analysis",
        "recommended_actions",
        "legal_sections",
        "declaration",
    ]

    @staticmethod
    def format_complainant(victim: Dict[str, Any]) -> str:
        lines = [
            "SECTION 1: COMPLAINANT DETAILS",
            "=" * 60,
            f"Full Name: {victim.get('victim_name', 'N/A')}",
            f"Mobile Number: {victim.get('victim_mobile', 'N/A')}",
            f"Email: {victim.get('victim_email', 'N/A')}",
            f"Address: {victim.get('victim_address', 'N/A')}",
            f"City: {victim.get('victim_city', 'N/A')}, State: {victim.get('victim_state', 'N/A')}",
            f"PIN Code: {victim.get('victim_pin', 'N/A')}",
            f"ID Proof: {victim.get('id_proof_type', 'N/A')} — {victim.get('id_proof_number', 'N/A')}",
            "",
        ]
        return "\n".join(lines)

    @staticmethod
    def format_nature(victim: Dict, scan: Optional[Dict]) -> str:
        lines = [
            "SECTION 2: NATURE OF OFFENCE",
            "=" * 60,
            f"Incident Date: {victim.get('incident_date', 'N/A')}",
            f"Incident Time: {victim.get('incident_time', 'N/A')}",
            f"Category: {scan.get('category', 'Cyber Fraud') if scan else 'Cyber Fraud'}",
            f"Amount Lost (INR): {victim.get('amount_lost', 0)}",
            f"Payment Method: {victim.get('payment_method', 'N/A')}",
            "",
            "INCIDENT NARRATIVE:",
            victim.get("incident_details", "As described by complainant."),
            "",
        ]
        if scan:
            lines.append(f"Scan Reference ID: {scan.get('scan_id', 'N/A')}")
            lines.append(f"AI Risk Assessment: {scan.get('risk_score', 0)}% ({scan.get('risk_level', 'N/A')})")
        return "\n".join(lines)

    @staticmethod
    def format_suspect(victim: Dict, scan: Optional[Dict]) -> str:
        phone = victim.get("suspect_phone") or (scan or {}).get("suspect_phone", "Unknown")
        upi = victim.get("suspect_upi") or (scan or {}).get("suspect_upi", "Unknown")
        web = victim.get("suspect_website") or (scan or {}).get("suspect_website", "Unknown")
        lines = [
            "SECTION 3: SUSPECT INFORMATION",
            "=" * 60,
            f"Suspect Phone Number: {phone}",
            f"Suspect UPI ID: {upi}",
            f"Suspect Website/URL: {web}",
            "",
            "ADDITIONAL SUSPECT DETAILS:",
            victim.get("suspect_details", "To be identified through investigation."),
            "",
        ]
        return "\n".join(lines)

    @staticmethod
    def format_forensic(scan: Optional[Dict], ai_narrative: str) -> str:
        lines = [
            "SECTION 4: FORENSIC ANALYSIS (AI-ASSISTED)",
            "=" * 60,
        ]
        if scan:
            lines.append(f"Verdict: {scan.get('verdict', 'SCAM')}")
            lines.append(f"Behaviour Triggers: {json.dumps(scan.get('behaviour_triggers', []), indent=2)[:2000]}")
            if scan.get("url_threats"):
                lines.append(f"URL Threats Detected: {json.dumps(scan.get('url_threats', []), indent=2)[:1500]}")
            if scan.get("mismatch_alerts"):
                lines.append(f"Official Mismatches: {json.dumps(scan.get('mismatch_alerts', []), indent=2)[:1500]}")
        lines.extend(["", "FORENSIC NARRATIVE:", ai_narrative or "See attached scan analysis.", ""])
        return "\n".join(lines)

    @staticmethod
    def format_actions(scan: Optional[Dict]) -> str:
        actions = (scan or {}).get("recommended_actions", [
            "Preserve all screenshots, SMS, call logs, and bank statements.",
            "Report on National Cyber Crime Portal: https://cybercrime.gov.in",
            "Call National Cyber Crime Helpline: 1930",
            "Contact your bank to freeze/lodge dispute for fraudulent transactions.",
            "Do not delete any communication with the suspect.",
        ])
        lines = ["SECTION 5: RECOMMENDED ACTIONS", "=" * 60]
        for i, a in enumerate(actions, 1):
            lines.append(f"{i}. {a}")
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def format_legal() -> str:
        lines = [
            "SECTION 6: APPLICABLE LEGAL PROVISIONS",
            "=" * 60,
            "Information Technology Act, 2000:",
        ]
        for s in IT_ACT_SECTIONS:
            lines.append(f"  • {s}")
        lines.append("")
        lines.append("Bharatiya Nyaya Sanhita (BNS), 2023:")
        for s in BNS_SECTIONS:
            lines.append(f"  • {s}")
        lines.append("")
        lines.append(
            "This complaint is filed under the jurisdiction of the Cyber Crime Cell "
            "as per the National Cyber Crime Reporting Portal guidelines."
        )
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def format_declaration(victim: Dict) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lines = [
            "SECTION 7: DECLARATION & SIGNATURE",
            "=" * 60,
            "I hereby declare that the information provided above is true and correct "
            "to the best of my knowledge and belief. I understand that filing a false "
            "complaint is punishable under applicable Indian law.",
            "",
            f"Complainant Name: {victim.get('victim_name', '')}",
            f"Date of Filing: {now}",
            "",
            "Signature: _________________________",
            "",
            "FOR POLICE USE ONLY:",
            "FIR No.: _______________  Date: _______________",
            "Investigating Officer: _______________",
            "Police Station: _______________",
            "",
            "--- End of Complaint Document ---",
            "File at: https://cybercrime.gov.in | Helpline: 1930",
        ]
        return "\n".join(lines)

    @classmethod
    def build_full_report(
        cls,
        victim: Dict[str, Any],
        scan: Optional[Dict[str, Any]],
        ai_narrative: str = "",
    ) -> Dict[str, str]:
        sections = {
            "complainant_details": cls.format_complainant(victim),
            "nature_of_offence": cls.format_nature(victim, scan),
            "suspect_information": cls.format_suspect(victim, scan),
            "forensic_analysis": cls.format_forensic(scan, ai_narrative),
            "recommended_actions": cls.format_actions(scan),
            "legal_sections": cls.format_legal(),
            "declaration": cls.format_declaration(victim),
        }
        full_text = "\n".join(sections[s] for s in cls.SECTIONS)
        return {"sections": sections, "full_text": full_text}


class GroqClient:
    """Groq API client for Llama 3.1 8B instant."""

    API_URL = "https://api.groq.com/openai/v1/chat/completions"

    def __init__(self) -> None:
        self.api_key = config.GROQ_API_KEY
        self.model = config.GROQ_MODEL

    def available(self) -> bool:
        return bool(self.api_key and self.api_key != "YOUR_KEY_HERE")

    async def generate(self, prompt: str, max_tokens: int = 4096) -> str:
        if not self.available():
            return ""
        try:
            async with httpx.AsyncClient(timeout=90.0) as client:
                resp = await client.post(
                    self.API_URL,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {
                                "role": "system",
                                "content": (
                                    "You are a legal document writer for Indian cybercrime complaints. "
                                    "Write formal legal English suitable for police and cybercrime.gov.in."
                                ),
                            },
                            {"role": "user", "content": prompt},
                        ],
                        "max_tokens": max_tokens,
                        "temperature": 0.3,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data["choices"][0]["message"]["content"]
                logger.warning("Groq status %s", resp.status_code)
        except Exception as exc:
            logger.error("Groq generate failed: %s", exc)
        return ""


class ReportGenerator:
    """AI 4: generates complete police complaint."""

    def __init__(self) -> None:
        self.groq = GroqClient()
        self.formatter = ReportFormatter()

    async def generate_complaint(
        self,
        victim: Dict[str, Any],
        scan: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        try:
            scan_summary = ""
            if scan:
                scan_summary = json.dumps({
                    "scan_id": scan.get("scan_id"),
                    "risk_score": scan.get("risk_score"),
                    "category": scan.get("category"),
                    "summary": scan.get("summary"),
                    "input_text": (scan.get("input_text") or "")[:3000],
                    "mismatch_alerts": scan.get("mismatch_alerts"),
                    "url_threats": scan.get("url_threats"),
                }, indent=2)
            ai_narrative = ""
            if self.groq.available():
                prompt = (
                    f"Write a detailed forensic analysis section (600+ words) for an Indian cybercrime "
                    f"police complaint. Use formal legal English.\n\n"
                    f"Victim: {victim.get('victim_name')}, lost INR {victim.get('amount_lost', 0)}\n"
                    f"Incident: {victim.get('incident_details', '')}\n"
                    f"Scan data:\n{scan_summary}\n\n"
                    "Include: timeline, modus operandi, technical indicators, psychological manipulation "
                    "tactics used, and connection to known Indian scam patterns."
                )
                ai_narrative = await self.groq.generate(prompt)
            if not ai_narrative or len(ai_narrative) < 200:
                ai_narrative = self._template_narrative(victim, scan)
            report = self.formatter.build_full_report(victim, scan, ai_narrative)
            return {
                "complaint_text": report["full_text"],
                "complaint_sections": report["sections"],
                "forensic_narrative": ai_narrative,
                "generated_by": "groq" if self.groq.available() else "template",
            }
        except Exception as exc:
            logger.error("generate_complaint failed: %s", exc)
            report = self.formatter.build_full_report(
                victim, scan, self._template_narrative(victim, scan)
            )
            return {
                "complaint_text": report["full_text"],
                "complaint_sections": report["sections"],
                "forensic_narrative": report["sections"].get("forensic_analysis", ""),
                "generated_by": "template_fallback",
            }

    def _template_narrative(
        self, victim: Dict[str, Any], scan: Optional[Dict[str, Any]]
    ) -> str:
        paragraphs = [
            (
                f"The complainant, {victim.get('victim_name', 'the victim')}, hereby reports a cybercrime "
                f"incident that occurred on {victim.get('incident_date', 'the reported date')}. "
                f"The matter falls under the category of {(scan or {}).get('category', 'cyber fraud').replace('_', ' ')} "
                f"as classified by the AI-assisted forensic analysis system Your Sentinel."
            ),
            (
                f"The incident involved fraudulent communication wherein the complainant was induced "
                f"to transfer funds amounting to INR {victim.get('amount_lost', 0)} via "
                f"{victim.get('payment_method', 'electronic payment')}. The suspect utilized "
                f"communication channels including phone number {victim.get('suspect_phone', 'unknown')} "
                f"and/or UPI identifier {victim.get('suspect_upi', 'unknown')}."
            ),
            (
                f"Forensic analysis indicates a risk score of {(scan or {}).get('risk_score', 'N/A')}% "
                f"with verdict {(scan or {}).get('verdict', 'SCAM')}. Multiple indicators of social engineering "
                f"were detected including urgency creation, authority impersonation, and/or credential harvesting attempts. "
                f"This modus operandi is consistent with prevalent cyber fraud patterns reported across India in 2024-2026."
            ),
            (
                "The complainant has preserved available digital evidence including message screenshots, "
                "transaction records, and call logs. It is requested that the investigating agency: "
                "(1) register an FIR under applicable IT Act and BNS provisions; "
                "(2) issue notices to telecom and payment service providers for KYC details of suspect accounts; "
                "(3) freeze suspect accounts under CrPC provisions; "
                "(4) coordinate with the National Cyber Crime Reporting Portal for centralized tracking."
            ),
            (
                f"Detailed incident description as provided by complainant: "
                f"{victim.get('incident_details', 'See Section 2 above.')}"
            ),
        ]
        return "\n\n".join(paragraphs)
