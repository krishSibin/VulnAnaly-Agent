"""
Vulnerability Analysis Agent — Dual LLM Mode
─────────────────────────────────────────────
HOME MODE  : Uses Google Gemini API directly (GEMINI_API_KEY in .env)
LAB MODE   : Uses TCS LiteLLM Gateway at https://genailab.tcs.in (TCS_GATEWAY_KEY in .env)

The agent auto-selects the mode based on which key is set in the environment.
Both modes fall back gracefully to heuristic analysis if neither key is available.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional

from remediation_engine import RemediationFixEngine

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────
#  LLM MODE DETECTION
# ─────────────────────────────────────────────────────────
LLM_MODE_HOME = "home"       # Direct Google Gemini API  (gemini-2.5-flash)
LLM_MODE_LAB  = "lab"        # TCS LiteLLM Gateway        (gemini-2.5-flash via genailab.tcs.in)
LLM_MODE_NONE = "heuristic"  # No LLM key — rule-based fallback


def _detect_llm_mode(gemini_key: Optional[str], tcs_key: Optional[str]) -> str:
    if tcs_key:
        return LLM_MODE_LAB
    if gemini_key:
        return LLM_MODE_HOME
    return LLM_MODE_NONE


# ─────────────────────────────────────────────────────────
#  HOME MODE: Google GenAI SDK (google-genai)
# ─────────────────────────────────────────────────────────
def _call_gemini_home(prompt: str, api_key: str) -> Optional[Dict]:
    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.2,
            ),
        )
        if response.text:
            return json.loads(response.text)
    except Exception as e:
        logger.error(f"[HOME MODE] Gemini API error: {e}")
    return None


# ─────────────────────────────────────────────────────────
#  LAB MODE: TCS LiteLLM Gateway (OpenAI-compatible REST)
# ─────────────────────────────────────────────────────────
TCS_GATEWAY_URL   = "https://genailab.tcs.in/v1/chat/completions"
TCS_GATEWAY_MODEL = "gemini-2.5-flash"   # Approved model as per handbook


def _call_tcs_gateway(prompt: str, api_key: str) -> Optional[Dict]:
    """
    Calls the TCS LiteLLM Gateway which exposes an OpenAI-compatible endpoint.
    Uses standard HTTP so no additional SDK is required.
    """
    import urllib.request

    payload = json.dumps({
        "model": TCS_GATEWAY_MODEL,
        "messages": [
            {
                "role": "system",
                "content": "You are an expert Cyber Security Vulnerability Remediation Agent. Always respond in valid JSON only."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"}
    }).encode()

    req = urllib.request.Request(
        TCS_GATEWAY_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
            content = result["choices"][0]["message"]["content"]
            return json.loads(content)
    except Exception as e:
        logger.error(f"[LAB MODE] TCS Gateway error: {e}")
    return None


# ─────────────────────────────────────────────────────────
#  VULNERABILITY AGENT
# ─────────────────────────────────────────────────────────
class VulnerabilityAgent:
    """
    AI-powered Vulnerability Remediation Agent with dual LLM support:

    • Home Mode  → Google Gemini API (GEMINI_API_KEY)
    • Lab Mode   → TCS LiteLLM Gateway (TCS_GATEWAY_KEY) for hackathon demo
    • Heuristic  → Rule-based fallback (works offline, no keys needed)

    Responsibilities:
    1. Prioritize vulnerabilities by risk score, rating, and business impact.
    2. Analyze each vulnerability with Gemini LLM (impact, CVE details).
    3. Formulate change request / team approval messages.
    4. Coordinate remediation dispatch to the correct server node.
    """

    def __init__(
        self,
        gemini_api_key: Optional[str] = None,
        tcs_gateway_key: Optional[str] = None,
    ):
        self.gemini_key  = gemini_api_key  or os.getenv("GEMINI_API_KEY", "")
        self.tcs_key     = tcs_gateway_key or os.getenv("TCS_GATEWAY_KEY", "")
        self.llm_mode    = _detect_llm_mode(self.gemini_key, self.tcs_key)

        # Backwards-compat: expose .api_key so main.py can check if any key is set
        self.api_key = self.tcs_key or self.gemini_key or None

        mode_labels = {
            LLM_MODE_HOME: "✅ Home Mode  — Google Gemini API (gemini-2.5-flash)",
            LLM_MODE_LAB:  "✅ Lab Mode   — TCS LiteLLM Gateway (genailab.tcs.in)",
            LLM_MODE_NONE: "⚠️  Heuristic  — No API key set. Using rule-based analysis.",
        }
        logger.info(f"[AGENT] LLM Mode: {mode_labels[self.llm_mode]}")

    @property
    def mode_label(self) -> str:
        labels = {
            LLM_MODE_HOME: "Google Gemini API (Home)",
            LLM_MODE_LAB:  "TCS LiteLLM Gateway (Lab)",
            LLM_MODE_NONE: "Heuristic / Rule-based",
        }
        return labels.get(self.llm_mode, "Unknown")

    # ── Prioritization ────────────────────────────────────
    def prioritize_vulnerabilities(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sorts vulnerabilities so HIGHEST risk is processed first.
        Scoring logic:
          Risk Rating   → Critical +1000, High +500, Moderate +200
          Business Impact → Critical +300, Significant +150
          Risk Score    → raw value added (0-100)
        """
        def _rank(item: Dict[str, Any]) -> int:
            score  = item.get("risk_score", 0)
            rating = str(item.get("risk_rating", "")).lower()
            impact = str(item.get("business_impact", "")).lower()
            bonus  = 0

            if "1 - critical" in rating or rating == "critical":
                bonus += 1000
            elif "2 - high" in rating or rating == "high":
                bonus += 500
            elif "3 - moderate" in rating or "medium" in rating:
                bonus += 200

            if "1 - critical" in impact:
                bonus += 300
            elif "2 - significant" in impact:
                bonus += 150

            return bonus + score

        return sorted(items, key=_rank, reverse=True)

    # ── LLM Prompt Builder ───────────────────────────────
    def _build_prompt(self, vuln: Dict[str, Any], fix: Dict[str, Any]) -> str:
        return f"""
You are an expert Cyber Security Vulnerability Remediation Agent.

Analyze this Qualys vulnerability finding from ServiceNow:

Vulnerability Details:
- Target Host/Server : {vuln.get('configuration_item', 'Unknown')}
- Summary            : {vuln.get('summary', '')}
- Software Path      : {vuln.get('description', '')}
- Risk Rating        : {vuln.get('risk_rating', 'Unknown')}
- Risk Score         : {vuln.get('risk_score', 0)} / 100
- Qualys QID         : {vuln.get('qid', '')}
- Assigned Team      : {vuln.get('assignment_group', 'S-TCS-DC-WINTEL')}
- Environment        : {vuln.get('operating_environment', 'Production')}
- Remediation Task   : {vuln.get('remediation_task', '')}

Detected Patch Strategy:
- Patch Type         : {fix['patch_type']}
- Target Software    : {fix['target_software']}
- Recommended Action : {fix['recommended_action']}
- Download Source    : {fix['dl_source']}
- Reboot Required    : {fix['requires_reboot']}

Respond ONLY with a valid JSON object containing:
{{
  "risk_assessment": "<2-sentence explanation of why this is dangerous>",
  "approval_request_message": "<formal approval request to the team>",
  "remediation_plan": ["step 1", "step 2", "step 3"],
  "patch_urgency": "IMMEDIATE" | "STANDARD_MAINTENANCE" | "LOW"
}}
"""

    # ── Main Analysis Method ─────────────────────────────
    def analyze_vulnerability_with_llm(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze vulnerability with LLM (or fallback to heuristics).
        Returns the enriched vulnerability dict with fix strategy and LLM analysis.
        """
        fix = RemediationFixEngine.identify_remediation_strategy(vuln)
        llm_result = None

        # ── Try LLM call based on active mode ───────────
        if self.llm_mode == LLM_MODE_HOME and self.gemini_key:
            prompt    = self._build_prompt(vuln, fix)
            llm_result = _call_gemini_home(prompt, self.gemini_key)

        elif self.llm_mode == LLM_MODE_LAB and self.tcs_key:
            prompt    = self._build_prompt(vuln, fix)
            llm_result = _call_tcs_gateway(prompt, self.tcs_key)

        # ── Heuristic fallback if LLM failed / not available ─
        if not llm_result:
            risk_score = vuln.get("risk_score", 0)
            urgency    = (
                "IMMEDIATE"            if risk_score >= 90
                else "STANDARD_MAINTENANCE" if risk_score >= 70
                else "LOW"
            )
            ci     = vuln.get("configuration_item", "Unknown-Host")
            team   = vuln.get("assignment_group",   "S-TCS-DC-WINTEL")
            env    = vuln.get("operating_environment", "Production")
            task   = vuln.get("remediation_task", "N/A")
            summ   = vuln.get("summary", "")

            llm_result = {
                "risk_assessment": (
                    f"Vulnerability '{summ}' compromises host {ci} with a risk "
                    f"score of {risk_score}. Unpatched, this allows remote code "
                    f"execution or privilege escalation in the {env} environment."
                ),
                "approval_request_message": (
                    f"Team {team}: Automated Remediation Agent is requesting approval "
                    f"to apply a security patch on host {ci} ({env}). "
                    f"Action: {fix['recommended_action']}. "
                    f"ServiceNow Task: {task}."
                ),
                "remediation_plan": [
                    f"Obtain verified binary from {fix['dl_source']}",
                    f"Deploy patch silently on {ci} with reboot={'required' if fix['requires_reboot'] else 'NOT required'}",
                    f"Verify signature and close ServiceNow task {task}",
                ],
                "patch_urgency": urgency,
            }

        return {
            **vuln,
            "fix_strategy":      fix,
            "llm_analysis":      llm_result,
            "llm_mode_used":     self.mode_label,
            "approval_status":   "Pending",
            "responsible_team":  vuln.get("assignment_group", "S-TCS-DC-WINTEL"),
        }
