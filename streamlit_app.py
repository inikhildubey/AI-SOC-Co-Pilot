# streamlit_app.py
"""
SOC Co-Pilot (Hackathon-ready prototype)
- Upload a JSON log or paste JSON text
- Parse key fields
- Rule-based MITRE mapping (fast + deterministic)
- Call an LLM to produce: plain-English summary, severity, recommended action, and a Slack alert text.
- Shows everything in a neat Streamlit UI.

Requirements: openai, streamlit, python-dotenv
Set OPENAI_API_KEY in environment or .env file.
"""

import json
import os
import textwrap
from datetime import datetime
from typing import Dict, Optional

import streamlit as st
from dotenv import load_dotenv

# local MITRE mapping module
from mitre_mapping import MITRE_RULES

# Load env
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

USE_OLLAMA = False  # if you want to use Ollama local API, set True and ensure ollama is running

if not OPENAI_API_KEY and not USE_OLLAMA:
    st.warning("No OpenAI API key found. Set OPENAI_API_KEY in your environment or .env for LLM features.")
    # The app will still run but LLM calls will be disabled.

# simple helper: parse JSON safely
def parse_json_text(text: str) -> Optional[Dict]:
    try:
        return json.loads(text)
    except Exception:
        return None

# extract some commonly useful fields from CloudTrail / generic logs
def extract_fields(log: Dict) -> Dict:
    out = {}
    # Known CloudTrail-ish fields
    for k in ("eventTime", "eventName", "eventSource", "userIdentity", "sourceIPAddress", "responseElements"):
        if k in log:
            out[k] = log[k]
    # userName handling
    try:
        user = log.get("userIdentity", {})
        out["userName"] = user.get("userName") or user.get("arn") or user.get("principalId")
    except Exception:
        pass
    # fallback: keep top-level raw
    out["raw_preview"] = json.dumps(log, indent=2)[:2000]
    return out

# rule-based MITRE mapping
def map_to_mitre(log_text: str):
    matches = []
    text_lower = log_text.lower()
    for keyword, tactic, desc in MITRE_RULES:
        if keyword in text_lower:
            matches.append({"keyword": keyword, "tactic": tactic, "description": desc})
    return matches

# simple severity heuristic (expandable)
def severity_score(log_text: str, mitre_matches):
    score = 0
    text = log_text.lower()
    if "failure" in text or "failed" in text or "invalid" in text:
        score += 2
    if "root" in text or "administrator" in text or "privilege" in text or "iam" in text:
        score += 3
    if any(m["tactic"] == "Impact" for m in mitre_matches):
        score += 4
    if "consolelogin" in text or "console_login" in text or "consolelogin" in text:
        score += 2
    # map numeric score to qualitative
    if score >= 6:
        return "Critical"
    if score >= 4:
        return "High"
    if score >= 2:
        return "Medium"
    return "Low"

# wrapper to call LLM (OpenAI by default)
def call_llm_summary(parsed_fields: Dict, raw_log_text: str) -> Dict:
    """
    Returns: {"summary": str, "recommended_action": str, "slack_alert": str}
    Uses OpenAI ChatCompletion (or Ollama local API if configured).
    """
    # Basic prompt engineering: keep concise, give system role and examples
    system_prompt = (
        "You are a security analyst assistant. Given a parsed security log and raw log content, "
        "produce: 1) a concise human-readable summary (1-3 sentences), "
        "2) suggested immediate action(s) the analyst can take (short bullet list), "
        "3) a one-line Slack alert message suitable for SOC channel. "
        "Be conservative (avoid hallucinations). If you are unsure, say so."
    )

    parsed_text = json.dumps(parsed_fields, indent=2)

    user_prompt = textwrap.dedent(
        f"""
        Parsed fields:
        {parsed_text}

        Raw log (truncated):
        {raw_log_text[:3000]}

        Produce JSON with keys: summary, recommended_actions (list), slack_alert.
        """
    )

    # Use OpenAI if available
    if OPENAI_API_KEY and not USE_OLLAMA:
        import openai

        openai.api_key = OPENAI_API_KEY
        try:
            resp = openai.ChatCompletion.create(
                model="gpt-4o-mini" if "gpt-4o-mini" in openai.Model.list()["data"][0]["id"] else "gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=400,
                temperature=0.0,
            )
            content = resp["choices"][0]["message"]["content"]
        except Exception as e:
            # fallback with safer request (some environments may not have gpt-4o-mini)
            try:
                resp = openai.ChatCompletion.create(
                    model="gpt-4o",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    max_tokens=400,
                    temperature=0.0,
                )
                content = resp["choices"][0]["message"]["content"]
            except Exception as e2:
                return {"summary": f"LLM call failed: {str(e2)}", "recommended_actions": [], "slack_alert": ""}
    elif USE_OLLAMA:
        # Example of calling local Ollama HTTP API (adjust host/port if needed)
        try:
            import requests

            ollama_url = "http://localhost:11434/api/chat"  # Ollama default
            payload = {
                "model": "llama3.2:7b",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "max_tokens": 400,
                "temperature": 0.0,
            }
            r = requests.post(ollama_url, json=payload, timeout=30)
            r.raise_for_status()
            content = r.json().get("response") or r.text
        except Exception as e:
            return {"summary": f"Ollama call failed: {str(e)}", "recommended_actions": [], "slack_alert": ""}
    else:
        # LLM disabled / no key — return placeholders
        return {
            "summary": "LLM disabled (no API key). Install OPENAI_API_KEY to enable summaries.",
            "recommended_actions": [],
            "slack_alert": "",
        }

    # Try to parse JSON response from LLM; if not JSON, fallback to plain texts
    try:
        maybe_json = json.loads(content)
        summary = maybe_json.get("summary", "")
        actions = maybe_json.get("recommended_actions", [])
        slack_alert = maybe_json.get("slack_alert", "")
    except Exception:
        # If LLM returned text, heuristically split
        summary = content.strip().split("\n\n")[0][:800]
        actions = []
        slack_alert = ""
    return {"summary": summary, "recommended_actions": actions, "slack_alert": slack_alert}


# Streamlit UI
st.set_page_config(page_title="SOC Co-Pilot (Hackathon)", layout="wide")
st.title("SOC Co-Pilot — Demo (Upload a log to analyze)")

col1, col2 = st.columns([1, 1])

with col1:
    st.header("Log input")
    upload = st.file_uploader("Upload log (JSON)", type=["json", "txt"])
    raw_input_text = st.text_area("Or paste log JSON here:", height=200)
    if upload is not None:
        try:
            raw_input_text = upload.getvalue().decode("utf-8")
        except Exception:
            raw_input_text = str(upload.getvalue())

    st.markdown("**Example logs:**")
    st.markdown("- CloudTrail login failure (example provided).")
    st.markdown("- Paste a generated SIEM/GuardDuty event as JSON.")

    analyze_button = st.button("Analyze log")

with col2:
    st.header("Results")
    result_area = st.empty()

if analyze_button:
    if not raw_input_text.strip():
        st.error("Please upload or paste a JSON log.")
    else:
        parsed = parse_json_text(raw_input_text)
        if not parsed:
            st.error("Invalid JSON — please paste a valid JSON log.")
        else:
            fields = extract_fields(parsed)
            # prepare a textual representation for rules
            raw_text = json.dumps(parsed, indent=2)
            mitre_matches = map_to_mitre(raw_text)
            severity = severity_score(raw_text, mitre_matches)
            # call LLM to generate explanation and action
            llm_result = call_llm_summary(fields, raw_text)

            # display
            with result_area.container():
                st.subheader("Parsed Key Fields")
                st.json(fields)

                st.subheader("MITRE ATT&CK mapping (rule-based)")
                if mitre_matches:
                    for m in mitre_matches:
                        st.markdown(f"- **{m['tactic']}** (keyword `{m['keyword']}`): {m['description']}")
                else:
                    st.markdown("_No deterministic MITRE match found (you can expand rules)._")

                st.subheader("Severity")
                if severity == "Critical":
                    st.markdown(f"🔴 **{severity}**")
                elif severity == "High":
                    st.markdown(f"🔴 **{severity}**")
                elif severity == "Medium":
                    st.markdown(f"🟡 **{severity}**")
                else:
                    st.markdown(f"🟢 **{severity}**")

                st.subheader("LLM Summary & Recommended Actions")
                st.markdown("**Summary:**")
                st.write(llm_result.get("summary", ""))

                st.markdown("**Recommended actions:**")
                actions = llm_result.get("recommended_actions") or []
                if actions:
                    for a in actions:
                        st.markdown(f"- {a}")
                else:
                    st.markdown("_LLM provided no specific actions (or LLM disabled). Try enabling OPENAI_API_KEY._")

                st.subheader("Suggested Slack alert")
                if llm_result.get("slack_alert"):
                    st.code(llm_result["slack_alert"])
                else:
                    # generate a basic fallback slack alert
                    alert = f"[{severity}] Suspicious event: {fields.get('eventName','<unknown>')} for {fields.get('userName','<unknown>')} from {fields.get('sourceIPAddress','<unknown>')}"
                    st.code(alert)

                st.subheader("Raw log (truncated)")
                st.code(raw_text[:4000])

# small footer / tips
st.markdown("---")
st.caption("Notes: This is a demo prototype. Do not rely on LLM outputs for automated blocking without human review.")
