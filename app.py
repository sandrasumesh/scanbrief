"""Streamlit front end.  Run with:  streamlit run app.py"""

from __future__ import annotations

import os
from pathlib import Path

import streamlit as st

from scanbrief import ParseError, analyze, load_assets
from scanbrief.report import ReportError, ai_report, offline_report, to_markdown

SAMPLES = Path(__file__).parent / "samples"
st.set_page_config(page_title="ScanBrief", page_icon="🛡️", layout="wide")


def api_key() -> str | None:
    try:
        return st.secrets.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
    except Exception:
        return os.environ.get("ANTHROPIC_API_KEY")


st.title("ScanBrief")
st.caption("Turn Nmap and OWASP ZAP output into a ranked, plain-English report a clinic manager can act on.")

with st.sidebar:
    st.header("Inputs")
    uploads = st.file_uploader("Scan files (Nmap .xml, ZAP .json)", type=["xml", "json"],
                               accept_multiple_files=True)
    assets_file = st.file_uploader("assets.json (optional business context)", type="json")
    audience = st.radio("Report for", ["executive", "technical"],
                        format_func=lambda a: "Practice owner" if a == "executive" else "IT contractor")
    if not uploads:
        st.info("Showing the sample clinic. Upload your own scans to replace it.")

if uploads:
    files = {u.name: u.getvalue() for u in uploads}
    assets_raw = assets_file.getvalue() if assets_file else None
else:
    files = {p.name: p.read_bytes() for p in SAMPLES.iterdir()
             if p.suffix in {".xml", ".json"} and p.name != "assets.json"}
    assets_raw = (SAMPLES / "assets.json").read_bytes()

try:
    findings = analyze(files, load_assets(assets_raw))
except (ParseError, ValueError) as exc:
    st.error(f"Could not read the scan files: {exc}")
    st.stop()

counts = {s: sum(f.severity == s for f in findings) for s in ("critical", "high", "medium", "low")}
cols = st.columns(5)
cols[0].metric("Systems", len({f.asset_name for f in findings}))
for col, (sev, n) in zip(cols[1:], counts.items()):
    col.metric(sev.title(), n)

tab_report, tab_findings = st.tabs(["Client report", "Ranked findings"])

with tab_findings:
    st.dataframe(
        [{"ID": f.id, "Score": f.score, "Severity": f.severity, "System": f.asset_name,
          "Issue": f.title, "Why this score": "; ".join(f.score_reasons),
          "HIPAA safeguard": f.safeguard or ""} for f in findings],
        hide_index=True, use_container_width=True,
    )

with tab_report:
    key = api_key()
    use_ai = st.toggle("Write with Claude", value=bool(key), disabled=not key,
                       help=None if key else "Set ANTHROPIC_API_KEY to enable.")
    if st.button("Generate report", type="primary"):
        engine = "offline template"
        if use_ai:
            os.environ["ANTHROPIC_API_KEY"] = key
            with st.spinner("Writing and fact-checking the report..."):
                try:
                    report, log = ai_report(findings, audience=audience)
                    engine = "Claude, " + "; ".join(log)
                except ReportError as exc:
                    st.warning(f"The AI draft failed validation ({exc}), so this is the template version.")
                    report = offline_report(findings)
        else:
            report = offline_report(findings)
        st.session_state.report_md = to_markdown(report, findings, engine)
    if "report_md" in st.session_state:
        st.download_button("Download Markdown", st.session_state.report_md, file_name="scan_report.md")
        st.markdown(st.session_state.report_md)
