"""Write the client-facing report.

Claude is forced to answer through a tool whose input schema is the
ClientReport model, so the output is structured JSON rather than free text.
The result is then validated twice: by pydantic for shape, and by a
grounding check that every finding ID it cites actually exists. If either
check fails, the errors are sent back for one retry; if that also fails the
deterministic offline report is used instead.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from typing import Any

from pydantic import ValidationError

from .models import ClientReport, Finding, RiskItem

DEFAULT_MODEL = os.environ.get("SCANBRIEF_MODEL", "claude-sonnet-5-5")

SYSTEM_PROMPT = """You turn security scan findings into a report for a small healthcare
organization's office manager and owner. They are not technical.

Rules:
- Use only the findings provided. Cite their IDs in finding_ids. Never invent hosts, ports or issues.
- Group findings that share one fix into a single risk item. Order risks by the given score.
- Write at an 8th-grade reading level. Spell out acronyms or avoid them.
- Be specific about impact (e.g. "patient records could be copied") without exaggerating.
- Fix steps are instructions the IT contractor can follow; keep each to one sentence.
- Do not claim the organization is or is not HIPAA compliant."""

AUDIENCE_NOTES = {
    "executive": "Audience: the practice owner. Keep it brief and focused on decisions and cost of inaction.",
    "technical": "Audience: the IT contractor. You may name ports, headers and protocols in fix steps.",
}

REPORT_TOOL = {
    "name": "write_report",
    "description": "Submit the finished client report.",
    "input_schema": ClientReport.model_json_schema(),
}


class ReportError(RuntimeError):
    pass


def _findings_payload(findings: list[Finding]) -> str:
    keep = ("id", "asset_name", "host", "title", "severity", "score", "detail", "evidence", "fix")
    return json.dumps([{k: getattr(f, k) for k in keep} for f in findings], indent=1)


def grounding_errors(report: ClientReport, findings: list[Finding]) -> list[str]:
    known = {f.id for f in findings}
    errors = []
    for i, risk in enumerate(report.risks):
        unknown = [fid for fid in risk.finding_ids if fid not in known]
        if unknown:
            errors.append(f"risks[{i}] cites finding IDs that don't exist: {unknown}")
    actionable = {f.id for f in findings if f.severity in {"critical", "high"}}
    covered = {fid for r in report.risks for fid in r.finding_ids}
    missing = sorted(actionable - covered)
    if missing:
        errors.append(f"These critical/high findings are not covered by any risk item: {missing}")
    return errors


def ai_report(findings: list[Finding], client: Any = None, audience: str = "executive",
              model: str = DEFAULT_MODEL, max_attempts: int = 2) -> tuple[ClientReport, list[str]]:
    """Return (report, log). Raises ReportError if no valid report was produced."""
    if client is None:
        import anthropic
        client = anthropic.Anthropic()
    reportable = [f for f in findings if f.severity != "info"]
    messages: list[dict] = [{"role": "user", "content": (
        f"{AUDIENCE_NOTES[audience]}\n\nFindings (already scored, highest first):\n"
        f"{_findings_payload(reportable)}"
    )}]
    log: list[str] = []
    for attempt in range(1, max_attempts + 1):
        response = client.messages.create(
            model=model, max_tokens=4000, system=SYSTEM_PROMPT, messages=messages,
            tools=[REPORT_TOOL], tool_choice={"type": "tool", "name": "write_report"},
        )
        block = next((b for b in response.content if getattr(b, "type", None) == "tool_use"), None)
        if block is None:
            raise ReportError("Model did not return a report.")
        try:
            report = ClientReport.model_validate(block.input)
            errors = grounding_errors(report, reportable)
        except ValidationError as exc:
            report, errors = None, [f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()]
        if not errors:
            log.append(f"attempt {attempt}: valid")
            return report, log
        log.append(f"attempt {attempt}: rejected ({len(errors)} problems)")
        messages += [
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": block.id, "name": block.name, "input": block.input}]},
            {"role": "user", "content": [{
                "type": "tool_result", "tool_use_id": block.id, "is_error": True,
                "content": "Fix these problems and call write_report again:\n- " + "\n- ".join(errors),
            }]},
        ]
    raise ReportError("; ".join(log))


def offline_report(findings: list[Finding]) -> ClientReport:
    """Deterministic report built from the knowledge base, used without an API key."""
    reportable = [f for f in findings if f.severity != "info"]
    groups: dict[str, list[Finding]] = {}
    for f in reportable:
        groups.setdefault(f.title, []).append(f)
    # Groups holding critical/high findings always make the cut before lower ones.
    urgent = {"critical", "high"}
    ordered = sorted(groups.items(), key=lambda kv: not any(f.severity in urgent for f in kv[1]))
    risks = []
    for title, items in ordered[:8]:
        lead = items[0]
        where = ", ".join(sorted({f.asset_name for f in items}))
        risks.append(RiskItem(
            finding_ids=[f.id for f in items], title=title,
            what_it_means=f"{lead.detail} Found on: {where}.",
            why_it_matters=f"Rated {lead.severity} (priority {lead.score}/10)"
            + (" on a system that handles patient data." if any(
                "patient data" in r for f in items for r in f.score_reasons) else "."),
            fix_steps=[lead.fix],
            owner="Web developer" if lead.source == "zap" else "IT / network",
            effort="About a day" if lead.severity in {"critical", "high"} else "Under an hour",
        ))
    if not risks:
        risks = [RiskItem(finding_ids=[findings[0].id] if findings else ["S-00"],
                          title="No significant issues", what_it_means="The scan found nothing urgent.",
                          why_it_matters="Keep scanning regularly.", fix_steps=["Re-scan quarterly."],
                          owner="IT / network", effort="Under an hour")]
    sev = Counter(f.severity for f in reportable)
    overall = ("Critical" if sev["critical"] else "High" if sev["high"]
               else "Moderate" if sev["medium"] else "Low")
    return ClientReport(
        headline=f"{len(reportable)} issues found; {sev['critical'] + sev['high']} need attention this week.",
        overall_risk=overall,
        summary=(f"The scan covered {len({f.asset_name for f in findings})} systems. "
                 f"{sev['critical']} critical and {sev['high']} high-risk issues should be fixed first."),
        risks=risks,
        quick_wins=[r.fix_steps[0] for r in risks if r.effort == "Under an hour"][:5],
        questions_for_client=["Which of these systems are supposed to be reachable from the internet?"],
    )


def to_markdown(report: ClientReport, findings: list[Finding], generated_by: str) -> str:
    by_id = {f.id: f for f in findings}
    out = [f"# Security scan summary\n\n**{report.headline}**\n",
           f"Overall risk: **{report.overall_risk}**\n\n{report.summary}\n", "## What to fix, in order\n"]
    for n, r in enumerate(report.risks, start=1):
        systems = sorted({by_id[i].asset_name for i in r.finding_ids if i in by_id})
        out.append(f"### {n}. {r.title}\n")
        out.append(f"*Systems: {', '.join(systems)} · Owner: {r.owner} · Effort: {r.effort} · "
                   f"Findings: {', '.join(r.finding_ids)}*\n")
        out.append(f"**What it means.** {r.what_it_means}\n\n**Why it matters.** {r.why_it_matters}\n")
        out.append("**How to fix it**\n\n" + "\n".join(f"1. {s}" for s in r.fix_steps) + "\n")
    if report.quick_wins:
        out.append("## Quick wins\n\n" + "\n".join(f"- {w}" for w in report.quick_wins) + "\n")
    if report.questions_for_client:
        questions = "\n".join(f"- {q}" for q in report.questions_for_client)
        out.append(f"## Questions for you\n\n{questions}\n")
    out.append("## Appendix: all findings\n\n"
               "| ID | Score | Severity | System | Issue | Related HIPAA safeguard |\n"
               "|---|---|---|---|---|---|")
    for f in findings:
        out.append(f"| {f.id} | {f.score} | {f.severity} | {f.asset_name} | {f.title} "
                   f"| {f.safeguard or '—'} |")
    out.append(f"\n<sub>Generated by ScanBrief ({generated_by}). HIPAA references are a starting point "
               "for discussion, not a compliance determination.</sub>\n")
    return "\n".join(out)
