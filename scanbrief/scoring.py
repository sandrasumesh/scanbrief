"""Transparent priority scoring.

Every point added to a score comes with a written reason, so a reviewer can
see why one issue was ranked above another.
"""

from __future__ import annotations

from .models import SEVERITY_RANK, Asset, Finding

BASE = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0, "info": 1.0}


def score(finding: Finding, asset: Asset) -> Finding:
    points = BASE[finding.severity]
    reasons = [f"{finding.severity} severity (+{BASE[finding.severity]:g})"]
    if asset.internet_facing and finding.severity != "info":
        points += 1.5
        reasons.append("reachable from the internet (+1.5)")
    if asset.handles_phi and finding.severity != "info":
        points += 1.0
        reasons.append("system stores or transmits patient data (+1)")
    if finding.confidence == "low":
        points -= 1.0
        reasons.append("scanner has low confidence (-1)")
    return finding.model_copy(update={"score": round(min(points, 10.0), 1), "score_reasons": reasons})


def prioritize(findings: list[Finding], assets: dict[str, Asset]) -> list[Finding]:
    by_name = {a.name: a for a in assets.values()}
    scored = [score(f, by_name.get(f.asset_name, Asset(name=f.asset_name))) for f in findings]
    scored.sort(key=lambda f: (-f.score, SEVERITY_RANK[f.severity], f.asset_name, f.title))
    return [f.model_copy(update={"id": f"S-{i:02d}"}) for i, f in enumerate(scored, start=1)]
