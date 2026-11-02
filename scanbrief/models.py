"""Data models shared by the parsers, scorer and report writer."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Asset(BaseModel):
    """Business context the scanner can't see, supplied by whoever ran the scan."""
    name: str
    internet_facing: bool = False
    handles_phi: bool = False
    owner: str = "IT"


class Finding(BaseModel):
    id: str
    source: Literal["nmap", "zap"]
    host: str
    asset_name: str
    title: str
    severity: Severity
    confidence: Literal["high", "medium", "low"] = "high"
    detail: str
    evidence: list[str] = Field(default_factory=list)
    fix: str
    safeguard: str | None = None        # related HIPAA Security Rule safeguard, if any
    score: float = 0.0
    score_reasons: list[str] = Field(default_factory=list)


Owner = Literal["IT / network", "Web developer", "Software vendor", "Practice leadership"]
Effort = Literal["Under an hour", "About a day", "A week or more"]


class RiskItem(BaseModel):
    finding_ids: list[str] = Field(min_length=1, description="IDs of the findings this item covers")
    title: str = Field(description="Short plain-English name, no acronyms")
    what_it_means: str = Field(description="One or two sentences a non-technical manager understands")
    why_it_matters: str = Field(description="Business or patient-data impact, concrete")
    fix_steps: list[str] = Field(min_length=1, max_length=5)
    owner: Owner
    effort: Effort


class ClientReport(BaseModel):
    headline: str = Field(description="One sentence overall verdict")
    overall_risk: Literal["Critical", "High", "Moderate", "Low"]
    summary: str = Field(description="Two or three sentences, no jargon")
    risks: list[RiskItem] = Field(min_length=1, max_length=8, description="Most urgent first")
    quick_wins: list[str] = Field(max_length=5, description="Fixes that take under an hour")
    questions_for_client: list[str] = Field(max_length=4,
                                            description="What we need to know to finish the assessment")
