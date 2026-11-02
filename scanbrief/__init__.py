"""ScanBrief: turn raw security scan output into a prioritized, plain-English client report."""

from __future__ import annotations

import json
from pathlib import Path

from .models import Asset, ClientReport, Finding
from .parsers import ParseError, detect_and_parse
from .scoring import prioritize

__all__ = ["Asset", "ClientReport", "Finding", "ParseError", "analyze", "load_assets", "load_folder"]
__version__ = "0.1.0"


def load_assets(data: bytes | str | None) -> dict[str, Asset]:
    if not data:
        return {}
    return {host: Asset(**info) for host, info in json.loads(data).items()}


def analyze(files: dict[str, bytes], assets: dict[str, Asset]) -> list[Finding]:
    findings: list[Finding] = []
    for name, data in files.items():
        findings += detect_and_parse(name, data, assets)
    return prioritize(findings, assets)


def load_folder(folder: str | Path) -> tuple[list[Finding], dict[str, Asset]]:
    root = Path(folder)
    assets_file = root / "assets.json"
    assets = load_assets(assets_file.read_bytes() if assets_file.exists() else None)
    files = {p.name: p.read_bytes() for p in sorted(root.iterdir())
             if p.suffix in {".xml", ".json"} and p.name != "assets.json"}
    if not files:
        raise ParseError(f"No .xml or .json scan files found in {root}")
    return analyze(files, assets), assets
