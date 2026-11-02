"""Command line interface.

    python -m scanbrief samples                      # ranked findings
    python -m scanbrief samples --report report.md   # client report (AI if a key is set)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import ParseError, load_folder
from .report import ReportError, ai_report, offline_report, to_markdown


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="scanbrief")
    ap.add_argument("folder", help="Folder with Nmap .xml / ZAP .json files and optional assets.json")
    ap.add_argument("--report", metavar="FILE", help="Write a Markdown client report")
    ap.add_argument("--audience", choices=["executive", "technical"], default="executive")
    ap.add_argument("--offline", action="store_true", help="Skip the AI and use the template report")
    args = ap.parse_args(argv)

    try:
        findings, _ = load_folder(args.folder)
    except (ParseError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for f in findings:
        print(f"{f.id}  {f.score:>4}  {f.severity:<8} {f.asset_name:<22} {f.title}")

    if args.report:
        engine = "offline template"
        if not args.offline and os.environ.get("ANTHROPIC_API_KEY"):
            try:
                report, log = ai_report(findings, audience=args.audience)
                engine = "Claude, " + "; ".join(log)
            except ReportError as exc:
                print(f"AI report failed ({exc}); using offline template.", file=sys.stderr)
                report = offline_report(findings)
        else:
            report = offline_report(findings)
        Path(args.report).write_text(to_markdown(report, findings, engine))
        print(f"\nWrote {args.report} ({engine})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
