"""Turn Nmap XML and OWASP ZAP JSON reports into one list of Findings."""

from __future__ import annotations

import html
import json
import re
import xml.etree.ElementTree as ET

from .knowledge import PORT_RULES, ZAP_RULES
from .models import Asset, Finding

ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
ZAP_CONFIDENCE = {"3": "high", "4": "high", "2": "medium", "1": "low", "0": "low"}
_TAGS = re.compile(r"<[^>]+>")


class ParseError(ValueError):
    pass


def _clean(text: str) -> str:
    return " ".join(html.unescape(_TAGS.sub(" ", text or "")).split())


def parse_nmap(data: bytes | str, assets: dict[str, Asset] | None = None) -> list[Finding]:
    assets = assets or {}
    raw = data.encode() if isinstance(data, str) else data
    if b"<!ENTITY" in raw:
        raise ParseError("XML entity declarations are not allowed in scan files.")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ParseError(f"Not valid Nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ParseError("Expected an Nmap XML report (root element <nmaprun>).")

    findings: list[Finding] = []
    for host in root.iter("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addr = host.find("address").get("addr")
        hostname_el = host.find("hostnames/hostname")
        names = [addr] + ([hostname_el.get("name")] if hostname_el is not None else [])
        asset = next((assets[n] for n in names if n in assets), Asset(name=names[-1]))
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            num = int(port.get("portid"))
            svc = port.find("service")
            svc_text = " ".join(filter(None, [
                svc.get("name") if svc is not None else None,
                svc.get("product") if svc is not None else None,
                svc.get("version") if svc is not None else None,
            ])) or "unknown service"
            rule = PORT_RULES.get(num)
            if rule:
                title, sev_ext, sev_int, detail, fix, safeguard = rule
                severity = sev_ext if asset.internet_facing else sev_int
            else:
                title = f"Port {num} is open ({svc_text})"
                severity = "low" if asset.internet_facing else "info"
                detail = "A network service is listening that isn't on our list of known risky services."
                fix = "Confirm the service is needed; close the port if it isn't."
                safeguard = None
            findings.append(Finding(
                id="", source="nmap", host=addr, asset_name=asset.name, title=title,
                severity=severity, detail=detail, fix=fix, safeguard=safeguard,
                evidence=[f"{port.get('protocol', 'tcp')}/{num} open: {svc_text}"],
            ))
    return findings


def parse_zap(data: bytes | str, assets: dict[str, Asset] | None = None) -> list[Finding]:
    assets = assets or {}
    try:
        report = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ParseError(f"Not valid ZAP JSON: {exc}") from exc
    if not isinstance(report, dict) or "site" not in report:
        raise ParseError("Expected a ZAP JSON report with a 'site' list.")

    findings: list[Finding] = []
    for site in report["site"]:
        host = site.get("@host", site.get("@name", "unknown"))
        asset = assets.get(host) or assets.get(site.get("@name", "")) or Asset(name=host)
        for alert in site.get("alerts", []):
            pid = str(alert.get("pluginid", ""))
            plain = ZAP_RULES.get(pid)
            instances = alert.get("instances", [])
            evidence = [
                f"{i.get('method', 'GET')} {i.get('uri', '')}"
                + (f" param={i['param']}" if i.get("param") else "")
                for i in instances[:5]
            ]
            if len(instances) > 5:
                evidence.append(f"...and {len(instances) - 5} more URLs")
            findings.append(Finding(
                id="", source="zap", host=host, asset_name=asset.name,
                title=plain[0] if plain else alert.get("name") or alert.get("alert", "ZAP alert"),
                severity=ZAP_RISK.get(str(alert.get("riskcode")), "info"),
                confidence=ZAP_CONFIDENCE.get(str(alert.get("confidence")), "medium"),
                detail=_clean(alert.get("desc", ""))[:600],
                fix=plain[1] if plain else _clean(alert.get("solution", ""))[:400],
                safeguard=plain[2] if plain else None,
                evidence=evidence,
            ))
    return findings


def detect_and_parse(name: str, data: bytes, assets: dict[str, Asset] | None = None) -> list[Finding]:
    head = data.lstrip()[:200]
    if name.endswith(".xml") or head.startswith(b"<"):
        return parse_nmap(data, assets)
    if name.endswith(".json") or head.startswith(b"{"):
        return parse_zap(data, assets)
    raise ParseError(f"{name}: unrecognized format (expected Nmap .xml or ZAP .json)")
