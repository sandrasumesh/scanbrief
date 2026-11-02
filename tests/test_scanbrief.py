import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanbrief import ParseError, analyze, load_assets, load_folder  # noqa: E402
from scanbrief.models import Asset  # noqa: E402
from scanbrief.parsers import parse_nmap, parse_zap  # noqa: E402
from scanbrief.report import (  # noqa: E402
    ReportError, ai_report, grounding_errors, offline_report, to_markdown,
)

SAMPLES = ROOT / "samples"


@pytest.fixture(scope="module")
def sample():
    return load_folder(SAMPLES)


# ------------------------------------------------------------ parsing

def test_nmap_skips_down_hosts_and_closed_ports(sample):
    findings, _ = sample
    nmap = [f for f in findings if f.source == "nmap"]
    hosts = {f.host for f in nmap}
    assert "10.0.0.40" not in hosts                       # host was down
    assert not any("8080" in e for f in nmap for e in f.evidence)   # port was filtered


def test_same_port_is_rated_by_exposure(sample):
    findings, _ = sample
    rdp = {f.asset_name: f.severity for f in findings if f.title == "Remote Desktop is reachable"}
    assert rdp == {"Office file server": "critical", "Front desk PC": "medium"}


def test_zap_maps_plugins_to_plain_language(sample):
    findings, _ = sample
    sqli = next(f for f in findings if f.source == "zap" and "SQL injection" in f.title)
    assert sqli.severity == "high"
    assert sqli.asset_name == "Patient portal"
    assert "param=q" in sqli.evidence[0]
    assert "<p>" not in sqli.detail


def test_unknown_port_gets_generic_finding():
    xml = b"""<nmaprun><host><status state="up"/><address addr="10.1.1.1"/>
    <ports><port protocol="tcp" portid="4444"><state state="open"/><service name="krb524"/></port></ports>
    </host></nmaprun>"""
    [f] = parse_nmap(xml)
    assert "4444" in f.title and f.severity == "info"


@pytest.mark.parametrize("payload", [
    b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>',
    b"<html></html>",
    b"<nmaprun",
])
def test_bad_xml_rejected(payload):
    with pytest.raises(ParseError):
        parse_nmap(payload)


def test_bad_zap_rejected():
    with pytest.raises(ParseError):
        parse_zap(b'{"not": "zap"}')


# ------------------------------------------------------------ scoring

def test_scores_are_sorted_and_explained(sample):
    findings, _ = sample
    scores = [f.score for f in findings]
    assert scores == sorted(scores, reverse=True)
    assert [f.id for f in findings][:2] == ["S-01", "S-02"]
    top = findings[0]
    assert any("internet" in r for r in top.score_reasons)
    assert any("patient data" in r for r in top.score_reasons)


def test_low_confidence_lowers_score():
    zap = b"""{"site": [{"@host": "h", "alerts": [
      {"pluginid": "10202", "riskcode": "2", "confidence": "1", "desc": "", "instances": []},
      {"pluginid": "10038", "riskcode": "2", "confidence": "3", "desc": "", "instances": []}]}]}"""
    a, b = analyze({"z.json": zap}, load_assets(None))
    assert a.title.startswith("No Content Security") and a.score == b.score + 1


# ------------------------------------------------------------ report

class FakeClient:
    def __init__(self, inputs):
        self.inputs = list(inputs)
        self.requests = []
        self.messages = self

    def create(self, **kwargs):
        self.requests.append(kwargs)
        block = SimpleNamespace(type="tool_use", id=f"tu{len(self.requests)}", name="write_report",
                                input=self.inputs.pop(0))
        return SimpleNamespace(stop_reason="tool_use", content=[block])


def report_input(ids):
    return {
        "headline": "Two systems need urgent fixes.", "overall_risk": "Critical",
        "summary": "Short summary.",
        "risks": [{"finding_ids": ids, "title": "Close remote access", "what_it_means": "x",
                   "why_it_matters": "y", "fix_steps": ["Block the ports."],
                   "owner": "IT / network", "effort": "About a day"}],
        "quick_wins": [], "questions_for_client": [],
    }


def high_ids(findings):
    return [f.id for f in findings if f.severity in {"critical", "high"}]


def test_ai_report_accepts_grounded_output(sample):
    findings, _ = sample
    client = FakeClient([report_input(high_ids(findings))])
    report, log = ai_report(findings, client=client)
    assert log == ["attempt 1: valid"]
    assert client.requests[0]["tool_choice"] == {"type": "tool", "name": "write_report"}


def test_ai_report_retries_on_invented_ids(sample):
    findings, _ = sample
    client = FakeClient([report_input(["S-99"]), report_input(high_ids(findings))])
    report, log = ai_report(findings, client=client)
    assert log[0].startswith("attempt 1: rejected")
    feedback = client.requests[1]["messages"][-1]["content"][0]["content"]
    assert "S-99" in feedback and "not covered" in feedback


def test_ai_report_retries_on_schema_errors(sample):
    findings, _ = sample
    bad = report_input(high_ids(findings))
    bad["overall_risk"] = "Spicy"
    client = FakeClient([bad, bad])
    with pytest.raises(ReportError):
        ai_report(findings, client=client)
    assert "overall_risk" in client.requests[1]["messages"][-1]["content"][0]["content"]


def test_offline_report_is_grounded_and_renders(sample):
    findings, _ = sample
    report = offline_report(findings)
    reportable = [f for f in findings if f.severity != "info"]
    assert grounding_errors(report, reportable) == []
    md = to_markdown(report, findings, "offline template")
    assert md.startswith("# Security scan summary")
    assert "164.312(e)(1) Transmission security" in md
    assert "not a compliance determination" in md


def test_asset_lookup_by_hostname():
    xml = b"""<nmaprun><host><status state="up"/><address addr="198.51.100.5"/>
    <hostnames><hostname name="app.example"/></hostnames>
    <ports><port portid="23"><state state="open"/></port></ports></host></nmaprun>"""
    [f] = parse_nmap(xml, {"app.example": Asset(name="App", internet_facing=True)})
    assert f.asset_name == "App" and f.severity == "critical"
