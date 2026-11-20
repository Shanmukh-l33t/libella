"""Container scan tests: real trivy against a local image, honest CVE discipline."""
import shutil
import subprocess

import pytest

from libella.db import DB
from libella.evidence import EvidenceStore
from libella.findings import FindingPipeline
from libella.tools.container_adapters import assess_image, parse_trivy_json


def test_parse_trivy_json():
    sample = '{"Results": [{"Target": "img (alpine)", "Vulnerabilities": [' \
             '{"VulnerabilityID": "CVE-2021-0001", "PkgName": "libssl", "InstalledVersion": "1.0", ' \
             '"FixedVersion": "1.1", "Severity": "HIGH", "Title": "t"}]}]}'
    out = parse_trivy_json(sample)
    assert out["parse_error"] is False
    assert out["vulnerabilities"][0]["id"] == "CVE-2021-0001"
    assert parse_trivy_json("not json")["parse_error"] is True


def test_injection_in_image_name_rejected(tmp_path):
    db = DB(tmp_path / "t.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    pipe = FindingPipeline(db, ev)
    res = assess_image("busybox; rm -rf /", db, ev, pipe, "eng")
    assert res["ok"] is False
    row = db.one("SELECT scope_decision FROM tool_calls WHERE tool='trivy_image'")
    assert row["scope_decision"].startswith("refused")


@pytest.mark.skipif(shutil.which("trivy") is None or shutil.which("docker") is None,
                    reason="trivy/docker not installed")
def test_real_image_scan_observations_not_findings(tmp_path):
    # pick a small local image
    imgs = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                          capture_output=True, text=True, timeout=30).stdout.split()
    small = next((i for i in imgs if i.startswith("busybox")), None)
    if small is None:
        pytest.skip("no busybox image local")
    db = DB(tmp_path / "t.db")
    ev = EvidenceStore(db, tmp_path / "ev")
    pipe = FindingPipeline(db, ev)
    res = assess_image(small, db, ev, pipe, "eng")
    assert res["ok"] is True, res
    assert res["total"] >= 0
    # version-based CVEs are observations, never confirmed findings
    assert db.one("SELECT COUNT(*) n FROM findings WHERE engagement_id='eng'")["n"] == 0
    obs = db.query("SELECT kind FROM observations WHERE engagement_id='eng'")
    assert all(o["kind"] == "potentially_affected" for o in obs)
    assert ev.verify_chain("eng")["ok"]
