"""Report rendering: files are replaced atomically and one state renders once."""
import json
import threading
from pathlib import Path

import pytest

from libella.report import render_report


def _report_rows(app, eid):
    return app.db.query("SELECT id FROM evidence WHERE engagement_id=? AND kind='report'", (eid,))


def _rendered_events(app, eid):
    return app.db.query("SELECT seq FROM events WHERE engagement_id=? AND kind='report_rendered'", (eid,))


def test_repeated_render_of_one_state_records_one_artifact(pair):
    first = render_report(pair.db, pair.evidence, "eng_a")
    second = render_report(pair.db, pair.evidence, "eng_a")
    third = render_report(pair.db, pair.evidence, "eng_a")
    assert first["evidence_id"] == second["evidence_id"] == third["evidence_id"]
    assert len(_report_rows(pair, "eng_a")) == 1
    assert len(_rendered_events(pair, "eng_a")) == 1


def test_changed_state_renders_a_new_artifact(pair):
    render_report(pair.db, pair.evidence, "eng_a")
    pair.db.execute("UPDATE findings SET state='validated' WHERE id='f_eng_a_2'")
    res = render_report(pair.db, pair.evidence, "eng_a")
    assert len(_report_rows(pair, "eng_a")) == 2
    doc = json.loads((Path(res["outdir"]) / "report.json").read_text())
    assert doc["summary"]["confirmed"] == 3


@pytest.mark.parametrize("filename", ["report.json", "report.md", "report.sarif"])
def test_report_files_are_replaced_not_written_in_place(pair, monkeypatch, filename):
    import libella.report as report_mod
    seen, real = [], report_mod.os.replace

    def spy(src, dst):
        seen.append(Path(dst).name)
        return real(src, dst)

    monkeypatch.setattr(report_mod.os, "replace", spy)
    render_report(pair.db, pair.evidence, "eng_a")
    assert filename in seen, f"{filename} was written in place"


def test_pdf_is_replaced_not_written_in_place(tmp_path, report_json_path, monkeypatch):
    import libella.report_pdf as pdf_mod
    seen, real = [], pdf_mod.os.replace

    def spy(src, dst):
        seen.append(Path(dst).name)
        return real(src, dst)

    monkeypatch.setattr(pdf_mod.os, "replace", spy)
    pdf_mod.render_pdf(json.loads(report_json_path.read_text()), tmp_path / "report.pdf")
    assert "report.pdf" in seen


def test_pdf_build_failure_removes_temp_but_preserves_old_report(tmp_path, report_json_path, monkeypatch):
    import libella.report_pdf as pdf_mod

    def fail(*args, **kwargs):
        raise RuntimeError("injected rendering failure")

    out = tmp_path / "report.pdf"
    out.write_bytes(b"existing report")
    monkeypatch.setattr(pdf_mod.BaseDocTemplate, "build", fail)
    with pytest.raises(RuntimeError, match="injected rendering failure"):
        pdf_mod.render_pdf(json.loads(report_json_path.read_text()), out)
    assert out.read_bytes() == b"existing report"
    assert list(tmp_path.glob("*.pdf")) == [out]


def test_concurrent_renders_never_expose_a_truncated_json(pair):
    outdir = Path(render_report(pair.db, pair.evidence, "eng_a")["outdir"])
    path = outdir / "report.json"
    errors, reads, stop = [], [0], threading.Event()

    def reader():
        while not stop.is_set():
            try:
                json.loads(path.read_text())
                reads[0] += 1
            except FileNotFoundError:
                pass
            except json.JSONDecodeError as e:
                errors.append(e)

    def writer():
        for _ in range(6):
            render_report(pair.db, pair.evidence, "eng_a")

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    workers = [threading.Thread(target=writer) for _ in range(6)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    stop.set()
    t.join(timeout=5)
    assert reads[0] > 0, "reader never observed the report"
    assert not errors, f"truncated report.json served: {errors[0]}"
    assert len(_report_rows(pair, "eng_a")) == 1  # identical state, one artifact
