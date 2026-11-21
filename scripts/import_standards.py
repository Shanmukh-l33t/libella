"""Regenerate the versioned standards catalog from the authoritative source.

The ASVS catalog is data, not code: it is imported from the official OWASP
machine-readable export at a pinned commit so every requirement keeps its exact
identifier, chapter, section and level. Re-run with --asvs-sha to move the
catalog forward; the committed JSON carries the provenance that makes the
import auditable.

    python scripts/import_standards.py            # verify the committed data
    python scripts/import_standards.py --write    # re-import and rewrite it

ASVS is published by OWASP under CC BY-SA 4.0; the catalog file keeps that
attribution and is redistributed under the same terms.

No CWE bridge is imported: OWASP's 5.0 `v5.0.be_cwe_mapping.json` is keyed by the
separate backend-requirements numbering (v5.0.be-6.2.1 is not V6.2.1), so joining
it to V-ids would be a fabricated mapping. CWE links therefore live in the
hand-authored unit mapping, where each one can be justified.
"""
import argparse
import json
import pathlib
import urllib.request

REPO = "https://raw.githubusercontent.com/OWASP/ASVS"
# Pinned import point: the 5.0.0 export as it stands in the OWASP repository.
ASVS_SHA = "82fb2f41cdb623e0b11e4d9a6b97c4306c1d119c"
OUT = pathlib.Path(__file__).resolve().parent.parent / "src/libella/standards_data/asvs-5.0.0.json"
FLAT = "5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json"


def _get(path: str) -> dict:
    req = urllib.request.Request(f"{REPO}/{ASVS_SHA}/{path}",
                                 headers={"User-Agent": "libella-standards-import"})
    return json.loads(urllib.request.urlopen(req, timeout=120).read())


def build() -> dict:
    flat = _get(FLAT)["requirements"]
    reqs = []
    for r in flat:
        reqs.append({
            "id": r["req_id"],
            "title": " ".join(r["req_description"].split()),
            "chapter": r["chapter_id"], "chapter_title": r["chapter_name"],
            "section": r["section_id"], "section_title": r["section_name"],
            "level": int(r["L"]) if str(r.get("L", "")).isdigit() else None,
            "cwe": [],  # populated by the reviewed unit mapping, not by a join
        })
    ids = [r["id"] for r in reqs]
    assert len(ids) == len(set(ids)), "duplicate requirement ids in the upstream export"
    return {
        "framework": {
            "id": "ASVS", "version": "5.0.0",
            "title": "OWASP Application Security Verification Standard 5.0.0",
            "source": "https://github.com/OWASP/ASVS/tree/5.0",
            "license": "CC BY-SA 4.0",
            "upstream_sha": ASVS_SHA,
            "retrieved": "2026-11-21",
            "levels": [1, 2, 3],
        },
        "requirements": reqs,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()
    data = build()
    text = json.dumps(data, indent=1, ensure_ascii=False) + "\n"
    if args.write:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(text)
        print(f"wrote {OUT} ({len(data['requirements'])} requirements)")
        return 0
    current = json.loads(OUT.read_text()) if OUT.exists() else None
    if current != data:
        print("committed catalog differs from the pinned upstream export; re-run with --write")
        return 1
    levels = {lv: sum(1 for r in data["requirements"] if r["level"] == lv) for lv in (1, 2, 3)}
    print(f"catalog matches {ASVS_SHA[:12]}: {len(data['requirements'])} requirements, levels {levels}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
