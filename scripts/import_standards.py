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
# OWASP API Security Top 10 2023, from the project's own repository (CC BY-SA 4.0)
API_REPO = "https://raw.githubusercontent.com/OWASP/API-Security"
API_SHA = "33cea37b2ffde3e2e62f6b5d79a029a22a846633"
API_OUT = OUT.parent / "api-top10-2023.json"
API_INDEX = "editions/2023/en/0x11-t10.md"


def _get(path: str) -> dict:
    req = urllib.request.Request(f"{REPO}/{ASVS_SHA}/{path}",
                                 headers={"User-Agent": "libella-standards-import"})
    return json.loads(urllib.request.urlopen(req, timeout=120).read())


def build_api() -> dict:
    """The ten 2023 risks with their published ids, titles and summary text."""
    import re
    req = urllib.request.Request(f"{API_REPO}/{API_SHA}/{API_INDEX}",
                                 headers={"User-Agent": "libella-standards-import"})
    text = urllib.request.urlopen(req, timeout=120).read().decode()
    rows = re.findall(r"^\| \[(API\d+:2023) - ([^\]]+)\]\[api\d+\] \| (.+?) \|\s*$", text, re.M)
    unlink = lambda t: re.sub(r"\[([^\]]+)\]\[[^\]]*\]", r"\1", t)  # noqa: E731
    reqs = [{"id": rid, "title": title.strip(), "summary": " ".join(unlink(summary).split()),
             "chapter": "API", "chapter_title": "OWASP API Security Top 10 2023",
             "section": None, "section_title": None, "level": None, "cwe": []}
            for rid, title, summary in rows]
    assert [r["id"] for r in reqs] == [f"API{i}:2023" for i in range(1, 11)], "index changed"
    return {
        "framework": {
            "id": "API-Top10", "version": "2023",
            "title": "OWASP API Security Top 10",
            "source": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
            "license": "CC BY-SA 4.0", "upstream_sha": API_SHA, "retrieved": "2026-11-21",
            "levels": [],
        },
        "requirements": reqs,
    }


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
    api = build_api()
    text = json.dumps(data, indent=1, ensure_ascii=False) + "\n"
    if args.write:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(text)
        API_OUT.write_text(json.dumps(api, indent=1, ensure_ascii=False) + "\n")
        print(f"wrote {OUT} ({len(data['requirements'])} requirements) and {API_OUT} "
              f"({len(api['requirements'])} risks)")
        return 0
    if not API_OUT.exists() or json.loads(API_OUT.read_text()) != api:
        print("committed API Top 10 catalog differs from the pinned upstream; re-run with --write")
        return 1
    current = json.loads(OUT.read_text()) if OUT.exists() else None
    if current != data:
        print("committed catalog differs from the pinned upstream export; re-run with --write")
        return 1
    levels = {lv: sum(1 for r in data["requirements"] if r["level"] == lv) for lv in (1, 2, 3)}
    print(f"catalog matches {ASVS_SHA[:12]}: {len(data['requirements'])} requirements, levels {levels}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
