"""ffuf output contract: matched words precede the JSON report on stdout."""
import json

from libella.tools.adapters import parse_ffuf_json


def test_parses_report_after_matched_word_lines():
    report = {"results": [{"url": "http://127.0.0.1:1/admin", "status": 200, "length": 5, "words": 1}]}
    stdout = "admin\nbackup\n" + json.dumps(report) + "\n"
    assert parse_ffuf_json(stdout) == [{"url": "http://127.0.0.1:1/admin", "status": 200,
                                        "length": 5, "words": 1}]


def test_pure_json_and_garbage():
    assert parse_ffuf_json(json.dumps({"results": []})) == []
    assert parse_ffuf_json("not json\n{broken") == []
