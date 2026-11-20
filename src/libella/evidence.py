"""Evidence: content-addressed blobs + append-only hash-chain ledger.

Every artifact is stored by sha256. The ledger chains each entry to the
previous, so tampering with any historical record breaks the chain.
Verification re-hashes blobs on read (fail-closed).
"""
import hashlib
import json
import os
import re
import tempfile
import threading
import time
from pathlib import Path

from .db import DB, new_id

SAFE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


class EvidenceStore:
    def __init__(self, db: DB, root: str | Path):
        self.db = db
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._chain_lock = threading.Lock()  # prev-hash read + insert must be atomic

    def _last_hash(self, engagement_id: str) -> str:
        row = self.db.one(
            "SELECT chain_hash FROM evidence WHERE engagement_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (engagement_id,),
        )
        return row["chain_hash"] if row else "0" * 64

    def put(self, engagement_id: str, data: bytes, kind: str) -> dict:
        if not isinstance(engagement_id, str) or not SAFE_ID.fullmatch(engagement_id):
            raise ValueError(f"unsafe engagement id {engagement_id!r}")
        digest = hashlib.sha256(data).hexdigest()
        rel = f"{engagement_id}/{digest[:2]}/{digest}"
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            fd, tmp = tempfile.mkstemp(dir=str(path.parent))
            closed = False
            try:
                os.write(fd, data)
                os.fsync(fd)
                os.close(fd)
                closed = True
                os.replace(tmp, path)
            except BaseException:
                if not closed:
                    os.close(fd)
                if os.path.exists(tmp):
                    os.unlink(tmp)
                raise
        with self._chain_lock:
            prev = self._last_hash(engagement_id)
            ts = time.time()
            chain = hashlib.sha256(f"{prev}|{digest}|{kind}|{ts}".encode()).hexdigest()
            eid = new_id("ev")
            self.db.execute(
                "INSERT INTO evidence(id, engagement_id, sha256, kind, path, bytes, created_at, prev_hash, chain_hash) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (eid, engagement_id, digest, kind, str(rel), len(data), ts, prev, chain),
            )
        return {"id": eid, "sha256": digest, "kind": kind, "bytes": len(data), "path": str(rel)}

    def put_json(self, engagement_id: str, obj, kind: str) -> dict:
        return self.put(engagement_id, json.dumps(obj, indent=2, default=str).encode(), kind)

    def read(self, evidence_id: str) -> bytes:
        row = self.db.one("SELECT * FROM evidence WHERE id=?", (evidence_id,))
        if row is None:
            raise KeyError(f"evidence {evidence_id} not found")
        path = self.root / row["path"]
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != row["sha256"] or len(data) != row["bytes"]:
            raise ValueError(f"evidence {evidence_id} FAILED integrity check (tampered or corrupt)")
        return data

    def read_json(self, evidence_id: str):
        return json.loads(self.read(evidence_id))

    def verify_chain(self, engagement_id: str) -> dict:
        rows = self.db.query(
            "SELECT * FROM evidence WHERE engagement_id=? ORDER BY created_at, rowid",
            (engagement_id,),
        )
        prev = "0" * 64
        for r in rows:
            expect = hashlib.sha256(
                f"{prev}|{r['sha256']}|{r['kind']}|{r['created_at']}".encode()
            ).hexdigest()
            if r["prev_hash"] != prev or r["chain_hash"] != expect:
                return {"ok": False, "broken_at": r["id"], "checked": len(rows)}
            try:
                self.read(r["id"])
            except ValueError as e:
                return {"ok": False, "broken_at": r["id"], "error": str(e), "checked": len(rows)}
            prev = r["chain_hash"]
        return {"ok": True, "checked": len(rows), "head": prev}
