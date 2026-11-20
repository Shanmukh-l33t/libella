"""SQLite persistence. Single writer path; WAL for concurrent reads."""
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, profile TEXT NOT NULL DEFAULT 'safe_active',
  status TEXT NOT NULL DEFAULT 'draft', scope_json TEXT NOT NULL, auth_json TEXT NOT NULL DEFAULT '{}',
  budgets_json TEXT NOT NULL DEFAULT '{}', objectives_json TEXT NOT NULL DEFAULT '[]',
  window_start TEXT, window_end TEXT, created_at REAL, started_at REAL, finished_at REAL,
  status_detail TEXT
);
CREATE TABLE IF NOT EXISTS assets(
  id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL,
  value_json TEXT NOT NULL DEFAULT '{}', parent_id TEXT, discovered_by TEXT,
  first_seen REAL, last_seen REAL,
  UNIQUE(engagement_id, kind, key)
);
CREATE TABLE IF NOT EXISTS intents(
  id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, parent_id TEXT, role TEXT NOT NULL,
  objective TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
  claim_token TEXT, lease_expires REAL, depends_on_json TEXT NOT NULL DEFAULT '[]',
  informed_by_json TEXT NOT NULL DEFAULT '[]', asset_ids_json TEXT NOT NULL DEFAULT '[]',
  created_at REAL, finished_at REAL, result_json TEXT, attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS observations(
  id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, intent_id TEXT, asset_id TEXT,
  kind TEXT NOT NULL, summary TEXT NOT NULL, evidence_id TEXT, quote TEXT,
  source_derived TEXT NOT NULL, created_at REAL
);
CREATE TABLE IF NOT EXISTS findings(
  id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, title TEXT NOT NULL,
  cwe TEXT, owasp TEXT, severity TEXT NOT NULL DEFAULT 'info', cvss REAL,
  confidence TEXT NOT NULL DEFAULT 'low', asset_id TEXT, endpoint TEXT,
  state TEXT NOT NULL DEFAULT 'suspected', description TEXT, impact TEXT, remediation TEXT,
  dedup_key TEXT, evidence_ids_json TEXT NOT NULL DEFAULT '[]', created_at REAL, updated_at REAL
);
CREATE TABLE IF NOT EXISTS evidence(
  id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, sha256 TEXT NOT NULL, kind TEXT NOT NULL,
  path TEXT NOT NULL, bytes INTEGER NOT NULL, created_at REAL,
  prev_hash TEXT NOT NULL, chain_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS exchanges(
  id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, evidence_id TEXT,
  method TEXT, url TEXT, status INTEGER, req_headers_json TEXT, resp_headers_json TEXT,
  req_body TEXT, duration_ms REAL, tool TEXT, peer_ip TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS verifications(
  id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, attempt INTEGER, method TEXT,
  replay_exchange_id TEXT, verdict TEXT, detail TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS tool_calls(
  id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, intent_id TEXT, tool TEXT NOT NULL,
  argv_json TEXT, target TEXT, scope_decision TEXT, exit_code INTEGER,
  duration_ms REAL, artifact_id TEXT, error TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, engagement_id TEXT NOT NULL, kind TEXT NOT NULL,
  payload_json TEXT NOT NULL, created_at REAL
);
CREATE TABLE IF NOT EXISTS llm_usage(
  id TEXT PRIMARY KEY, engagement_id TEXT, role TEXT, model TEXT,
  input_tokens INTEGER, output_tokens INTEGER, cost_usd REAL, created_at REAL
);
CREATE TABLE IF NOT EXISTS retests(
  id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, exchange_id TEXT, verdict TEXT,
  detail TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS hypotheses(
  id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, asset_id TEXT, intent_id TEXT,
  kind TEXT, statement TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
  confidence REAL DEFAULT 0.5, created_by TEXT, created_at REAL, updated_at REAL
);
CREATE TABLE IF NOT EXISTS investigation_steps(
  id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, intent_id TEXT, agent_run_id TEXT,
  seq INTEGER, action_kind TEXT NOT NULL, summary TEXT, tool_call_id TEXT,
  observation_id TEXT, evidence_id TEXT, hypothesis_id TEXT, model TEXT,
  tokens INTEGER DEFAULT 0, created_at REAL
);
CREATE TABLE IF NOT EXISTS agent_runs(
  id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, intent_id TEXT, role TEXT NOT NULL,
  model TEXT, status TEXT NOT NULL DEFAULT 'running', iterations INTEGER DEFAULT 0,
  tokens_in INTEGER DEFAULT 0, tokens_out INTEGER DEFAULT 0, cost_usd REAL DEFAULT 0,
  started_at REAL, finished_at REAL, summary TEXT, exit_reason TEXT
);
CREATE TABLE IF NOT EXISTS auth_contexts(
  id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, name TEXT, username TEXT,
  login_flow_json TEXT, cookies_json TEXT, status TEXT DEFAULT 'active',
  last_verified_at REAL, created_at REAL
);
CREATE TABLE IF NOT EXISTS workflows(
  id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, name TEXT, auth_context_id TEXT,
  steps_json TEXT, status TEXT DEFAULT 'draft', created_at REAL
);
CREATE TABLE IF NOT EXISTS memory_facts(
  id TEXT PRIMARY KEY, target_key TEXT NOT NULL, kind TEXT NOT NULL, value_json TEXT,
  source_engagement_id TEXT, confidence REAL DEFAULT 0.5, first_seen REAL, last_seen REAL,
  UNIQUE(target_key, kind)
);
CREATE TABLE IF NOT EXISTS asset_changes(
  id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, asset_key TEXT NOT NULL,
  change_kind TEXT NOT NULL, old_json TEXT, new_json TEXT, detected_at REAL
);
CREATE INDEX IF NOT EXISTS idx_hyp_eng ON hypotheses(engagement_id);
CREATE INDEX IF NOT EXISTS idx_steps_eng ON investigation_steps(engagement_id, intent_id);
CREATE INDEX IF NOT EXISTS idx_runs_eng ON agent_runs(engagement_id);
CREATE INDEX IF NOT EXISTS idx_auth_eng ON auth_contexts(engagement_id);
CREATE INDEX IF NOT EXISTS idx_mem_target ON memory_facts(target_key);
CREATE INDEX IF NOT EXISTS idx_assets_eng ON assets(engagement_id);
CREATE INDEX IF NOT EXISTS idx_intents_eng ON intents(engagement_id, status);
CREATE INDEX IF NOT EXISTS idx_obs_eng ON observations(engagement_id);
CREATE INDEX IF NOT EXISTS idx_findings_eng ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_events_eng ON events(engagement_id, seq);
CREATE INDEX IF NOT EXISTS idx_exchanges_eng ON exchanges(engagement_id);
"""


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class DB:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._migrate()
            self._conn.commit()

    def _migrate(self):
        """Add columns to pre-existing tables (idempotent)."""
        additions = {
            "findings": [("remediation_notes", "TEXT"), ("owner", "TEXT"),
                         ("fix_commit", "TEXT"), ("remediated_at", "REAL")],
            "exchanges": [("replay_of", "TEXT"), ("tags_json", "TEXT DEFAULT '[]'")],
        }
        for table, cols in additions.items():
            existing = {r[1] for r in self._conn.execute(f"PRAGMA table_info({table})")}
            for name, typ in cols:
                if name not in existing:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {typ}")

    def execute(self, sql: str, params=()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def query(self, sql: str, params=()) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    def one(self, sql: str, params=()) -> dict | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def emit(self, engagement_id: str, kind: str, payload: dict) -> int:
        cur = self.execute(
            "INSERT INTO events(engagement_id, kind, payload_json, created_at) VALUES(?,?,?,?)",
            (engagement_id, kind, json.dumps(payload, default=str), time.time()),
        )
        return cur.lastrowid

    def close(self):
        with self._lock:
            self._conn.close()
