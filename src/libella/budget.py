"""Authoritative engagement spend: atomic reservations settled to the real cost.

Check-after-spend let two agents both see headroom and overshoot. Here a model
call reserves an estimated cost BEFORE it happens, inside one BEGIN IMMEDIATE
transaction (sum of settled rows + live reservations), and settles to the
provider-reported cost after it. The committed total therefore cannot pass the
engagement ceiling, however many agents run at once.

Reservation lifecycle: reserved -> settled (actual cost) | released (no cost: a
provider error, or a crash older than RESERVATION_TTL_S, which is swept back to
released on the next reservation and reported as an event).
"""
import time

from .db import new_id

# Longer than the LLM client's own timeout: a live call is never freed under it.
RESERVATION_TTL_S = 900
_ACTIVE = ("settled", "reserved")


class BudgetLedger:
    def __init__(self, db):
        self.db = db

    def _sum(self, conn, engagement_id: str) -> float:
        row = conn.execute(
            "SELECT COALESCE(SUM(amount_usd),0) FROM budget_ledger "
            "WHERE engagement_id=? AND state IN ('settled','reserved')", (engagement_id,)).fetchone()
        return float(row[0] or 0.0)

    def committed(self, engagement_id: str) -> float:
        """Settled spend plus live reservations: what the engagement has committed."""
        with self.db._lock:
            return self._sum(self.db._conn, engagement_id)

    def reserve(self, engagement_id: str, run_id, amount_usd: float, max_usd: float,
                ttl_s: float = RESERVATION_TTL_S) -> str | None:
        """Atomically reserve headroom for one model call; None when it would pass the ceiling."""
        amount = round(max(0.0, float(amount_usd)), 9)
        now = time.time()
        # shortcut: one shared connection guarded by DB._lock, so threads serialize here;
        # BEGIN IMMEDIATE keeps a second process out too.
        with self.db._lock:
            conn = self.db._conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                expired = conn.execute(
                    "UPDATE budget_ledger SET state='released', settled_at=? "
                    "WHERE engagement_id=? AND state='reserved' AND created_at < ?",
                    (now, engagement_id, now - ttl_s)).rowcount
                if self._sum(conn, engagement_id) + amount > float(max_usd) + 1e-12:
                    conn.execute("ROLLBACK")
                    rid = None
                else:
                    rid = new_id("bud")
                    conn.execute(
                        "INSERT INTO budget_ledger(id, engagement_id, run_id, kind, amount_usd, "
                        "state, created_at) VALUES(?,?,?,?,?,?,?)",
                        (rid, engagement_id, run_id, "reservation", amount, "reserved", now))
                    conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        if expired:  # a crashed worker's reservation stops holding budget hostage
            self.db.emit(engagement_id, "budget_reservation_expired",
                         {"count": expired, "age_s": ttl_s,
                          "detail": f"{expired} reservation(s) older than {ttl_s:.0f}s were "
                                    f"released: the worker that took them never settled"})
        return rid

    def settle(self, reservation_id: str, amount_usd: float) -> float:
        """Reconcile one reservation to what the call actually cost (0 = release)."""
        amount = round(max(0.0, float(amount_usd)), 9)
        self.db.execute(
            "UPDATE budget_ledger SET amount_usd=?, state=?, settled_at=? "
            "WHERE id=? AND state='reserved'",
            (amount, "settled" if amount > 0 else "released", time.time(), reservation_id))
        return amount

    def totals(self, engagement_id: str) -> dict:
        rows = self.db.query(
            "SELECT state, COALESCE(SUM(amount_usd),0) amount, COUNT(*) n FROM budget_ledger "
            "WHERE engagement_id=? GROUP BY state", (engagement_id,))
        by_state = {r["state"]: {"amount": round(r["amount"], 9), "count": r["n"]} for r in rows}
        return {"committed": round(sum(by_state.get(s, {}).get("amount", 0.0) for s in _ACTIVE), 9),
                "by_state": by_state}
