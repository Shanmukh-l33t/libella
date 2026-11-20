"""Authorization time bounds shared by scheduling and target dispatch."""
import datetime
import math
import time


def _parse(value, field: str) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError(f"{field} must be an ISO8601 timestamp or epoch seconds")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            value = float(text)
        except ValueError:
            try:
                dt = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                return dt.timestamp()
            except (OverflowError, OSError, ValueError):
                raise ValueError(f"{field} must be an ISO8601 timestamp or epoch seconds") from None
    if not math.isfinite(value):
        raise ValueError(f"{field} is not a finite timestamp")
    return float(value)


def window_state(eng: dict, now: float | None = None) -> tuple[bool, str]:
    """(may_run, detail); invalid policy raises ValueError."""
    now = time.time() if now is None else now
    start = _parse(eng.get("window_start"), "window_start")
    end = _parse(eng.get("window_end"), "window_end")
    if start is not None and end is not None and start >= end:
        raise ValueError("window_start must precede window_end")
    if start is not None and now < start:
        return False, "outside the authorized assessment window: window_start has not been reached"
    if end is not None and now >= end:
        return False, "outside the authorized assessment window: window_end has passed"
    return True, "inside the authorized assessment window"


def stored_window_refusal(db, engagement_id: str) -> str | None:
    row = db.one("SELECT window_start, window_end FROM engagements WHERE id=?", (engagement_id,))
    # Internal callers can use a caller-owned fixture ID; public routes require an engagement.
    if row is None:
        return None
    try:
        allowed, detail = window_state(row)
    except ValueError as exc:
        return f"invalid assessment window: {exc}"
    return None if allowed else detail
