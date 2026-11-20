"""Message signing helper: key material is read from a file outside the repo."""
import os
from pathlib import Path


def signing_key() -> bytes:
    path = os.environ.get("SIGNING_KEY_PATH")
    if not path:
        raise RuntimeError("SIGNING_KEY_PATH is not configured")
    return Path(path).read_text(encoding="utf-8").encode()
