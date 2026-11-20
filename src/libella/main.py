"""Libella entrypoint. Localhost-only by default."""
import argparse
import json
import os
import secrets
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from cryptography.fernet import InvalidToken

from .secrets import SecretBox


def _operator_token(data_dir: Path, rotate: bool):
    # Inspecting a credential must not start plugins, migrate a DB, or create a key.
    if not os.environ.get("LIBELLA_SECRET_KEY") and not (data_dir / "secret.key").is_file():
        raise ValueError("missing encryption key")
    box = SecretBox(data_dir)
    uri = (data_dir / "libella.db").resolve().as_uri() + ("?mode=rw" if rotate else "?mode=ro")
    with closing(sqlite3.connect(uri, uri=True)) as db, db:
        if rotate:
            db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT value_json FROM settings WHERE key='api_token'").fetchone()
        if not row:
            raise ValueError("missing stored token")
        current = box.decrypt(json.loads(row[0]))
        if rotate:
            db.execute("UPDATE settings SET value_json=? WHERE key='api_token'",
                       (json.dumps(box.encrypt(secrets.token_urlsafe(32))),))
        else:
            print(current)


def cli():
    p = argparse.ArgumentParser(prog="libella", description="Autonomous pentest workbench")
    p.add_argument("--data-dir", default=os.environ.get("LIBELLA_DATA", str(Path.home() / ".local/share/libella")))
    p.add_argument("--host", default=os.environ.get("LIBELLA_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("LIBELLA_PORT", "8787")))
    p.add_argument("--token", default=os.environ.get("LIBELLA_TOKEN"))
    modes = p.add_mutually_exclusive_group()
    modes.add_argument("--show-token", action="store_true", help="display the stored token on a private terminal")
    modes.add_argument("--rotate-token", action="store_true", help="replace the stored token with the service stopped")
    args = p.parse_args()
    if args.show_token or args.rotate_token:
        if args.show_token and not sys.stdout.isatty():
            p.error("show-token requires a private terminal (no pipes or redirection)")
        try:
            _operator_token(Path(args.data_dir), args.rotate_token)
        except (InvalidToken, ValueError, TypeError, AttributeError, OSError, sqlite3.Error):
            p.exit(1, "Cannot access stored credential; check the data directory, database and encryption key.\n")
        if args.rotate_token:
            print("Stored token replaced. Restart Libella to invalidate the old token.")
        return
    if args.token:
        os.environ["LIBELLA_TOKEN"] = args.token

    import uvicorn
    from .api import App, create_api
    app = App(args.data_dir)
    api = create_api(app)
    print(f"Libella running at http://{args.host}:{args.port}")
    print("Use the configured instance token or run libella --show-token for this data directory on a private terminal.")
    print(f"Data dir: {args.data_dir}")
    uvicorn.run(api, host=args.host, port=args.port, log_level="info", access_log=False)


if __name__ == "__main__":
    cli()
