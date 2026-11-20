"""Libella entrypoint. Localhost-only by default."""
import argparse
import os
from pathlib import Path


def cli():
    p = argparse.ArgumentParser(prog="libella", description="Autonomous pentest workbench")
    p.add_argument("--data-dir", default=os.environ.get("LIBELLA_DATA", str(Path.home() / ".local/share/libella")))
    p.add_argument("--host", default=os.environ.get("LIBELLA_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("LIBELLA_PORT", "8787")))
    p.add_argument("--token", default=os.environ.get("LIBELLA_TOKEN"))
    args = p.parse_args()
    if args.token:
        os.environ["LIBELLA_TOKEN"] = args.token

    import uvicorn
    from .api import App, create_api
    app = App(args.data_dir)
    api = create_api(app)
    print(f"Libella running at http://{args.host}:{args.port}")
    print(f"API token: {app.token}")
    print(f"Data dir: {args.data_dir}")
    uvicorn.run(api, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    cli()