"""Run one CloudLab twin: moto endpoint on 127.0.0.1, seeded vuln or hardened.

Prints one line `READY <endpoint>` on stdout as soon as the mock is serving and
seeded, then blocks. Runs in its own process so the two twins never share moto's
global backend (which is keyed by account id, not by endpoint).
"""
import argparse
import sys
import time

from moto.server import ThreadedMotoServer

import seed as seed_mod


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["vuln", "hardened"])
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args()

    srv = ThreadedMotoServer(ip_address="127.0.0.1", port=args.port, verbose=False)
    srv.start()
    host, port = srv.get_host_and_port()
    endpoint = f"http://{host}:{port}"
    seed_mod.seed(args.mode, endpoint)
    print(f"READY {endpoint}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        srv.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
