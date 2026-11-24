"""A tiny fake scanner: raw TCP connects to every host:port in argv, ignoring any proxy.

Stdlib only (it runs as uid 65534 inside a namespace). Prints one line per
target: `<host:port> CONNECTED|FAILED <error>`. With --loop it keeps going until
killed, so timeout/cancel paths have something to interrupt. Exit 0 when every
target connected, 1 otherwise.
"""
import socket
import sys
import time


def hit(target: str) -> bool:
    host, port = target.rsplit(":", 1)
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect((host, int(port)))
        s.sendall(b"GET /raw HTTP/1.0\r\n\r\n")
        print(target, "CONNECTED", flush=True)
        return True
    except OSError as e:
        print(target, "FAILED", e, flush=True)
        return False
    finally:
        s.close()


if __name__ == "__main__":
    args = sys.argv[1:]
    loop = "--loop" in args
    targets = [a for a in args if a != "--loop"]
    while True:
        ok = [hit(t) for t in targets]
        if not loop:
            sys.exit(0 if all(ok) else 1)
        time.sleep(0.2)
