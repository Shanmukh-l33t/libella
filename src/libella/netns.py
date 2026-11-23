"""Real network confinement for raw-socket subprocesses (nmap, future unproxied tools).

A disposable network namespace joined to the host by a veth pair. The nftables
filter lives INSIDE the namespace (policy drop, accept only the authorized
IPv4:tcp-ports), and the tool runs as an unprivileged uid with no capabilities,
so it cannot alter it. The tool's socket calls, raw or not, hit that filter.

Design (measured on this host, see docs/egress-enforcement.md): no forwarding.
The namespace's only route is the host end of the veth, so it reaches addresses
the HOST terminates (host-local lab/target addresses). A remote target would need
the host to forward + NAT, and here docker's FORWARD policy-drop (another owner's
table) blocks that, so it is refused (`NetnsUnavailable`), never half-confined.

Everything created here is removed on success, exception, timeout and cancel,
and `reap_orphans()` removes what a killed process left behind.
"""
import ipaddress
import os
import random
import re
import shutil
import signal
import socket
import subprocess
from dataclasses import dataclass

UID = 65534  # nobody
PREFIX = "lb"
_ORPHAN = re.compile(rf"^{PREFIX}(?:ns|h|n)(\d+)_[0-9a-f]{{3}}$")


class NetnsUnavailable(RuntimeError):
    """Isolation could not be set up or verified: the caller must not run the tool."""


@dataclass
class NetnsResult:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool


def _bin(name: str) -> str:
    p = shutil.which(name, path="/usr/sbin:/sbin:/usr/bin:/bin")
    if p is None:
        raise NetnsUnavailable(f"'{name}' is not installed")
    return p


def _sh(*argv: str, stdin: str | None = None, check: bool = True) -> str:
    try:
        p = subprocess.run([_bin(argv[0]), *argv[1:]], input=stdin, text=True,
                           capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise NetnsUnavailable(f"{argv[0]}: {e}") from e
    if check and p.returncode != 0:
        raise NetnsUnavailable(f"{' '.join(argv[:4])}: {(p.stderr or p.stdout).strip()[:200]}")
    return p.stdout


def host_local(ip: str) -> bool:
    """True when the host itself terminates `ip` and the namespace can reach it.

    Loopback is excluded: the namespace has its own loopback, so 127.x would
    silently be a different (empty) host.
    """
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version != 4 or a.is_loopback:
        return False
    with socket.socket() as s:
        try:
            s.bind((ip, 0))
        except OSError:
            return False
    return True


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _destroy(ns: str, hif: str) -> None:
    """Idempotent teardown: kill what is still inside, then drop the veth and the ns."""
    pids = _sh("ip", "netns", "pids", ns, check=False).split()
    for pid in pids:
        try:
            os.kill(int(pid), signal.SIGKILL)
        except (ProcessLookupError, ValueError):
            pass
    _sh("ip", "link", "del", hif, check=False)  # removes both veth ends synchronously
    _sh("ip", "netns", "del", ns, check=False)


def reap_orphans() -> list[str]:
    """Remove namespaces/veths whose creating process is dead. Returns what was removed."""
    removed = []
    for line in _sh("ip", "netns", "list", check=False).splitlines():
        name = line.split()[0] if line.split() else ""
        m = _ORPHAN.match(name)
        if m and not _pid_alive(int(m.group(1))):
            _destroy(name, "lbh" + name[4:])
            removed.append(name)
    for line in _sh("ip", "-o", "link", "show", check=False).splitlines():
        parts = line.split(":")
        name = parts[1].strip().split("@")[0] if len(parts) > 1 else ""
        m = _ORPHAN.match(name)
        if m and name.startswith("lbh") and not _pid_alive(int(m.group(1))):
            _sh("ip", "link", "del", name, check=False)
            removed.append(name)
    return removed


class Confinement:
    """`with Confinement(ips, ports) as c: c.argv([...])` / `c.run([...])`.

    ips: IPv4 addresses the tool may reach (each must be host-local).
    ports: tcp ports it may reach on them; None = any tcp port on those ips.
    Everything else the tool sends is dropped by the in-namespace filter.
    """

    def __init__(self, ips, ports=None, uid: int = UID):
        self.ips = sorted({str(i) for i in ips})
        self.ports = sorted({int(p) for p in ports}) if ports else None
        self.uid = uid
        self.ns = self.hif = self.nif = ""
        self.host_ip = self.ns_ip = ""
        self.rules = ""
        self._live = False

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self):
        for ip in self.ips:
            if not host_local(ip):
                raise NetnsUnavailable(
                    f"{ip} is not an address this host terminates (or is loopback): the "
                    "namespace has no forwarding, so it could not reach it")
        if not self.ips:
            raise NetnsUnavailable("no authorized address to confine the tool to")
        if self.ports and not all(0 < p < 65536 for p in self.ports):
            raise NetnsUnavailable("invalid port in the authorized port set")
        if os.geteuid() != 0:
            raise NetnsUnavailable("network namespaces need root (CAP_NET_ADMIN)")
        reap_orphans()
        tok = f"{os.getpid()}_{random.randrange(4096):03x}"
        self.ns, self.hif, self.nif = f"{PREFIX}ns{tok}", f"{PREFIX}h{tok}", f"{PREFIX}n{tok}"
        try:
            self._build()
        except BaseException as e:
            _destroy(self.ns, self.hif)
            if isinstance(e, NetnsUnavailable):
                raise
            if isinstance(e, Exception):
                raise NetnsUnavailable(str(e)) from e
            raise
        self._live = True
        return self

    def __exit__(self, *exc):
        _destroy(self.ns, self.hif)
        self._live = False
        return False

    def _build(self):
        used = []
        for line in _sh("ip", "-o", "-4", "route", "show").splitlines():
            try:
                used.append(ipaddress.ip_network(line.split()[0], strict=False))
            except (ValueError, IndexError):
                pass  # "default", "unreachable ..." etc. cannot collide with a /30
        for _ in range(40):  # a random /30 in 10.254/16 that no existing route overlaps
            base = random.randrange(0, 65536, 4)
            net = ipaddress.ip_network((int(ipaddress.ip_address("10.254.0.0")) + base, 30))
            if not any(net.overlaps(u) for u in used):
                break
        else:
            raise NetnsUnavailable("no free /30 for the veth")
        self.host_ip, self.ns_ip = str(net[1]), str(net[2])
        _sh("ip", "netns", "add", self.ns)
        _sh("ip", "link", "add", self.hif, "type", "veth", "peer", "name", self.nif)
        _sh("ip", "link", "set", self.nif, "netns", self.ns)
        _sh("ip", "addr", "add", f"{self.host_ip}/30", "dev", self.hif)
        _sh("ip", "link", "set", self.hif, "up")
        inns = ["ip", "netns", "exec", self.ns]
        _sh(*inns, "ip", "addr", "add", f"{self.ns_ip}/30", "dev", self.nif)
        _sh(*inns, "ip", "link", "set", self.nif, "up")
        _sh(*inns, "ip", "link", "set", "lo", "up")
        # connected /30 route comes from the address; the default route reaches host-local addresses
        _sh(*inns, "ip", "route", "add", "default", "via", self.host_ip)
        dport = f" tcp dport {{ {', '.join(map(str, self.ports))} }}" if self.ports else " meta l4proto tcp"
        script = (
            "add table inet guard\n"
            "add chain inet guard o { type filter hook output priority 0 ; policy drop ; }\n"
            "add rule inet guard o ct state established,related accept\n"
            f"add rule inet guard o ip daddr {{ {', '.join(self.ips)} }}{dport} accept\n")
        _sh(*inns, "nft", "-f", "-", stdin=script)
        # verify the filter is really there before anything is allowed to run in it
        listing = _sh(*inns, "nft", "list", "chain", "inet", "guard", "o")
        if "policy drop" not in listing or self.ips[0] not in listing:
            raise NetnsUnavailable("the in-namespace filter was not applied")
        self.rules = listing

    # -- running -----------------------------------------------------------
    def argv(self, argv: list[str]) -> list[str]:
        """argv wrapped so it runs inside the namespace as an unprivileged, capless uid."""
        if not self._live:
            raise NetnsUnavailable("confinement is not active")
        return [_bin("ip"), "netns", "exec", self.ns, _bin("setpriv"),
                f"--reuid={self.uid}", f"--regid={self.uid}", "--clear-groups",
                "--bounding-set=-all", "--no-new-privs", *argv]

    def run(self, argv: list[str], cwd=None, env=None, timeout: float = 60) -> NetnsResult:
        p = subprocess.Popen(self.argv(argv), cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            out, err = p.communicate(timeout=timeout)
            return NetnsResult(p.returncode, out, err, False)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                p.kill()
            out, err = p.communicate()
            return NetnsResult(None, out, err, True)
