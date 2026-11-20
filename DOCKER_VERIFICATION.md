# Docker Installation Verification (real execution)

Date: 2026-11-20. Host: Linux x86_64, Docker 29.1.3.

## Steps performed

1. `docker build -t libella:local .` from the published repository.
   Result: SUCCESS (multi-stage: node web build, pinned scanner binaries,
   python runtime, non-root uid 10001).
2. `docker run -d --name libella-verify --network host
   -e LIBELLA_TOKEN=*** -e LIBELLA_DATA=/data libella:local`
   Result: container healthy (HEALTHCHECK passing), uvicorn on :8787,
   all 5 scanner tools detected inside the image (nmap, nuclei, httpx,
   subfinder, ffuf), nuclei templates present.
3. Created an engagement via the container API against the PairLab vuln
   twin (http://127.0.0.1:8801), scope url target, categories
   recon/web/api/infra, rate 20 rps, budget 600s.
4. Started in deterministic mode; polled to completion.
5. Read findings and report via the container API.

## Observed results

- Engagement status: done, 6/6 intents done, 0 blocked.
- Findings: 8 total, 8 independently validated (the 8 seed classes
  testable without configured identities/hints; auth-bypass, IDOR,
  cookie-flag, UNION-SQLi and SSRF classes require identity/hint config
  and are exercised in the full benchmark with them).
- Report rendered deterministically (JSON/MD/SARIF) with summary counters.
- Token auth enforced on every route (401 without/with wrong token).
- Loopback-only exposure via compose default; --network host used here
  solely to reach the host lab for verification.

## Conclusion

The documented single-container installation works from a clean image:
build, run, authenticate, create engagement, execute real assessment,
inspect validated findings, export report. No manual tool installation
required on the host.