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

## v0.3 image verification (2026-11-20)

- `docker build -t libella:v0.3 .` SUCCESS (adds graphene, Playwright +
  Chromium at /opt/ms-playwright via PLAYWRIGHT_BROWSERS_PATH, libatomic1).
- browser_available() True inside the container as the non-root runtime user.
- Real GraphQL engagement via container API against host graphlab (:8821,
  scope url target, categories recon+api, auth.graphql + 3 identities):
  status done, 7/7 findings INDEPENDENTLY VALIDATED (CWE-89 injection,
  CWE-639 field authz x2, CWE-770 depth/alias/batch, CWE-200 introspection).
- Two orchestration defects found and fixed during this verification:
  verify/report intent dependencies now cover all audit roles; verifier
  replay selects a category the engagement permits (api-only engagements
  previously refused replay under default 'web'). Regression tests added.

## v0.2 image verification (2026-11-20)

- `docker build -t libella:v0.2 .` SUCCESS (adds trivy, gitleaks, semgrep,
  dirb wordlists; LIBELLA_TEMPLATE_DIR / LIBELLA_WORDLIST_DIR configured).
- Container health: all 9 tools available (nmap, nuclei, httpx, subfinder,
  ffuf, semgrep, trivy_fs, gitleaks, trivy_image).
- Real code-audit engagement via container API against a read-only mounted
  repo (/labs/vulnrepo, scope kind repo, category code): status done,
  6/6 seeded findings recorded (CWE-798 x2, CWE-94, CWE-78, CWE-502,
  CWE-489) with file:line evidence, state observed (static findings are
  not auto-validated; runtime correlation is roadmap).