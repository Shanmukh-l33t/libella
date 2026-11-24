# Juice Shop: first unfamiliar-lab assessment (2026-11-24)

Target: `bkimminich/juice-shop:latest` on 127.0.0.1 only, deterministic engine, no nuclei,
no operator hints. Engagement `done`, evidence chain intact.

## Before the SQLi fix

46 findings, 45 of them SQL injection from the new boolean-differential check. One of those
45 was VALIDATED by the verifier, which is the failure that mattered.

Two mechanisms, both real shapes this app has:
- `/rest/admin?tag=` answers 500 to a malformed value and 200 to a formed one: a refusal
  read as a differential, 44 endpoints.
- `/rest/user/whoami?callback=` is JSONP and reflects the value, so `...' AND '1'='1` came
  back as `...AND11` and the false case as `...AND12`: two 200 bodies differing by two
  digits. Echoed input is not a query, and this one validated.

## After the fix (`769659e`)

1 finding: missing security headers (CSP, HSTS, Referrer-Policy), validated. Zero false
positives. 4,755 exchanges, 486s.

## What the run did NOT find

14 documented Juice Shop categories produced nothing, including Broken Access Control,
Broken Authentication, XSS, Sensitive Data Exposure, XXE, deserialization, vulnerable
components and unvalidated redirects. That is the honest measure of reach: the engine tests
generic web hygiene and a few injection classes well, and an unfamiliar application's real
weaknesses need application-specific investigation it does not yet do.

Recoil to state plainly: one genuine finding out of a target with dozens of seeded flaws is
a low yield, and it is the strongest evidence yet that the agent work must aim at
application-specific reasoning rather than more generic checks.
