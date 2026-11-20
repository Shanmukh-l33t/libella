# Security Policy

## Authorization requirement

Libella is for assessing systems you own or have explicit written permission
to test. Creating an engagement is an assertion of authorization. The
platform enforces the declared scope in code, but it cannot verify that you
actually hold authorization. You are responsible for the legal basis of
every assessment.

Never point Libella at third-party infrastructure without permission.
"Everything is approved" is not a scope; declare concrete targets.

## Supported versions

The latest release on main is supported. Older tags receive no fixes.

## Reporting a vulnerability in Libella

Email the maintainers via the contact on the GitHub profile, or open a
private security advisory on the repository. Do not open public issues for
exploitable defects. Include: affected version, reproduction steps, impact,
and any suggested fix. We aim to acknowledge within 72 hours.

## Platform security model

See THREAT_MODEL.md. Summary of enforced controls:

- Engagement authorization object checked before every egress-capable action
  (DNS-resolved IPs, redirect hops, post-connect peer verification).
- Typed tool contracts; argv built by code; no shell; no free-text args.
- Append-only hash-chained evidence; integrity re-checked on read.
- Independent replay verification gates the validated state.
- Token auth on all API routes; loopback-only default bind.
- Secret redaction in reports and evidence views.
- Per-engagement budgets (time, cost, rate, concurrency) and emergency stop.

## Known residual risks (honest list)

Earlier versions wrote the instance token to startup logs and accepted it in URLs.
Treat the old token as disclosed to anyone who could read those logs. Stop all
Libella processes using the data directory. With the upgraded code, run
`libella --data-dir <directory> --rotate-token`, then restart the service.
`LIBELLA_TOKEN` is for first initialization; changing it does not rotate an existing
instance. Retrieve the replacement with `libella --data-dir <directory> --show-token`
on a private terminal (in Compose, `docker compose exec libella libella --data-dir /data --show-token`).
Update API clients. Restoring an older database also restores the older token:
rotate again before serving traffic. Protect terminal recordings, backups, and
reverse-proxy logs. Do not log Authorization headers, cookies, or URL queries.

- Subprocess scanners that re-resolve DNS have a TOCTOU window between the
  platform's scope check and the tool's own connection. The platform HTTP
  client is peer-verified; full network-namespace egress isolation is roadmap.
- SQLite single-writer: concurrent heavy writes serialize; not multi-tenant
  hardened. Run one instance per trust domain.
- LLM planning quality depends on the configured model; the compile gate
  bounds what a model can authorize, not how useful its proposals are.
- Evidence at rest is not encrypted by default (filesystem permissions are
  the boundary). Encrypt the volume for sensitive engagements.