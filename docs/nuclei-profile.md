# Nuclei focused profile: measured workload

Question: does the focused Nuclei profile reduce the work the scanner actually does, or only the size of the template tree?

Answer from the scanner's own counters (the `-stats` line, parsed by `PARSERS["nuclei_stats"]`): the workload dropped. Nuclei with the focused profile built 3,425 templates and planned 9,424 requests. The unfocused run built 6,635 templates and planned 16,005 requests.

## Setup

- Nuclei v3.11.1, templates in `~/nuclei-templates`, target PairLab vuln twin on `127.0.0.1:8851`, `-rate-limit 20`, runner timeout 600 s (`adapters.py`, `timeout_s=600`), egress proxy on.
- Harness: `benchmarks/bench_nuclei_ports.py`, a copy of `benchmarks/bench_modes.py` with the twin ports changed to 8851/8852 so other runs are not disturbed.
- Same argv for both runs except `-tags`.

## Template tree (`nuclei -tl`, protocol http)

| selection | templates listed |
|---|---|
| no filter | 12,064 |
| focused tags, no severity | 4,513 |
| severity medium,high,critical | 6,898 |
| focused tags + severity (what runs) | 3,626 |

## Measured run, mode C (nuclei only), vuln twin

| | focused | comprehensive (no tag filter) |
|---|---|---|
| templates selected (scanner `-stats`) | 3,425 | 6,635 |
| total_requests planned | 9,424 | 16,005 |
| requests sent at last sample | 9,437 | 15,117 |
| percent at last sample | 100 | 94 |
| errors (scanner) | 112 | 277 |
| egress_denied (proxy) | 295 | 324 |
| wall clock | 403.6 s | 600.6 s |
| state | completed (ok=True) | hit the 600 s cap, killed (ok=False), partial |
| stats samples | 38 | 40 |
| findings submitted | 0 | 0 |

Reduction, focused vs comprehensive: templates -48.4%, planned requests -41.1%, wall clock to completion 403.6 s vs not finished at 600.6 s.

Notes:
- "requests sent" can exceed "total_requests" slightly (9,437 vs 9,424); the scanner counts redirects/extra requests that were not in the plan. It is the scanner's number, not adjusted.
- Selected templates (3,425) is lower than the `-tl` listing (3,626): the engine drops templates it cannot compile or that need unsupported features.
- The comprehensive run was cut at 94%, so its 15,117 is a floor; the planned 16,005 is the full load.

## What the zero findings mean

Nuclei executed 3,425 templates and 9,437 requests (focused, completed) and 6,635 templates and 15,117 requests (comprehensive, 94%, partial) against this target and matched nothing. That is a statement about these templates against this target, not about Nuclei in general. The PairLab seeds are custom app logic (IDOR, custom SQLi and SSRF routes), which public templates are not written for. The runs do not show whether nuclei would detect known-CVE or default-exposure issues; the lab does not contain any. Not measured: any target where nuclei is expected to match.

## Command lines

```
LAB_MODE=vuln LAB_PORT=8851 python labs/pairlab/app.py
PYTHONPATH=src python benchmarks/bench_nuclei_ports.py --modes C --twins vuln --nuclei-profile focused --out-dir <dir>
PYTHONPATH=src python benchmarks/bench_nuclei_ports.py --modes C --twins vuln --nuclei-profile comprehensive --out-dir <dir>
nuclei -tl -t ~/nuclei-templates -pt http -tags exposure,misconfig,headers,cors,redirect,xss,sqli,traversal,ssrf,file -silent | wc -l
```

Nuclei argv recorded by the runner (focused):

```
nuclei -u http://127.0.0.1:8851 -jsonl -no-color -stats -si 5 -rate-limit 20 -timeout 10 -retries 0 -disable-update-check -no-interactsh -pt http -t /root/nuclei-templates -severity medium,high,critical -tags exposure,misconfig,headers,cors,redirect,xss,sqli,traversal,ssrf,file -proxy http://127.0.0.1:<port>
```

Comprehensive is the same without `-tags`.

## Harness defect fixed

`bench_modes.py` read `prof["tags"]` unconditionally, so `--nuclei-profile comprehensive` raised KeyError before running; the tool schema also rejects `tags=None`. Tags are now passed only when the profile has them. Nothing under `src/` changed.

Single run per profile; no repeat, so run-to-run variance in wall clock is not measured.
