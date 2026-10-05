# Observed validation — 5 October 2026

The baseline was deployed and tested locally on Windows with Docker Desktop's
Linux engine. These are actual observations, not expected/example results.

| Check | Observed result |
| --- | --- |
| Wazuh versions | Manager, indexer, dashboard and agent: 4.14.8 |
| Docker engine | 22 logical CPUs, 15.5 GiB available RAM |
| Host resources | About 32 GB RAM; 22 logical processors |
| Container health | All four services healthy |
| Manager API authentication | Generated service credentials accepted |
| Indexer | Green, one node |
| Endpoint | `lab-linux`, agent 001, Active |
| Published port | Dashboard only, `127.0.0.1:8443` |
| Static configuration | Compose model, XML, version pins, loopback binding and upstream SHA-256 passed |
| CLI regression tests | 7 passed |
| Wazuh rules | Positive, benign and repeated-login correlation tests passed |
| Full pipeline | 13 checks passed; 14 indexed alerts |

Run ID: `20261005T153655Z-8ac00d3e`.

Run interval: **5 October 2026, 22:36:55–22:38:15 WIB (Asia/Jakarta)**.
Machine-readable evidence uses UTC: 15:36:55–15:38:15.

| Rule | Indexed alerts in this run |
| --- | ---: |
| 100101 — individual failed login | 7 |
| 100102 — repeated-login correlation | 1 |
| 100103 — root login | 1 |
| 100104 — encoded PowerShell string | 1 |
| 100105 — traversal string | 1 |
| 554 — actual file added | 1 |
| 550 — actual file modified | 1 |
| 553 — actual file deleted | 1 |

Authentication, process and web events were synthetic. File operations were real
inside the endpoint volume. The three benign fixtures produced no indexed alert.
This small fixture set does not establish real-world detection accuracy.

The reviewed report, JSON check summary, event fixtures and indexed alerts are copied to
[`evidence/published/validation-2026-10-05/`](../evidence/published/validation-2026-10-05/).
Original events and indexed alerts remain in
`evidence/runs/20261005T153655Z-8ac00d3e/` (ignored by Git).

The dashboard's HTTPS login route passed its container health check. Interactive
browser sign-in and screenshots remain manual: the automated browser stopped at
the private-CA certificate warning. Open `https://localhost:8443` in your browser
and review/accept that local lab warning yourself before logging in.

The lab is left running. Use `python scripts/lab.py stop` to release its running
resources while preserving data. These results describe this run, not future
availability or a claim that every optional extension was tested.

To rerun the source-only regression suite:

```powershell
python -m unittest discover -s tests -v
python scripts/lab.py validate
```
