# Turn the lab into a portfolio project

The valuable part is your evidence and reasoning: explain the data path, prove
the detections worked, identify limitations, and show how you would improve them.

## Recommended repository presentation

1. Write a short project objective and explain why you chose Wazuh.
2. Keep the architecture diagram and state your tested hardware/software versions.
3. Run `python scripts/lab.py test` and read the generated report.
4. Capture the screenshots below with the same run ID and time range.
5. Copy only reviewed evidence into `evidence/published/`.
6. Fill out an investigation using `INCIDENT-REPORT-TEMPLATE.md`.
7. Describe one improvement you implemented, then rerun the tests and compare results.

Do not publish `.env`, `runtime`, private keys, Docker inspect/config output or
unreviewed logs. The Git ignore rules exclude generated secrets and raw runs.
Check `git status --short` and inspect the actual staged files before publishing.
The lab scripts never initialize Git, create commits or upload files automatically.

## Screenshot checklist

| File suggestion | Show |
| --- | --- |
| `01-agent-active.png` | `lab-linux` registered and active |
| `02-test-pass.png` | Terminal PASS, run ID and timestamp; no credentials |
| `03-auth-correlation.png` | Rule 100102 with source, rule level and run ID |
| `04-process-detection.png` | Rule 100104 with the synthetic command string |
| `05-file-integrity.png` | A real modified-file alert, path and hashes/diff |
| `06-dashboard-overview.png` | Your alert timeline and rule distribution |

Do not manufacture screenshots or relabel synthetic events as real attacks.
The FIM exercises demonstrate actual file monitoring. The JSON exercises show
custom log collection, rule logic and correlation, not a native SSH or Sysmon integration.

## A concise demo video (3-5 minutes)

- Explain the architecture and the default local-only dashboard access.
- Show the agent connected, then launch a test.
- Open the resulting authentication-correlation and FIM alerts.
- Explain the match fields, severity and a possible benign explanation.
- Show the evidence report and one improvement you would make for a real network.

## Investigate, do not just screenshot

For the repeated-login exercise, explain how the rule groups by source/run, the
60-second window and the difference between individual failures and correlation.
The subsequent root-login fixture is an independent detection; this lab does not
claim a failure-then-success correlation rule.

For encoded PowerShell, discuss why legitimate administration may use encoding.
The current pattern is intentionally simple: it misses abbreviated switches,
other shells and more complex evasion. Test improvements with both positive and
benign samples. MITRE ATT&CK labels describe the scenario concept; they do not
prove an adversary performed the technique.

For FIM, distinguish a detected configuration change from a confirmed compromise.
Explain who could authorize it and what additional audit telemetry would be needed.

## Honest metrics

Report the number of checks passed, alerts by rule, repeatability across runs,
and the time range observed. Do not claim accuracy, precision, recall, MTTD or
false-positive rate from this tiny constructed dataset. Three benign fixtures
are regression controls, not a statistical evaluation.

## Useful next milestones

- Add a real Windows VM agent with Security and Sysmon event collection.
- Detect native SSH failures on a Linux VM, then compare with the synthetic tests.
- Tune a rule, add adversarial/benign regression fixtures, and record the change.
- Add index retention and a tested backup/restore procedure.
- Separate ingestion credentials from administrator credentials.
- Enable vulnerability assessment on a supported full VM and explain findings.

These are extensions, not completed features of the baseline lab.
