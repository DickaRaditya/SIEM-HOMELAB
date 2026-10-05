# Lab Incident Report: Repeated Authentication Failures and File Integrity Validation

**Disposition: Closed — expected activity from an authorized lab exercise.**

The reviewed run demonstrated that Wazuh collected endpoint telemetry, matched
custom rules, correlated repeated authentication-failure fixtures, and indexed
real file-integrity events. All 13 automated checks passed, and 14 alerts were
exported. The evidence describes a controlled test; it does not establish an
actual account compromise or malicious activity on the Windows host.

| Case field | Value |
| --- | --- |
| Case ID | LAB-2026-10-05-001 |
| Prepared for | Dicka Raditya — SIEM Home Lab portfolio |
| Report date | 5 October 2026, Asia/Jakarta |
| Review method | Retrospective review of saved event fixtures, indexed alert exports, test results and configuration |
| Run ID | `20261005T153655Z-8ac00d3e` |
| Endpoint | `lab-linux`, agent `001` |
| SIEM | Wazuh 4.14.8; manager, indexer, dashboard and containerized agent |
| Primary detection | Rule `100102`, Wazuh level `10`, repeated failed logins |
| Scope | One saved test run and one disposable file inside the Linux endpoint |
| Activity type | Synthetic authentication/process/web logs and real container file operations |
| Observed impact | Test log entries and creation, modification and deletion of one disposable lab file |

## Objective and hypothesis

The primary objective was to determine whether repeated authentication-failure
events sharing a source and test-run identifier would produce a correlation
alert after passing through the agent, manager and indexer. Individual failures
should match rule `100101`; the repeated pattern should match `100102`.

Supporting checks tested a privileged-login fixture, an encoded PowerShell
command string, a traversal string, and actual file monitoring. An ordinary-user
login, a `Get-Date` command string and a normal URL should remain below the
indexing alert threshold. These controls test specific rule behavior, not
general detection accuracy.

## Evidence reviewed

The source and baseline evidence were published in repository commit
[`bb6458c`](https://github.com/DickaRaditya/SIEM-HOMELAB/commit/bb6458c37c451610fc84ef17d424a36957391d5a).

| Reference | Artifact | Purpose |
| --- | --- | --- |
| E1 | [Submitted events](../evidence/published/validation-2026-10-05/events.jsonl) | 14 JSON fixtures: eight failures, three other positive cases and three benign controls |
| E2 | [Indexed alerts](../evidence/published/validation-2026-10-05/alerts.json) | 14 exported alert documents, including IDs, timestamps, decoded fields and file hashes |
| E3 | [Machine-readable result](../evidence/published/validation-2026-10-05/result.json) | Run boundaries, 13 check results, observed rule IDs and PASS status |
| E4 | [Human-readable test report](../evidence/published/validation-2026-10-05/REPORT.md) | Summary of the completed automated run |
| E5 | [Custom detection rules](../config/local_rules.xml) | Matching fields, correlation key, window and configured severities |
| E6 | [Endpoint configuration](../config/agent.conf) and [test runner](../scripts/lab.py) | Collection path, FIM settings and exact test actions |
| E7 | [Deployment validation](VALIDATION.md) | Recorded container health, active agent and green indexer observations |

The JSON logs were collected from `/lab/logs/events.json`. The source field
`data.lab_source_ip: 192.0.2.10` is synthetic fixture data. The agent's recorded
container address, `172.20.0.4`, identifies the collector in this run. Neither
address is evidence of an external attacker or a network connection made by the
test runner.

The investigation used the run ID for JSON events and the exact FIM path below
to distinguish this run from earlier tests:

```text
/lab/monitored/20261005T153655Z-8ac00d3e.txt
```

## Timeline

All times below are **5 October 2026, WIB (UTC+07:00, Asia/Jakarta)**. Alert rows
use each exported document's `timestamp`; those timestamps do not independently
measure when indexing finished or when a person viewed the alert. E3 records the
overall test interval, which lasted **79.859 seconds**.

| Time (WIB) | Observation | Evidence |
| --- | --- | --- |
| 22:36:55.763 | Test run started; fixtures carry a common generation timestamp | E1, E3 |
| 22:37:11.574 | First exported individual authentication-failure alert, rule `100101` | E2: `1791214631.711974` |
| 22:37:11.586 | Repeated-failure correlation alert, rule `100102`, level `10` | E2: `1791214631.714902` |
| 22:37:11.598 | Privileged-login fixture matched rule `100103` | E2: `1791214631.719753` |
| 22:37:11.598 | Encoded-command fixture matched rule `100104` | E2: `1791214631.720458` |
| 22:37:11.598 | Traversal-string fixture matched rule `100105` | E2: `1791214631.718967` |
| 22:37:18.980 | Disposable file addition detected, rule `554` | E2: `1791214638.721353` |
| 22:37:32.746 | File content/hash change detected, rule `550` | E2: `1791214652.722063` |
| 22:37:46.196 | Disposable file deletion detected, rule `553` | E2: `1791214666.723281` |
| 22:38:15.622 | Runner completed with all checks passing and 14 exported alerts | E3 |

Several fixtures share identical timestamps. The saved fixture generation time
precedes rule-engine checks and log injection in the runner. It is therefore not
a reliable measure of event-to-alert latency. Equal timestamps also cannot
establish an attack sequence or causality between these independent cases.

## Findings and analysis

### Repeated authentication failures

The JSON decoder recognized `integration: homelab`. Parent rule `100100` routed
the fixture to custom rules, and `event_type: auth_failure` matched individual
failure rule `100101` at level `5`.

Rule `100102` references `100101` through `if_matched_sid`, has configured
`frequency="5"` and `timeframe="60"`, and compares `correlation_key`. For this
run that key was:

```text
20261005T153655Z-8ac00d3e:192.0.2.10
```

The export contains **seven individual-failure alerts and one correlation
alert** for the eight submitted failure fixtures. In the correlation document,
the current event carries sequence `4`; its `previous_output` contains sequences
`3`, `6`, `2` and `1`. That is evidence of prior matching events with the same
key. It also shows that fixture sequence numbers did not match processing order;
the alert should not be described as firing on the fourth chronological attempt.

The correlation document carries the ATT&CK label **T1110.001 — Password
Guessing**. This is the rule's scenario mapping. No passwords were guessed, no
SSH login was attempted, and the source address was not contacted. The confirmed
finding is that the configured detection worked on the supplied telemetry.

The alert's `rule.firedtimes` value is `2`, but only **one** `100102` document
belongs to this run's export. This report counts exported documents scoped to the
run rather than treating that engine counter as a per-run incident count.

### Other synthetic detections

| Rule | Level | Observed match | Interpretation |
| --- | ---: | --- | --- |
| `100103` | 7 | `auth_success` with `lab_user: root` | An independent privileged-login fixture; no real root session was established |
| `100104` | 10 | A PowerShell command string containing `-EncodedCommand` | The string pattern matched; PowerShell was not executed |
| `100105` | 8 | `/download?file=../../etc/passwd` | The traversal pattern matched; no HTTP request or file disclosure occurred |

The root-login alert is not a failure-then-success correlation detection.
The failure fixtures use `student`, while the privileged-login fixture uses
`root`. Shared source/run fields do not establish that one account was guessed
successfully or that the process/web fixtures followed a compromise.

The remaining three fixtures represented an ordinary `student` login,
`powershell.exe Get-Date`, and `/index.html`. The saved result reports that the
rule-engine tests passed and these benign controls produced no indexed alert.
Because level-zero matches are not exported as alerts, their absence alone
cannot prove collection of each benign event; the rule-engine check provides
separate support for their expected classification.

### Real file integrity monitoring

The runner created, modified and deleted one unique file inside the endpoint
volume. All three alert documents identify the same path and `mode: realtime`.
Rules `554`, `550` and `553` recorded addition, modification and deletion at
levels `5`, `7` and `7`, respectively.

The modification alert lists changes to `mtime`, `md5`, `sha1` and `sha256`.
Its before/after SHA-256 values are:

```text
Before: e535b7121aa4038e085121c5b4d28807829b9d0a2deed085f51535b9cea1f97f
After:  44e1d1bba100ed2506c034241d4cc6ae061e243ce7a1452b8e4ef4cd4c0e0e7d
```

Recomputing SHA-256 for the runner's expected strings, including their trailing
newline, reproduces both values:

```text
Home lab create: 20261005T153655Z-8ac00d3e
Home lab modify: 20261005T153655Z-8ac00d3e
```

Each version is 43 bytes. The unchanged size and permissions did not prevent
content-change detection. This supports the conclusion that the FIM alerts
represent the intended disposable-file exercise. The export does not include a
`syscheck.diff` field, so this report relies on hashes and known runner content
rather than claiming a captured text diff.

The file owner is recorded as `root`. Ownership metadata does not identify the
process or person who performed a change. Attribution to the test runner comes
from its defined actions, unique run/path and matching content hashes; this is
not a process-audit or forensic disk investigation.

## Outcome and impact

| Measure | Observed result |
| --- | --- |
| Synthetic input fixtures | 14: 11 positive cases and 3 benign controls |
| Indexed synthetic alerts | 11: 7 individual failures, 1 correlation and 3 other positive detections |
| Indexed real FIM alerts | 3: added, modified, deleted |
| Total exported alerts | 14 |
| Automated checks | 13 passed, 0 failed |
| Disposition | Expected lab activity; no escalation required for this exercise |

The repeated-failure and encoded-command rules reached level `10`, their
configured detection priorities. These values do not quantify business impact.
The activity in scope changed a test log and one disposable file inside the
container. There is no evidence in the reviewed records of actual account abuse,
malware execution, data theft or compromise of the Windows host. The limited
dataset is not a general assessment of that host or the home network.

## Response taken and recommended production workflow

For this exercise, the runner verified the indexed detections, deleted its
disposable FIM file as the final test action, and saved the evidence. Review of
the exported records supports closing the case as expected lab activity.
Automated response is disabled in the endpoint configuration; no account was
disabled, source blocked or machine isolated as part of this investigation.

If comparable alerts arose from native endpoint telemetry, the recommended
investigation would be to verify the source logs and asset context, correlate
the affected account and destination with successful authentications, and check
authorized administration or testing. A process alert would require executable,
parent process, user and command-line evidence. An unexplained file change would
require change authorization and process/audit evidence before attributing it
to an attacker. Containment would follow the organization's incident procedure
if that additional evidence justified it. These are recommendations, not actions
performed in this lab report.

## Tuning and retest plan

No detection changes or new test runs were performed to prepare this report.
The baseline run above is the verified result. The following improvements remain
proposed work:

| Proposed improvement | Benefit and trade-off | Planned verification |
| --- | --- | --- |
| Test correlation boundaries and key isolation | Establish actual threshold/window behavior and guard against mixing unrelated events; adds test cases | Try isolated counts around the configured threshold, a 61-second separation, and different source/run keys |
| Add native Linux authentication collection | Demonstrate detection on actual service logs; requires a controlled VM and native rules | Perform authorized failed logins against that VM, then verify source, user, destination and expected rule IDs |
| Add a separate failure-then-success rule | Provide account-specific context beyond the independent root fixture; legitimate recovery can also match | Test same-account success after failures, different-account success, and success outside the window |
| Expand encoded-command controls | Evaluate case variations, other switch forms and legitimate administration; broader matches may add noise | Add positive and benign samples, then compare rule-engine results and indexed alerts |

For any implemented change, preserve this baseline, record the rule revision,
run the full suite with a new run ID, and compare expected versus observed
results. Do not reuse this report's PASS status as evidence for a modified rule.

## Limitations and lessons

The JSON tests demonstrate collection, parsing, custom matching and correlation.
They do not demonstrate a real SSH attack, Windows process collection or a web
exploit. FIM demonstrates actual container file monitoring, but not who changed
the file. The three benign controls and one saved run are insufficient to
estimate accuracy, precision, recall, false-positive rate or MTTD.

The reviewed artifacts contain no dashboard screenshots or timestamped human
triage session. Alert availability was established by querying the indexer;
interactive browser login and screenshot capture were not part of this review.

The exercise illustrates why an investigation should separate event content
from observed actions, use run-scoped alert counts, distinguish alert timestamps
from ingestion latency, and check content hashes instead of file size alone.
It also shows that a useful portfolio case can document verified behavior and
its limits without representing a simulation as a real compromise.

## Evidence integrity appendix

These SHA-256 values were calculated from the reviewed files at report
preparation. They support later byte-for-byte comparison; they are not evidence
of a formal forensic chain of custody.

```text
events.jsonl  a6c92cfbb6503cbc8c43c6a861f29eb14f9a49da9fe54bcc913a53b523fcc710
alerts.json   a7d64667947d8690fd50d195577e4e335edd58112495d9e8e6d5e096849a4c32
result.json   df7744d3b461fbe2a98fec982489f91c2f98cc585edcb006db5fc730e175abed
```
