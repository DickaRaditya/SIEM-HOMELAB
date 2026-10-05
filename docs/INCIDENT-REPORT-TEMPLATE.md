# Lab investigation: <title>

Status: **Template — replace placeholders with your own observations.**

| Field | Value |
| --- | --- |
| Analyst | <your name> |
| Date and timezone | <date, UTC or Asia/Jakarta> |
| Test run ID | <exact run ID> |
| Endpoint | lab-linux |
| Wazuh version | 4.14.8 |
| Scenario type | <synthetic telemetry / real lab file operation> |
| Disposition | <expected test activity / needs investigation> |

## Objective and hypothesis

What activity should trigger the rule? What should remain quiet?

## Evidence

Link your reviewed `REPORT.md`, relevant alert JSON, rule XML and screenshots.
Record rule ID, severity, timestamp, source field, user/path and test run ID.

## Timeline

| Time (include timezone) | Observation | Evidence reference |
| --- | --- | --- |
| <time> | <event submitted or file changed> | <source> |
| <time> | <alert indexed> | <alert ID> |
| <time> | <analyst reviewed> | <screenshot/note> |

## Analysis

Explain why it matched, what correlation was applied, and whether a benign
explanation is possible. Separate observed facts from hypotheses. Identify what
the lab cannot establish from the available logs.

## Response recommendation

Describe the next investigative step in a real environment. Do not claim an
account was blocked or a host isolated unless you actually implemented and
verified that response. Automated response is disabled in this lab.

## Tuning and retest

Describe a specific improvement and its trade-off. Record the new test run ID
and compare the expected/observed results, including benign controls.

## Lessons learned

What did you learn about telemetry, detection, triage and reproducibility?
