# Investigation queries

Use the dashboard's DQL search bar and set the time range to Last 1 hour. Replace
`RUN_ID` with the exact ID printed by the test runner. Field names are case-sensitive.

| Purpose | DQL query |
| --- | --- |
| Everything from the lab endpoint | `agent.name: "lab-linux"` |
| Synthetic events from one run | `data.lab_run_id: "RUN_ID"` |
| All custom detections | `rule.groups: "homelab"` |
| Repeated-login alerts | `rule.id: "100102"` |
| Encoded-command fixtures | `rule.id: "100104"` |
| High-severity lab alerts | `agent.name: "lab-linux" AND rule.level >= 10` |
| FIM from one run | `agent.name: "lab-linux" AND syscheck.path: "/lab/monitored/RUN_ID.txt"` |
| All FIM exercise events | `agent.name: "lab-linux" AND rule.id: ("550" OR "553" OR "554")` |
| Benign fixtures (expect zero alerts) | `data.lab_run_id: "RUN_ID" AND data.lab_case: "benign"` |

If the search bar is in Lucene mode, switch to DQL or use the dashboard's Add
filter controls to set the equivalent exact field values.

Suggested Discover columns: `timestamp`, `agent.name`, `rule.id`, `rule.level`,
`rule.description`, `data.lab_source_ip`, `data.lab_user`, `data.lab_run_id`.
For FIM, add `syscheck.path` and `syscheck.event`.

Create your own saved visualizations for the portfolio:

1. Alert count by `rule.id` (bar chart).
2. Alert timeline (date histogram on `timestamp`).
3. Severity distribution (`rule.level`).
4. A table of file changes (`syscheck.path`, `syscheck.event`, `timestamp`).

Use a filter for one test run or the lab endpoint so manager/system alerts do not
distort the exercise. Record your time range in every screenshot. Do not call
alert severity a calibrated risk score; these are exercise priorities.
