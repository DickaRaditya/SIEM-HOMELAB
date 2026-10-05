# Wazuh lab test: PASS

Run: `20261005T153655Z-8ac00d3e`

Started (UTC): 2026-10-05T15:36:55.763436+00:00

Finished (UTC): 2026-10-05T15:38:15.622554+00:00

Version: 4.14.8; endpoint: lab-linux; indexed alerts: 14

| Check | Result |
| --- | --- |
| endpoint connected | PASS |
| Wazuh rule engine tests | PASS |
| synthetic rule 100101 indexed | PASS |
| synthetic rule 100102 indexed | PASS |
| synthetic rule 100103 indexed | PASS |
| synthetic rule 100104 indexed | PASS |
| synthetic rule 100105 indexed | PASS |
| real FIM create rule 554 indexed | PASS |
| real FIM modify rule 550 indexed | PASS |
| real FIM delete rule 553 indexed | PASS |
| all expected alerts present in final evidence | PASS |
| benign controls produced no indexed alert | PASS |
| indexer cluster not red | PASS |

Observed rule IDs: 100101, 100102, 100103, 100104, 100105, 550, 553, 554.

Authentication, PowerShell and web events are synthetic JSON fixtures. No attack,
login attempt or PowerShell command was executed. FIM create/modify/delete operations
are real changes to one disposable file inside the lab endpoint volume.
Passing verifies agent collection, manager rules and indexer storage for these cases.
It does not establish detection accuracy on production data or on a Windows endpoint.

Error: None

Evidence: `events.jsonl`, `alerts.json`, `result.json`. Capture the dashboard separately.
