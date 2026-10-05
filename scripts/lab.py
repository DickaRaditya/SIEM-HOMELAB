"""Portable Wazuh lab lifecycle and evidence CLI. Python 3.10+, stdlib only."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "runtime"
UPSTREAM = ROOT / "vendor" / "wazuh"
VERSION = "4.14.8"
COMPOSE = ["docker", "compose", "--project-directory", str(ROOT), "-f", str(ROOT / "compose.yml")]
EXPECTED = {"100101", "100102", "100103", "100104", "100105"}
CERTS = ["root-ca.pem", "root-ca-manager.pem", "admin.pem", "admin-key.pem",
         "wazuh.indexer.pem", "wazuh.indexer-key.pem", "wazuh.manager.pem",
         "wazuh.manager-key.pem", "wazuh.dashboard.pem", "wazuh.dashboard-key.pem"]


def run(args, *, input=None, capture=False, check=True, timeout=900):
    # Binary stdin avoids Windows translating LF to CRLF (a trailing CR changes
    # passwords read by Linux shell scripts and corrupts credential hashes).
    result = subprocess.run(args, cwd=ROOT, input=input.encode("utf-8") if input is not None else None,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None, timeout=timeout)
    if capture:
        result.stdout = result.stdout.decode("utf-8", errors="replace")
        result.stderr = result.stderr.decode("utf-8", errors="replace")
    if check and result.returncode:
        # Command arguments never contain generated passwords. Do not print captured
        # container diagnostics here: callers may be reading sensitive configuration.
        raise RuntimeError(f"Command failed (exit {result.returncode}): {' '.join(args[:8])}. "
                           "Run the logs command for diagnostics.")
    return result


def compose(*args, **kwargs):
    return run(COMPOSE + list(args), **kwargs)


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def require_setup():
    if not (RUNTIME / "setup-complete.json").exists():
        raise RuntimeError("Setup is incomplete. Run: python scripts/lab.py setup")


def credentials():
    path = ROOT / ".env"
    if not path.exists():
        raise RuntimeError("No credentials yet. Run setup first.")
    return dict(line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines()
                if line and not line.startswith("#"))


def validate():
    manifest = json.loads((UPSTREAM / "manifest.json").read_text(encoding="utf-8"))
    for name, expected in manifest["sha256"].items():
        if hashlib.sha256((UPSTREAM / name).read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"Upstream integrity mismatch: {name}")
    rules = ET.fromstring((ROOT / "config/local_rules.xml").read_text(encoding="utf-8"))
    ids = [r.attrib["id"] for r in rules.findall("rule")]
    if len(ids) != len(set(ids)) or not EXPECTED.issubset(ids):
        raise RuntimeError("Custom rule IDs are missing or duplicated.")
    ET.parse(ROOT / "config/agent.conf")
    model = json.loads(compose("config", "--no-interpolate", "--format", "json", capture=True).stdout)
    if set(model["services"]) != {"wazuh.manager", "wazuh.indexer", "wazuh.dashboard", "lab.endpoint"}:
        raise RuntimeError("Unexpected service set.")
    for name, service in model["services"].items():
        if not service["image"].endswith(":" + VERSION):
            raise RuntimeError(f"Unpinned Wazuh service: {name}")
        for port in service.get("ports", []):
            if port.get("host_ip") != "127.0.0.1":
                raise RuntimeError(f"Unexpected external exposure: {name}")
    print("PASS: upstream SHA-256, XML structure, rule IDs, Compose model, version pins and loopback ports.")


def preflight():
    if not shutil.which("docker"):
        raise RuntimeError("Install Docker Desktop (Linux containers / WSL 2) first.")
    info_result = run(["docker", "info", "--format", "{{json .}}"], capture=True, check=False, timeout=45)
    if info_result.returncode:
        raise RuntimeError("Docker engine is unavailable. Start Docker Desktop in Linux container mode, then retry.")
    info = json.loads(info_result.stdout)
    if info["OSType"] != "linux":
        raise RuntimeError("Switch Docker Desktop to Linux containers.")
    if info["NCPU"] < 4 or info["MemTotal"] < 8_000_000_000:
        raise RuntimeError("Allocate at least 4 CPUs and 8 GB RAM to Docker; 10-12 GB is recommended for this lab.")
    if info.get("Architecture") not in ("x86_64", "amd64"):
        raise RuntimeError("This bundled endpoint image requires an x86-64/AMD64 Docker host.")
    if shutil.disk_usage(ROOT).free < 50 * 1024**3:
        print("WARNING: less than 50 GiB free on the project drive. Also check Docker's data disk.")
    print(f"Docker ready: {info['NCPU']} CPUs, {info['MemTotal'] / 1024**3:.1f} GiB RAM.")


def retry(args, attempts=3):
    for attempt in range(attempts):
        result = run(args, check=False)
        if result.returncode == 0:
            return
        if attempt + 1 < attempts:
            print(f"Download attempt {attempt + 1} failed; retrying in 5 seconds...", flush=True)
            time.sleep(5)
    raise RuntimeError("Download failed after retries. Check connectivity and rerun setup; existing layers are reused.")


def render_config(creds, hashes):
    source = UPSTREAM / "single-node/config"
    manager = (source / "wazuh_cluster/wazuh_manager.conf").read_text(encoding="utf-8")
    manager = manager.replace("<use_password>no</use_password>", "<use_password>yes</use_password>")
    manager = manager.replace("<vulnerability-detection>\n    <enabled>yes</enabled>",
                              "<vulnerability-detection>\n    <enabled>no</enabled>")
    write(RUNTIME / "manager.conf", manager)
    write(RUNTIME / "authd.pass", creds["ENROLLMENT_PASSWORD"] + "\n")
    if os.name != "nt":
        os.chmod(RUNTIME / "authd.pass", 0o600)
    write(RUNTIME / "indexer.yml", (source / "wazuh_indexer/wazuh.indexer.yml").read_text(encoding="utf-8"))
    write(RUNTIME / "dashboard.yml", (source / "wazuh_dashboard/opensearch_dashboards.yml").read_text(encoding="utf-8"))
    write(RUNTIME / "wazuh.yml", (source / "wazuh_dashboard/wazuh.yml").read_text(encoding="utf-8").replace(
        "MyS3cr37P450r.*-", creds["API_PASSWORD"]))
    write(RUNTIME / "internal_users.yml", f'''# Generated locally; no upstream demo users.
_meta:
  type: internalusers
  config_version: 2
admin:
  hash: "{hashes[0]}"
  reserved: true
  backend_roles: ["admin"]
  description: Home lab administrator
kibanaserver:
  hash: "{hashes[1]}"
  reserved: true
  description: Dashboard service
''')


def password_hashes(creds):
    hash_script = ('while IFS= read -r password; do '
                   '/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$password"; done')
    result = run(["docker", "run", "--rm", "-i", "-e", "JAVA_HOME=/usr/share/wazuh-indexer/jdk",
                  "--entrypoint", "bash", f"wazuh/wazuh-indexer:{VERSION}", "-c", hash_script],
                 input=creds["INDEXER_PASSWORD"] + "\n" + creds["DASHBOARD_PASSWORD"] + "\n", capture=True)
    hashes = re.findall(r"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}", result.stdout)
    if len(hashes) != 2:
        raise RuntimeError("The official indexer hash tool did not return two password hashes.")
    return hashes


def setup():
    validate()
    preflight()
    RUNTIME.mkdir(exist_ok=True)
    if not (ROOT / ".env").exists():
        names = ["INDEXER_PASSWORD", "DASHBOARD_PASSWORD", "API_PASSWORD", "ENROLLMENT_PASSWORD"]
        write(ROOT / ".env", "# Local credentials. Never publish this file.\n" +
              "".join(f"{name}=Aa1!{secrets.token_hex(18)}\n" for name in names))
        if os.name != "nt":
            os.chmod(ROOT / ".env", 0o600)
    creds = credentials()
    retry(COMPOSE + ["pull"])
    count = int(run(["docker", "run", "--rm", "--entrypoint", "cat",
                     f"wazuh/wazuh-indexer:{VERSION}", "/proc/sys/vm/max_map_count"], capture=True).stdout.strip())
    if count < 262144:
        raise RuntimeError("vm.max_map_count must be >=262144. See README prerequisite commands, then rerun setup.")
    # Preserve initialized security state. Re-running setup never rotates passwords.
    if not (RUNTIME / "setup-complete.json").exists():
        render_config(creds, password_hashes(creds))
    cert_dir = RUNTIME / "certs"
    cert_dir.mkdir(exist_ok=True)
    if not all((cert_dir / name).is_file() and (cert_dir / name).stat().st_size for name in CERTS):
        retry(["docker", "compose", "-f", str(ROOT / "generate-certs.yml"), "run", "--rm", "generator"])
    if not all((cert_dir / name).is_file() and (cert_dir / name).stat().st_size for name in CERTS):
        raise RuntimeError("Certificate generation returned incomplete output. See runtime/certs and the setup log.")
    compose("run", "--rm", "--no-deps", "--entrypoint", "bash", "lab.endpoint", "-c",
            "mkdir -p /lab/logs /lab/monitored; touch /lab/logs/events.json")
    write(RUNTIME / "setup-complete.json", json.dumps({"version": VERSION, "configured_at": utcnow()}, indent=2) + "\n")
    print("Setup complete. Run: python scripts/lab.py start")


def index_request(path, body=None):
    # Only fixed application paths are passed here; neither the password nor body
    # is interpolated into a shell command. Verify TLS with the generated CA.
    if not re.fullmatch(r"[A-Za-z0-9_./*?=&-]+", path):
        raise ValueError("Invalid indexer API path")
    script = ('curl -fsS --max-time 20 --cacert config/certs/root-ca.pem '
              '-u "admin:$LAB_ADMIN_PASSWORD" -H "Content-Type: application/json" ')
    if body is not None:
        script += "--data-binary @- "
    script += "https://wazuh.indexer:9200/" + path
    result = compose("exec", "-T", "wazuh.indexer", "bash", "-c", script,
                     input=json.dumps(body) if body is not None else None, capture=True, timeout=35)
    return json.loads(result.stdout)


def connected():
    result = compose("exec", "-T", "wazuh.manager", "/var/ossec/bin/agent_control", "-lc", capture=True)
    return any("Name: lab-linux," in line and "Active" in line for line in result.stdout.splitlines())


def start():
    require_setup()
    preflight()
    compose("up", "-d", "--wait", "--wait-timeout", "600", timeout=700)
    if not connected():
        raise RuntimeError("Containers started but lab-linux is not active. Run status and logs.")
    cluster = index_request("_cluster/health")
    if cluster["status"] == "red":
        raise RuntimeError("Indexer cluster is red. Run logs and investigate before testing.")
    # The manager API has its own self-signed certificate. This check is confined
    # to localhost inside the manager, and the returned token is never displayed.
    compose("exec", "-T", "wazuh.manager", "bash", "-c",
            'curl -fkSs --max-time 20 -u "$API_USERNAME:$API_PASSWORD" -X POST '
            '"https://localhost:55000/security/user/authenticate?raw=true" >/dev/null', capture=True)
    print("Ready: https://localhost:8443 | username: admin")
    print("Show your local password: python scripts/lab.py credentials")
    print("Run all scenarios: python scripts/lab.py test")


def make_events(run_id):
    base = {"integration": "homelab", "lab_run_id": run_id, "synthetic": True,
            "lab_source_ip": "192.0.2.10", "lab_user": "student", "event_time": utcnow(),
            "correlation_key": run_id + ":192.0.2.10"}
    events = [dict(base, event_type="auth_failure", sequence=i) for i in range(1, 9)]
    events += [dict(base, event_type="auth_success", lab_user="root"),
               dict(base, event_type="process_start", lab_command="powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcATABBAEIAJwA="),
               dict(base, event_type="web_request", lab_url="/download?file=../../etc/passwd")]
    events += [dict(base, event_type="auth_success", lab_case="benign", lab_user="student"),
               dict(base, event_type="process_start", lab_case="benign", lab_command="powershell.exe Get-Date"),
               dict(base, event_type="web_request", lab_case="benign", lab_url="/index.html")]
    return events


def rule_test():
    require_setup()
    events = make_events("rule-test-" + uuid.uuid4().hex[:12])
    cases = [(events[0], "100101:5:json"), (events[8], "100103:7:json"),
             (events[9], "100104:10:json"), (events[10], "100105:8:json")]
    for event, expected in cases:
        compose("exec", "-T", "wazuh.manager", "/var/ossec/bin/wazuh-logtest", "-q", "-U", expected,
                input=json.dumps(event) + "\n", capture=True)
        print(f"PASS: rule {expected}")
    for event in events[11:]:
        compose("exec", "-T", "wazuh.manager", "/var/ossec/bin/wazuh-logtest", "-q", "-U", "100100:0:json",
                input=json.dumps(event) + "\n", capture=True)
    print("PASS: all three benign controls match only the level-zero parent rule.")
    # Stateful correlation needs one continuous logtest session.
    result = compose("exec", "-T", "wazuh.manager", "/var/ossec/bin/wazuh-logtest",
                     input="\n".join(json.dumps(e) for e in events[:8]) + "\n", capture=True)
    if not re.search(r"id:\s*'100102'", result.stdout + result.stderr):
        raise RuntimeError("Correlation rule 100102 did not fire in wazuh-logtest.")
    print("PASS: repeated-login correlation in a single Wazuh rule engine session.")


def search_alerts(run_id):
    body = {"size": 200, "sort": [{"timestamp": "asc"}], "query": {"bool": {
        "minimum_should_match": 1, "should": [
            {"term": {"data.lab_run_id": run_id}},
            {"term": {"syscheck.path": f"/lab/monitored/{run_id}.txt"}}
        ], "filter": [{"term": {"agent.name": "lab-linux"}}]
    }}}
    try:
        return [hit["_source"] for hit in index_request("wazuh-alerts-*/_search", body)["hits"]["hits"]]
    except (RuntimeError, KeyError, json.JSONDecodeError):
        return []


def rule_ids(alerts):
    return {str(alert.get("rule", {}).get("id")) for alert in alerts}


def await_alerts(run_id, required, timeout=180):
    deadline = time.monotonic() + timeout
    last_notice = 0
    alerts = []
    while time.monotonic() < deadline:
        alerts = search_alerts(run_id)
        if required <= rule_ids(alerts):
            return alerts
        if time.monotonic() - last_notice > 30:
            print("Waiting for indexed rules: " + ", ".join(sorted(required - rule_ids(alerts))), flush=True)
            last_notice = time.monotonic()
        time.sleep(5)
    return alerts


def save_report(run_id, events, alerts, checks, started, error=None):
    folder = ROOT / "evidence/runs" / run_id
    folder.mkdir(parents=True, exist_ok=True)
    report = {"run_id": run_id, "version": VERSION, "started_at": started, "finished_at": utcnow(),
              "passed": all(checks.values()) and error is None, "checks": checks, "error": error,
              "observed_rule_ids": sorted(rule_ids(alerts)), "alert_count": len(alerts),
              "synthetic_events": len(events), "endpoint": "lab-linux"}
    write(folder / "result.json", json.dumps(report, indent=2) + "\n")
    write(folder / "events.jsonl", "".join(json.dumps(e) + "\n" for e in events))
    write(folder / "alerts.json", json.dumps(alerts, indent=2) + "\n")
    rows = "\n".join(f"| {name} | {'PASS' if passed else 'FAIL'} |" for name, passed in checks.items())
    write(folder / "REPORT.md", f"""# Wazuh lab test: {'PASS' if report['passed'] else 'FAIL'}

Run: `{run_id}`

Started (UTC): {started}

Finished (UTC): {report['finished_at']}

Version: {VERSION}; endpoint: lab-linux; indexed alerts: {len(alerts)}

| Check | Result |
| --- | --- |
{rows}

Observed rule IDs: {', '.join(sorted(rule_ids(alerts)))}.

Authentication, PowerShell and web events are synthetic JSON fixtures. No attack,
login attempt or PowerShell command was executed. FIM create/modify/delete operations
are real changes to one disposable file inside the lab endpoint volume.
Passing verifies agent collection, manager rules and indexer storage for these cases.
It does not establish detection accuracy on production data or on a Windows endpoint.

Error: {error or 'None'}

Evidence: `events.jsonl`, `alerts.json`, `result.json`. Capture the dashboard separately.
""")
    print(f"Evidence written to {folder}")
    return report["passed"]


def test():
    require_setup()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    started = utcnow()
    events = make_events(run_id)
    alerts, checks, error = [], {"endpoint connected": False}, None
    try:
        checks["endpoint connected"] = connected()
        if not checks["endpoint connected"]:
            raise RuntimeError("lab-linux is not active. Run start and status first.")
        rule_test()
        checks["Wazuh rule engine tests"] = True
        compose("exec", "-T", "lab.endpoint", "bash", "-c", "cat >> /lab/logs/events.json",
                input="".join(json.dumps(e) + "\n" for e in events))
        print(f"Injected {len(events)} synthetic events; run ID: {run_id}", flush=True)
        alerts = await_alerts(run_id, EXPECTED)
        for rid in sorted(EXPECTED):
            checks[f"synthetic rule {rid} indexed"] = rid in rule_ids(alerts)
        # Unique file per run prevents old alerts from satisfying new assertions.
        path = f"/lab/monitored/{run_id}.txt"
        required = EXPECTED.copy()
        for action, rid in [("create", "554"), ("modify", "550"), ("delete", "553")]:
            if action == "delete":
                compose("exec", "-T", "lab.endpoint", "rm", "--", path)
            else:
                compose("exec", "-T", "lab.endpoint", "bash", "-c", 'cat > "$1"', "lab-write", path,
                        input=f"Home lab {action}: {run_id}\n")
            required.add(rid)
            alerts = await_alerts(run_id, required)
            checks[f"real FIM {action} rule {rid} indexed"] = rid in rule_ids(alerts)
        # Give low-priority benign input time to traverse the same pipeline.
        time.sleep(15)
        alerts = search_alerts(run_id)
        checks["all expected alerts present in final evidence"] = (EXPECTED | {"550", "553", "554"}) <= rule_ids(alerts)
        checks["benign controls produced no indexed alert"] = not any(
            a.get("data", {}).get("lab_case") == "benign" for a in alerts)
        checks["indexer cluster not red"] = index_request("_cluster/health")["status"] != "red"
    except Exception as exc:
        # Preserve a failure report even for an unexpected runner error.
        error = str(exc)
    passed = save_report(run_id, events, alerts, checks, started, error)
    print("PASS: all scenarios verified." if passed else "FAIL: inspect the evidence report and run logs.")
    print(f'Dashboard filter: data.lab_run_id: "{run_id}"')
    if not passed:
        raise RuntimeError("One or more lab checks failed; see the generated report.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["setup", "start", "stop", "status", "test", "rule-test",
                                           "credentials", "logs", "validate"])
    args = parser.parse_args()
    if args.action == "validate":
        validate()
    elif args.action == "setup":
        setup()
    elif args.action == "start":
        start()
    elif args.action == "test":
        test()
    elif args.action == "rule-test":
        rule_test()
    elif args.action == "credentials":
        print("URL: https://localhost:8443\nUsername: admin\nPassword: " + credentials()["INDEXER_PASSWORD"])
    else:
        require_setup()
        if args.action == "stop":
            compose("down")
            print("Stopped. Docker volumes and local credentials are retained.")
        elif args.action == "status":
            compose("ps", "-a")
            print(json.dumps(index_request("_cluster/health"), indent=2))
            compose("exec", "-T", "wazuh.manager", "/var/ossec/bin/agent_control", "-lc")
        elif args.action == "logs":
            compose("logs", "--tail", "100")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Interrupted. Existing containers and data are retained.", file=sys.stderr)
        sys.exit(130)
