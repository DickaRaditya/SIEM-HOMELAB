"""Fetch the exact upstream configuration used by this lab (maintainer utility)."""
import hashlib
import json
from pathlib import Path
import urllib.request
import time

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "5f5951b795578cb0844f4601b66df890860c20f3"
FILES = [
    "LICENSE",
    "single-node/docker-compose.yml",
    "single-node/generate-indexer-certs.yml",
    "single-node/config/certs.yml",
    "single-node/config/wazuh_cluster/wazuh_manager.conf",
    "single-node/config/wazuh_indexer/wazuh.indexer.yml",
    "single-node/config/wazuh_indexer/internal_users.yml",
    "single-node/config/wazuh_dashboard/opensearch_dashboards.yml",
    "single-node/config/wazuh_dashboard/wazuh.yml",
    "wazuh-agent/config/wazuh-agent-conf",
]

if __name__ == "__main__":
    manifest = {"release": "4.14.8", "commit": COMMIT, "sha256": {}}
    for name in FILES:
        url = f"https://raw.githubusercontent.com/wazuh/wazuh-docker/{COMMIT}/{name}"
        for attempt in range(5):
            try:
                with urllib.request.urlopen(url, timeout=30) as response:
                    data = response.read()
                break
            except OSError:
                if attempt == 4:
                    raise
                time.sleep(2)
        target = ROOT / "vendor" / "wazuh" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        manifest["sha256"][name] = hashlib.sha256(data).hexdigest()
        print(f"Fetched {name}")
    (ROOT / "vendor" / "wazuh" / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
