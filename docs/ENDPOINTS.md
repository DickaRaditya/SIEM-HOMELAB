# Optional: monitor Windows or another home LAN endpoint

The included `lab-linux` agent monitors a container. It has no access to your
Windows event logs, applications or home-router traffic. Add agents to machines
you own/administer if you want actual host telemetry. This expansion is manual
and is not part of the automated baseline test.

## Windows on this same PC

Create a new file named `compose.endpoint.yml` in the project root:

```yaml
services:
  wazuh.manager:
    ports:
      - "127.0.0.1:1514:1514"
      - "127.0.0.1:1515:1515"
```

Apply the additional port bindings explicitly:

```powershell
docker compose -f compose.yml -f compose.endpoint.yml up -d
```

Use Wazuh's dashboard **Deploy new agent** workflow and the
[official Windows installation guide](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html).
Choose a Windows agent version compatible with the 4.14.8 manager (never newer
than the manager), set manager/registration address to `127.0.0.1`, and use a
unique name such as `lab-windows`.

This manager requires an enrollment password. Supply the `ENROLLMENT_PASSWORD`
value from local `.env` using the official `WAZUH_REGISTRATION_PASSWORD`
installation variable or the [password enrollment procedure](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/using-password-authentication.html).
Run the installer with Administrator privileges. Do not paste secrets into a
published README, shared terminal transcript or screenshot.

Verify the new agent is **Active** before testing. Check its local `ossec.conf`
for Windows Security/System/Application event-channel collection. Security-log
events depend on Windows audit policy. Sysmon requires a separate install and
configuration; this project does not silently install it or change audit policies.

After installing/enabling a channel, generate a harmless matching Windows event
and verify its agent name, channel and event ID in Wazuh. Document precisely what
you enabled. The JSON PowerShell fixture in the baseline remains synthetic even
when a real Windows agent is connected.

The CLI uses only `compose.yml`. Once you add an override, use both files for
subsequent `up` operations so the port bindings remain in place. Baseline tests
still target `lab-linux` only. To return to the baseline:

```powershell
docker compose -f compose.yml -f compose.endpoint.yml down
python scripts/lab.py start
```

## Another machine on your private LAN

In the override, replace `127.0.0.1` with this Docker host's private LAN IP for
1514 and 1515. Use that IP as the agent's manager/registration address. Allow
those TCP ports in Windows Firewall **only from the intended endpoint addresses**.
Do not forward them through your router. Keep dashboard, indexer and manager API
bound as in the baseline. Enrollment over a real network should also validate
the manager's identity with trusted certificates; see
[Wazuh enrollment security](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/index.html).

Document IP addressing, agent installation and firewall changes as a separate
portfolio milestone. Native endpoint tests need their own expected rules and
evidence; the baseline runner is not a validator for arbitrary LAN endpoints.
