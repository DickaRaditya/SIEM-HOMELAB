# Attribution and provenance

This project incorporates and adapts Wazuh Docker configuration from Wazuh Inc.

- Repository: https://github.com/wazuh/wazuh-docker
- Release tag: `v4.14.8`
- Resolved commit: `5f5951b795578cb0844f4601b66df890860c20f3`
- Unmodified selected source files: `vendor/wazuh/`
- Per-file SHA-256: `vendor/wazuh/manifest.json`
- Upstream license: `vendor/wazuh/LICENSE` (GNU GPL v2)

`compose.yml` and `generate-certs.yml` are adapted from the corresponding files
in that upstream commit. Runtime configuration uses the retained upstream
templates. Changes include loopback-only dashboard publishing,
generated credentials, a bundled endpoint, health checks, enrollment password,
custom rules, and disabling the manager's vulnerability feed for the baseline.

The certificate generator image is pinned to `wazuh/wazuh-certs-generator:0.0.4`
with `CERT_TOOL_VERSION=4.14`, following upstream. That utility downloads its
certificate-generation script during setup; setup is not an offline build.

All four Wazuh images are pinned to version `4.14.8`, not immutable OCI digests.
Version pins reduce accidental drift but do not promise bit-for-bit builds.
Record image digests (`docker image inspect`) when a deployment requires that level
of provenance. Images and their bundled third-party software retain their own
licenses. The source project is distributed under GPL-2.0; see `LICENSE`.

Only configuration consumed by setup/certificate generation, its checksum manifest
and the upstream license are bundled. Unused example deployments, the example
agent configuration and the demo user database are omitted. Setup generates its
own user database and verifies retained upstream files without GitHub access.
