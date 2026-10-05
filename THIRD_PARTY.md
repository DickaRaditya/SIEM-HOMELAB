# Attribution and provenance

This project incorporates and adapts Wazuh Docker configuration from Wazuh Inc.

- Repository: https://github.com/wazuh/wazuh-docker
- Release tag: `v4.14.8`
- Resolved commit: `5f5951b795578cb0844f4601b66df890860c20f3`
- Unmodified selected source files: `vendor/wazuh/`
- Per-file SHA-256: `vendor/wazuh/manifest.json`
- Upstream license: `vendor/wazuh/LICENSE` (GNU GPL v2)

`compose.yml`, `generate-certs.yml`, and the generated runtime configuration are
adapted from these files. Changes include loopback-only dashboard publishing,
generated credentials, a bundled endpoint, health checks, enrollment password,
custom rules, and disabling the manager's vulnerability feed for the baseline.

The certificate generator image is pinned to `wazuh/wazuh-certs-generator:0.0.4`
with `CERT_TOOL_VERSION=4.14`, following upstream. That utility downloads its
certificate-generation script during setup; setup is not an offline build.

All four Wazuh images are pinned to version `4.14.8`, not immutable OCI digests.
Version pins reduce accidental drift but do not promise bit-for-bit builds.
Record image digests (`docker image inspect`) if your portfolio needs that level
of provenance. Images and their bundled third-party software retain their own
licenses. The source project is distributed under GPL-2.0; see `LICENSE`.

`scripts/fetch_upstream.py` is a maintainer utility to retrieve this same commit.
Normal setup verifies bundled file checksums and does not need GitHub access.
