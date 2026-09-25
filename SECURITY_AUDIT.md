# Security Audit — fork of Anthropic-Cybersecurity-Skills

**Date:** 2026-09-24
**Fork:** `triggs2025/Anthropic-Cybersecurity-Skills`
**Forked from:** `rogerthenomad/Anthropic-Cybersecurity-Skills` (itself a fork of `mukul975/Anthropic-Cybersecurity-Skills`)
**Tree audited:** upstream `main` @ `54a79883` — 818 skills, 1,096 Python scripts, 2 PowerShell scripts, 4 GitHub Actions workflows, 1 Claude plugin manifest

## Summary

**No malicious content found.** Nothing in the repository sends data to unexpected hosts, no real credentials are present, no skill text contains hidden instructions aimed at AI agents, the plugin manifest declares no hooks, and the workflows use only the repo-scoped `GITHUB_TOKEN`. The findings below are hardening issues typical of a large community-contributed codebase. Six were fixed in this fork (commit `33bd56c0` plus the follow-up bandit fixes); the rest are documented.

A note on forking: creating a fork gives the original owners no access to your account or machine. Risk arises only from *running* content — scripts, workflows, and (for a skills library) the instructions an agent follows. All of those were reviewed.

## Method

Static review only; no skill scripts were executed. The repo's own validators were run locally (`tools/validate-skill.py --all`: 818/818 pass; `lint-descriptions.py`: 0 new failures; `detect-collisions.py`: clean) along with `bandit` over all 1,103 Python files (results below).

| Area | Checked | Result |
|---|---|---|
| Scripts | risky calls (`shell=True`, `os.system`, `eval`/`exec`, `pickle`, `yaml.load`, `ctypes`, `__import__`), TLS verification, temp files, hardcoded credentials, every external hostname | 3 issues fixed; remainder by design (see below) |
| Secrets | common token formats, private-key blocks, JWTs, `password=` / `api_key=` literals | Only official documentation placeholders and lab-tool defaults |
| Network egress | every `http(s)://` host in all scripts | Well-known security APIs, cloud metadata endpoints used by SSRF-testing skills, and obvious placeholders (`example.com`, `evil.com`, `*.oast.fun`). Paste/tunnel/webhook domains appear only inside detection blocklists |
| Skill text | instruction-override phrasing, HTML comments, encoded blobs | Hits occur only inside skills *about* detecting prompt injection, or in tabletop narrative; HTML comments are code-sample labels |
| Workflows | triggers, permissions, secrets, third-party actions, shell pipes | `GITHUB_TOKEN` only, `contents: write`, no `pull_request_target`, no external downloads |
| Plugin manifest | `.claude-plugin/*.json` | Metadata only — no hooks, commands, or agents |

## Fixed in this fork

1. **Unsafe deserialization (CWE-502)** — `skills/detecting-command-and-control-over-dns/scripts/agent.py` unpickled a user-supplied `--dga-model` file. Loading now requires an explicit `--trust-dga-model` flag.
2. **Predictable temp files (CWE-377)** — `skills/exploiting-vulnerabilities-with-metasploit-framework/scripts/agent.py` and `skills/implementing-aqua-security-for-container-scanning/scripts/process.py` wrote fixed names under `/tmp`. Both now use `tempfile.mkstemp` / `mkdtemp`.
3. **CI supply chain** — `actions/checkout@v4` pinned to a commit SHA in all four workflows; automated commits use the `github-actions[bot]` identity instead of the upstream maintainer's personal name and email.
4. **Literal bidirectional-control characters in source (bandit B613)** — `skills/auditing-mcp-servers-for-tool-poisoning/scripts/agent.py` embedded raw U+200B–U+206F characters inside its own detector regex. Replaced with `\uXXXX` escapes; behavior unchanged, and the file no longer trips trojan-source scanners or AV.
5. **Tar extraction without path filtering (B202 / CWE-22)** — `skills/detecting-malicious-npm-packages/scripts/agent.py` extracts suspected-malicious npm tarballs; its prefix check missed `a/../../x` paths and symlink members. Now uses `extractall(..., filter="data")`.
6. **Flask demo server with the debugger on, bound to all interfaces (B201)** — `skills/implementing-scim-provisioning-with-okta/scripts/process.py`. The Werkzeug debugger allows remote code execution if reachable. Now binds to `127.0.0.1` with `debug=False`.

## Static analysis (bandit) summary

1,985 raw findings across 1,103 files; nearly all are expected for security tooling and were triaged rather than changed:

| Rule | Count | Assessment |
|---|---|---|
| B603/B404/B607 subprocess use | ~1,400 | Argument-list calls to security tools; by design |
| B501 TLS verification disabled | 105 | Offensive-testing helpers; see L1 below |
| B108 hardcoded `/tmp` paths | 67 | Mostly string constants in detection lists; the three that created files were fixed (item 2) |
| B324 MD5/SHA1 | 43 | Malware-sample hashing for lookups, not security — correct usage |
| B314/B310/B405 XML & URL parsing | ~110 | Local / lab data |
| B105/B106/B107 hardcoded passwords | 59 | Lab-tool defaults and placeholders; see L3 |
| B602 `shell=True` | 4 | Hardcoded pipelines in the CIS-benchmark and privilege-escalation *assessment* scripts, plus the Atomic Red Team runner (L2). No user input reaches the shell |
| B507 Paramiko `AutoAddPolicy` | 3 | SSH host keys auto-trusted in three scanning helpers; use a `known_hosts` file in production |
| B615 unpinned Hugging Face download | 2 | `defending-llms-with-guardrails` loads a classifier by name only; pin `revision=` for supply-chain safety |
| B701 Jinja2 autoescape off | 1 | Renders Markdown/text reports, not HTML; not exploitable as used |
| B613 / B202 / B201 | 3 | Fixed (items 4–6) |

## Documented, not changed

- **TLS verification disabled** (`verify=False`) in ~35 offensive-testing helper scripts. Intentional for self-signed targets, but it should be an opt-in `--insecure` flag rather than the default. A cross-cutting change best made upstream.
- **`shell=True`** in `skills/performing-threat-emulation-with-atomic-red-team/scripts/agent.py`. Documented in-line as required; safe only when the test definitions come from a pinned, trusted checkout.
- **Lab default credentials** in a handful of scripts (Neo4j, Kismet, Harbor shipped defaults; a `replace-with-secure-token` placeholder). Should be read from environment variables.
- **Vendor `curl … | sh` install one-liners** in a few skill docs. Standard vendor guidance, but pin versions or verify checksums where possible.
- **Windows Defender false positive** — `skills/detecting-fileless-malware-techniques/SKILL.md` (a detection guide) is quarantined by Defender on checkout. The file is intact in git; add a folder exclusion if you need it locally.

## Recommendations for keeping the fork healthy

- Keep syncing from `mukul975/Anthropic-Cybersecurity-Skills`; that is where fixes land.
- Treat every helper script as a starting point to read before running, not a turnkey tool.
- Re-run this review after each upstream sync: `grep -rnE 'shell=True|pickle\.load|yaml\.load\(|verify=False' skills tools` plus a secrets scan.
