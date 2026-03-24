# Changelog

All notable changes to **@mcp-firewall/enforce** are documented here.

This project follows [Semantic Versioning](https://semver.org/) and
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions.

---

## [1.0.0] — 2026-03-24

### Added

- **Active stdio proxy** — wraps any MCP server and enforces policies on traffic
- **7 configurable enforcement rules:**
  - `pii` — PII field redaction (25 built-in patterns + custom fields)
  - `payload` — Response size enforcement (truncate/block/warn)
  - `rows` — Array truncation to configurable max items
  - `fields` — Allowlist/blocklist field filtering (Egress Firewall)
  - `tools` — Tool access control (allowlist/blocklist)
  - `rateLimit` — Per-tool sliding window rate limiter
  - `secrets` — API key and token detection via regex patterns

- **Policy file** (`firewall.yaml`) — YAML-based, deep-merged with sensible defaults
- **`--init` command** — generates a default `firewall.yaml`
- **Audit logger** — structured JSONL file for compliance (SOC 2 / HIPAA / GDPR)
- **Terminal reporter** — color-coded per-call enforcement reports + session summary
- **CLI** with `--policy`, `--quiet`, and `--json` modes
- **Programmatic API** — all rules, engine, and policy loader exported

- **61 tests** — full coverage across all 7 rules, engine, session, and reporter

- Full TypeScript, ESM-native, Node.js ≥ 18

---

*Older versions will be listed here as they are released.*
