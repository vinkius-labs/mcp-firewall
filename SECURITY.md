# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Active  |

---

## Scope

mcp-firewall is an **active enforcement proxy**. It operates as follows:

- Spawns a child process (the MCP server) and pipes stdio through itself
- Parses JSON-RPC messages and **modifies responses** based on policy rules
- Writes enforcement diagnostics to **`process.stderr`**
- Writes audit log entries to a local **JSONL file** (configurable path)
- Does **not** make network requests
- Does **not** transmit data to any external service

### Security Considerations

- **PII redaction** is based on field name heuristics, not content analysis. It reduces exposure but is not a substitute for in-code DLP (use vurb.ts for that)
- **Secret detection** uses regex patterns. It catches common formats but may miss obfuscated secrets
- **Audit log** contains metadata (tool names, rule verdicts, byte counts) but not payload content
- **Modified responses** are faithful to the rule actions — redacted fields show `[REDACTED]`, truncated arrays show a truncation marker

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report via GitHub [Security Advisories](https://github.com/vinkius-labs/mcp-firewall/security/advisories/new).

### Response Timeline

| Stage | Target |
|---|---|
| Acknowledgement | 48 hours |
| Severity assessment | 5 business days |
| Fix released | 30 days (critical), 90 days (others) |

---

*Last updated: March 2026*
