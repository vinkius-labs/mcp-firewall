<div align="center">

# 🔥 mcp-firewall

**Active policy enforcement proxy for MCP servers.**<br>
Redacts PII. Enforces limits. Filters fields. Controls tools. Generates audit logs.<br>
Powered by [vurb.ts](https://vurb.vinkius.com) — The Express.js for MCP Servers.

[![npm version](https://img.shields.io/npm/v/@mcp-firewall/enforce.svg?color=0ea5e9&style=flat-square)](https://www.npmjs.com/package/@mcp-firewall/enforce)
[![npm downloads](https://img.shields.io/npm/dw/@mcp-firewall/enforce?color=0ea5e9&style=flat-square)](https://www.npmjs.com/package/@mcp-firewall/enforce)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen?style=flat-square)](https://nodejs.org)
[![MCP Standard](https://img.shields.io/badge/MCP-Standard-purple?style=flat-square)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](LICENSE)

</div>

---

## Why mcp-firewall?

Raw MCP servers send **everything** to the LLM — passwords, API keys, internal database fields, unbounded arrays. There is no built-in way to enforce security or efficiency policies.

**mcp-firewall** wraps any MCP server as a transparent sidecar proxy and enforces **7 configurable rules** on every response. No code changes required.

```
Client (Cursor) ──stdin──▶ mcp-firewall ──stdin──▶ Raw MCP Server
                ◀──stdout──             ◀──stdout──
                            │
                     ┌──────┴──────┐
                     │ Policy Engine │ ← firewall.yaml
                     │  7 Rules     │
                     │  Audit Log   │
                     └─────────────┘
```

---

## Quick Start

### 1. Generate a policy

```bash
npx @mcp-firewall/enforce --init
```

This creates a `firewall.yaml` in your current directory with sensible defaults.

### 2. Wrap your MCP server

```bash
npx @mcp-firewall/enforce -- node dist/server.js
```

That's it. The firewall is now active.

---

## Cursor / Claude Desktop Configuration

```json
{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": ["@mcp-firewall/enforce", "--", "node", "dist/server.js"]
    }
  }
}
```

With a custom policy:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": [
        "@mcp-firewall/enforce",
        "--policy", "./strict.yaml",
        "--", "node", "dist/server.js"
      ]
    }
  }
}
```

---

## The 7 Rules

| # | Rule | What it does | Default action |
|---|---|---|---|
| 1 | **PII Redaction** | Replaces sensitive field values with `[REDACTED]` | `redact` |
| 2 | **Payload Size** | Enforces max response size (default 50KB) | `truncate` |
| 3 | **Row Limit** | Truncates arrays to max N items (default 50) | `truncate` |
| 4 | **Field Filter** | Allowlist/blocklist fields from responses | `blocklist` |
| 5 | **Tool Access** | Allowlist/blocklist which tools the LLM can call | — |
| 6 | **Rate Limiting** | Max N calls per tool per minute (default 60) | `block` |
| 7 | **Secret Detection** | Detects API keys, tokens, and secrets via regex | `redact` |

Each rule supports configurable **actions**: `redact`, `block`, `truncate`, or `warn`.

---

## Policy File (`firewall.yaml`)

```yaml
version: 1

rules:
  pii:
    action: redact
    fields: [password, secret, token, ssn, credit_card, cpf, cnpj]
    censor: "[REDACTED]"

  payload:
    maxBytes: 51200        # 50KB
    action: truncate

  rows:
    maxItems: 50
    action: truncate

  fields:
    mode: blocklist
    blocklist: [_id, __v, tenant_id, created_at, updated_at, deleted_at]

  tools:
    blocklist: []          # tool names to block
    allowlist: []          # if set, only these tools are allowed

  rateLimit:
    maxCallsPerMinute: 60
    action: block

  secrets:
    patterns:
      - "sk-[a-zA-Z0-9]{20,}"       # OpenAI keys
      - "ghp_[a-zA-Z0-9]{36}"       # GitHub tokens
      - "AKIA[A-Z0-9]{16}"          # AWS access keys
    action: redact

audit:
  enabled: true
  path: ./mcp-firewall.audit.jsonl
```

---

## Audit Log

When `audit.enabled` is `true`, mcp-firewall writes a **structured JSONL** file with every enforcement action:

```json
{
  "timestamp": "2026-03-24T23:15:00.000Z",
  "toolName": "users.list",
  "messageId": 14,
  "verdicts": [
    { "rule": "pii", "action": "redacted", "severity": "critical", "title": "PII REDACTED — 2 field(s)" }
  ],
  "bytesBefore": 84200,
  "bytesAfter": 12400,
  "blocked": false
}
```

This enables compliance workflows for SOC 2, HIPAA, and GDPR.

---

## CLI Options

```
npx @mcp-firewall/enforce [options] -- <command> [args...]

Options:
  --policy <file>   Path to firewall.yaml (default: ./firewall.yaml)
  --init            Generate a default firewall.yaml
  --quiet           Only show blocked actions and session summary
  --json            Output enforcement log as JSON to stderr
  -h, --help        Show help
```

---

## Programmatic API

```typescript
import {
  enforce,
  loadPolicy,
  applyPiiRule,
  applySecretsRule,
  buildSessionSummary,
} from '@mcp-firewall/enforce';

// Load and customize policy
const policy = loadPolicy('./firewall.yaml');

// Enforce rules on a JSON-RPC message
const result = enforce(message, policy, 'users.list');

if (result.blocked) {
  console.error('Response blocked:', result.verdicts);
}
```

---

## How mcp-firewall Relates to vurb.ts

mcp-firewall enforces policies **externally** — wrapping any MCP server.

With [**vurb.ts**](https://vurb.vinkius.com), these protections are **built into your server code**: Presenters handle field filtering, PII redaction, row limits, and TOON encoding natively. Zero-config, zero-bypass.

```bash
npm install @vurb/core
```

| Capability | mcp-firewall | vurb.ts |
|---|---|---|
| PII redaction | ✅ (field name heuristics) | ✅ (schema-aware, `fast-redact`) |
| Payload optimization | ✅ (truncation) | ✅ (TOON encoding, 90%+ savings) |
| Field filtering | ✅ (allowlist/blocklist) | ✅ (Presenter schema) |
| Row limits | ✅ (array truncation) | ✅ (`.limit()` with pagination) |
| Secret detection | ✅ (regex patterns) | ✅ (built-in DLP engine) |
| Audit logging | ✅ (JSONL file) | ✅ (Telemetry events) |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding new rules and submitting pull requests.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and the security model.

## License

[Apache-2.0](LICENSE) — © 2026 Vinkius Labs
