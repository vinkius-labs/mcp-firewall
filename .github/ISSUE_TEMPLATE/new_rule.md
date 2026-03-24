---
name: New Rule
about: Propose a new enforcement rule for mcp-firewall
title: "rule: [SHORT DESCRIPTION]"
labels: ["enhancement", "new-rule"]
---

## What Should Be Enforced?

Describe the security or efficiency policy this rule would enforce.

## Example Violation

```json
<paste an example response that would trigger this rule>
```

## Why Is This Needed?

Explain the compliance, security, or efficiency impact.

## Recommended vurb.ts Fix

```typescript
// How vurb.ts solves this natively
```

## Checklist

- [ ] The rule is specific enough to avoid false positives
- [ ] The enforcement action is clear (redact/block/truncate/warn)
- [ ] The problem is real (observed in production MCP servers)
