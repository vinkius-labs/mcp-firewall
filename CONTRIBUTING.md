# Contributing to mcp-firewall

Thank you for your interest in contributing. This document covers everything
you need to know to get started.

---

## Code of Conduct

Be respectful and constructive. Harassment, discrimination, or personal
attacks of any kind will not be tolerated. We follow the spirit of the
[Contributor Covenant](https://www.contributor-covenant.org/).

---

## How to Contribute

### Reporting a bug

Open an issue with: Node.js/npm versions, the command used, stderr output,
and what you expected.

### Proposing a new rule

Open an issue with:
1. What the rule would enforce
2. The false-positive risk
3. The recommended vurb.ts fix (code snippet)

### Fixing a bug or adding a feature

1. Fork the repository
2. Create a branch: `git checkout -b feat/new-rule`
3. Make changes, add tests
4. Ensure `npm test` passes
5. Open a pull request

---

## Development Setup

```bash
git clone https://github.com/vinkius-labs/mcp-firewall.git
cd mcp-firewall
npm install
npm run build
npm test
```

---

## Project Structure

```
mcp-firewall/
├── src/
│   ├── index.ts         ← CLI entry point + public API
│   ├── proxy.ts         ← Active stdio proxy engine
│   ├── engine.ts        ← Policy engine orchestrator (7 rules)
│   ├── policy.ts        ← YAML policy loader with defaults
│   ├── audit.ts         ← JSONL audit logger
│   ├── reporter.ts      ← Terminal output formatting
│   ├── types.ts         ← Shared TypeScript types
│   └── rules/
│       ├── pii.ts       ← PII field redaction
│       ├── payload.ts   ← Payload size enforcement
│       ├── rows.ts      ← Row limit / array truncation
│       ├── fields.ts    ← Field allowlist/blocklist
│       ├── tools.ts     ← Tool access control
│       ├── rate-limit.ts← Per-tool rate limiting
│       └── secrets.ts   ← Secret/API key detection
├── tests/
│   └── mcp-firewall.test.ts
└── dist/
```

---

## Adding a New Rule

1. Create `src/rules/your-rule.ts` with a function that returns `RuleVerdict | null`
2. Add the rule name to `RuleName` in `types.ts`
3. Wire it into `engine.ts` → `enforce()`
4. Add at least 3 test cases per rule
5. Update `CHANGELOG.md` under `[Unreleased]`

---

## Commit Conventions

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add response latency rule
fix: improve PII pattern matching edge case
test: add edge case for empty array responses
```

---

## Pull Request Process

1. Target `main`
2. One concern per PR
3. All tests must pass, coverage must not decrease
4. Update `CHANGELOG.md`
5. A maintainer will review within a few days
