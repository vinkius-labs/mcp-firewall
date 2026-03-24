/**
 * mcp-firewall — Policy loader.
 *
 * Reads a firewall.yaml from disk and returns a fully-populated
 * FirewallPolicy with defaults for any missing fields.
 *
 * @module
 */
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { FirewallPolicy } from './types.js';

/** Default policy applied when no firewall.yaml is found. */
export const DEFAULT_POLICY: FirewallPolicy = {
    version: 1,
    rules: {
        pii: {
            action: 'redact',
            fields: [
                'password', 'senha', 'secret', 'token',
                'ssn', 'social_security',
                'credit_card', 'card_number', 'cvv',
                'cpf', 'cnpj', 'rg',
                'date_of_birth', 'dob',
                'bank_account', 'routing_number',
                'passport',
            ],
            censor: '[REDACTED]',
        },
        payload: {
            maxBytes: 51200,  // 50KB
            action: 'truncate',
        },
        rows: {
            maxItems: 50,
            action: 'truncate',
        },
        fields: {
            mode: 'blocklist',
            allowlist: [],
            blocklist: ['_id', '__v', 'tenant_id', 'created_at', 'updated_at', 'deleted_at'],
        },
        tools: {
            allowlist: [],
            blocklist: [],
        },
        rateLimit: {
            maxCallsPerMinute: 60,
            action: 'block',
        },
        secrets: {
            patterns: [
                'sk-[a-zA-Z0-9]{20,}',         // OpenAI keys
                'ghp_[a-zA-Z0-9]{36}',          // GitHub tokens
                'gho_[a-zA-Z0-9]{36}',          // GitHub OAuth tokens
                'AKIA[A-Z0-9]{16}',             // AWS access keys
                'xox[bpsa]-[0-9a-zA-Z-]{10,}',  // Slack tokens
            ],
            action: 'redact',
        },
    },
    audit: {
        enabled: true,
        path: './mcp-firewall.audit.jsonl',
    },
};

/**
 * Load a firewall policy from disk. Falls back to defaults.
 */
export function loadPolicy(policyPath?: string): FirewallPolicy {
    const resolvedPath = policyPath
        ? resolve(policyPath)
        : resolve(process.cwd(), 'firewall.yaml');

    if (!existsSync(resolvedPath)) {
        return structuredClone(DEFAULT_POLICY);
    }

    const raw = readFileSync(resolvedPath, 'utf-8');
    const parsed = parseYaml(raw) as Partial<FirewallPolicy> | null;

    if (!parsed || typeof parsed !== 'object') {
        return structuredClone(DEFAULT_POLICY);
    }

    // Deep merge with defaults
    return mergePolicy(DEFAULT_POLICY, parsed);
}

/**
 * Deep merge user policy over defaults, preserving default values
 * for any fields the user didn't specify.
 */
function mergePolicy(
    defaults: FirewallPolicy,
    user: Partial<FirewallPolicy>,
): FirewallPolicy {
    const merged = structuredClone(defaults);

    if (user.version != null) merged.version = user.version;

    if (user.rules) {
        const r = user.rules;
        if (r.pii) Object.assign(merged.rules.pii, r.pii);
        if (r.payload) Object.assign(merged.rules.payload, r.payload);
        if (r.rows) Object.assign(merged.rules.rows, r.rows);
        if (r.fields) Object.assign(merged.rules.fields, r.fields);
        if (r.tools) Object.assign(merged.rules.tools, r.tools);
        if (r.rateLimit) Object.assign(merged.rules.rateLimit, r.rateLimit);
        if (r.secrets) Object.assign(merged.rules.secrets, r.secrets);
    }

    if (user.audit) Object.assign(merged.audit, user.audit);

    return merged;
}

/** Generate a default firewall.yaml content string. */
export function generateDefaultPolicyYaml(): string {
    return `# mcp-firewall policy
# Documentation: https://vurb.vinkius.com/docs/firewall

version: 1

rules:
  pii:
    action: redact
    fields:
      - password
      - secret
      - token
      - ssn
      - credit_card
      - cpf
      - cnpj
    censor: "[REDACTED]"

  payload:
    maxBytes: 51200      # 50KB
    action: truncate

  rows:
    maxItems: 50
    action: truncate

  fields:
    mode: blocklist
    blocklist:
      - _id
      - __v
      - tenant_id
      - created_at
      - updated_at
      - deleted_at

  tools:
    blocklist: []
    allowlist: []

  rateLimit:
    maxCallsPerMinute: 60
    action: block

  secrets:
    patterns:
      - "sk-[a-zA-Z0-9]{20,}"
      - "ghp_[a-zA-Z0-9]{36}"
      - "AKIA[A-Z0-9]{16}"
    action: redact

audit:
  enabled: true
  path: ./mcp-firewall.audit.jsonl
`;
}
