/**
 * mcp-firewall — Shared type definitions.
 * @module
 */

// ─── Policy ─────────────────────────────────────────────────────────────────

export type PolicyAction = 'redact' | 'block' | 'truncate' | 'warn';

export interface PiiRuleConfig {
    action: PolicyAction;
    fields: string[];
    censor: string;
}

export interface PayloadRuleConfig {
    maxBytes: number;
    action: PolicyAction;
}

export interface RowsRuleConfig {
    maxItems: number;
    action: PolicyAction;
}

export interface FieldsRuleConfig {
    mode: 'allowlist' | 'blocklist';
    allowlist: string[];
    blocklist: string[];
}

export interface ToolsRuleConfig {
    allowlist: string[];
    blocklist: string[];
}

export interface RateLimitRuleConfig {
    maxCallsPerMinute: number;
    action: PolicyAction;
}

export interface SecretsRuleConfig {
    patterns: string[];
    action: PolicyAction;
}

export interface AuditConfig {
    enabled: boolean;
    path: string;
}

export interface FirewallPolicy {
    version: number;
    rules: {
        pii: PiiRuleConfig;
        payload: PayloadRuleConfig;
        rows: RowsRuleConfig;
        fields: FieldsRuleConfig;
        tools: ToolsRuleConfig;
        rateLimit: RateLimitRuleConfig;
        secrets: SecretsRuleConfig;
    };
    audit: AuditConfig;
}

// ─── Rule Verdicts ──────────────────────────────────────────────────────────

export type RuleName = 'pii' | 'payload' | 'rows' | 'fields' | 'tools' | 'rate_limit' | 'secrets';

export type VerdictAction = 'passed' | 'redacted' | 'blocked' | 'truncated' | 'warned';

export interface RuleVerdict {
    rule: RuleName;
    action: VerdictAction;
    severity: 'critical' | 'warning' | 'info';
    title: string;
    detail: string;
    /** Fields/items affected */
    affected?: string[];
}

// ─── Enforcement Result ─────────────────────────────────────────────────────

export interface EnforcementResult {
    /** The (possibly modified) JSON-RPC message */
    message: JsonRpcMessage;
    /** Verdicts from each rule that fired */
    verdicts: RuleVerdict[];
    /** Whether the response was blocked entirely */
    blocked: boolean;
    /** Tool name (if resolved) */
    toolName: string | null;
}

// ─── Audit ──────────────────────────────────────────────────────────────────

export interface AuditEntry {
    timestamp: string;
    toolName: string | null;
    messageId: number | string | null;
    verdicts: RuleVerdict[];
    bytesBefore: number;
    bytesAfter: number;
    blocked: boolean;
}

// ─── JSON-RPC ───────────────────────────────────────────────────────────────

export interface JsonRpcMessage {
    jsonrpc: '2.0';
    id?: number | string;
    method?: string;
    params?: Record<string, unknown>;
    result?: unknown;
    error?: { code: number; message: string; data?: unknown };
}

// ─── CLI Options ────────────────────────────────────────────────────────────

export interface FirewallOptions {
    /** Path to policy YAML file */
    policyPath?: string;
    /** Quiet mode — only show blocked actions and session summary */
    quiet?: boolean;
    /** JSON output to stderr */
    json?: boolean;
}
