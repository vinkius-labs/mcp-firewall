/**
 * mcp-firewall — Comprehensive test suite.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { applyPiiRule } from '../src/rules/pii.js';
import { applyPayloadRule, truncatePayload, formatBytes } from '../src/rules/payload.js';
import { applyRowsRule, truncateRows, countRows } from '../src/rules/rows.js';
import { applyFieldsRule } from '../src/rules/fields.js';
import { applyToolsRule } from '../src/rules/tools.js';
import { applyRateLimitRule, resetRateLimiter } from '../src/rules/rate-limit.js';
import { applySecretsRule } from '../src/rules/secrets.js';
import {
    enforce,
    trackRequest,
    resolveToolName,
    isRequest,
    isResponse,
    isToolCallRequest,
    isToolCallResult,
    extractTextContent,
} from '../src/engine.js';
import { buildSessionSummary } from '../src/audit.js';
import { renderEnforcement, renderSessionSummary } from '../src/reporter.js';
import { DEFAULT_POLICY } from '../src/policy.js';
import type { FirewallPolicy, JsonRpcMessage } from '../src/types.js';

// ─── Helpers ──────────────────────────────────────────────────────────────

function makeToolCallResult(data: unknown, id = 1): JsonRpcMessage {
    return {
        jsonrpc: '2.0',
        id,
        result: {
            content: [{ type: 'text', text: JSON.stringify(data) }],
        },
    };
}

function makeToolCallRequest(name: string, id = 1): JsonRpcMessage {
    return {
        jsonrpc: '2.0',
        id,
        method: 'tools/call',
        params: { name },
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// PII Rule
// ═══════════════════════════════════════════════════════════════════════════

describe('PII Rule', () => {
    const config = DEFAULT_POLICY.rules.pii;

    it('redacts password fields', () => {
        const data = { username: 'john', password: 'secret123' };
        const verdict = applyPiiRule(data, config);
        expect(verdict).not.toBeNull();
        expect(verdict!.action).toBe('redacted');
        expect(data.password).toBe('[REDACTED]');
        expect(data.username).toBe('john');
    });

    it('redacts nested PII fields', () => {
        const data = { user: { name: 'John', ssn: '123-45-6789' } };
        const verdict = applyPiiRule(data, config);
        expect(verdict).not.toBeNull();
        expect(data.user.ssn).toBe('[REDACTED]');
    });

    it('redacts PII in arrays', () => {
        const data = [
            { name: 'Alice', cpf: '111.222.333-44' },
            { name: 'Bob', cpf: '555.666.777-88' },
        ];
        const verdict = applyPiiRule(data, config);
        expect(verdict).not.toBeNull();
        expect(data[0].cpf).toBe('[REDACTED]');
        expect(data[1].cpf).toBe('[REDACTED]');
    });

    it('returns null when no PII found', () => {
        const data = { id: 1, name: 'Product', price: 99.90 };
        const verdict = applyPiiRule(data, config);
        expect(verdict).toBeNull();
    });

    it('respects custom censor string', () => {
        const data = { email: 'test@example.com' };
        const customConfig = { ...config, censor: '***' };
        applyPiiRule(data, customConfig);
        expect(data.email).toBe('***');
    });

    it('warns without redacting in warn mode', () => {
        const data = { password: 'secret' };
        const warnConfig = { ...config, action: 'warn' as const };
        const verdict = applyPiiRule(data, warnConfig);
        expect(verdict).not.toBeNull();
        expect(verdict!.action).toBe('warned');
        expect(data.password).toBe('secret'); // Not redacted
    });

    it('blocks in block mode', () => {
        const data = { ssn: '123-45-6789' };
        const blockConfig = { ...config, action: 'block' as const };
        const verdict = applyPiiRule(data, blockConfig);
        expect(verdict).not.toBeNull();
        expect(verdict!.action).toBe('blocked');
    });

    it('detects credit card fields', () => {
        const data = { credit_card_number: '4111-1111-1111-1111', cvv: '123' };
        const verdict = applyPiiRule(data, config);
        expect(verdict).not.toBeNull();
        expect(data.credit_card_number).toBe('[REDACTED]');
        expect(data.cvv).toBe('[REDACTED]');
    });

    it('does not redact null values', () => {
        const data = { password: null, name: 'test' };
        const verdict = applyPiiRule(data, config);
        expect(verdict).toBeNull();
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Payload Rule
// ═══════════════════════════════════════════════════════════════════════════

describe('Payload Rule', () => {
    const config = DEFAULT_POLICY.rules.payload;

    it('returns null for small payloads', () => {
        const verdict = applyPayloadRule('Hello world', config);
        expect(verdict).toBeNull();
    });

    it('flags oversized payloads', () => {
        const big = 'x'.repeat(60000); // ~60KB
        const verdict = applyPayloadRule(big, config);
        expect(verdict).not.toBeNull();
        expect(verdict!.rule).toBe('payload');
    });

    it('truncates text to max bytes', () => {
        const big = 'x'.repeat(60000);
        const truncated = truncatePayload(big, 1024);
        expect(Buffer.byteLength(truncated)).toBeLessThan(60000);
    });

    it('returns original if under limit', () => {
        const small = 'hello';
        expect(truncatePayload(small, 1024)).toBe(small);
    });

    it('blocks in block mode', () => {
        const big = 'x'.repeat(60000);
        const blockConfig = { ...config, action: 'block' as const };
        const verdict = applyPayloadRule(big, blockConfig);
        expect(verdict!.action).toBe('blocked');
    });

    it('warns in warn mode', () => {
        const big = 'x'.repeat(60000);
        const warnConfig = { ...config, action: 'warn' as const };
        const verdict = applyPayloadRule(big, warnConfig);
        expect(verdict!.action).toBe('warned');
    });
});

describe('formatBytes', () => {
    it('formats bytes', () => expect(formatBytes(500)).toBe('500B'));
    it('formats kilobytes', () => expect(formatBytes(2048)).toBe('2.0KB'));
    it('formats megabytes', () => expect(formatBytes(2 * 1024 * 1024)).toBe('2.0MB'));
});

// ═══════════════════════════════════════════════════════════════════════════
// Rows Rule
// ═══════════════════════════════════════════════════════════════════════════

describe('Rows Rule', () => {
    const config = DEFAULT_POLICY.rules.rows;

    it('returns null for small arrays', () => {
        const data = Array.from({ length: 10 }, (_, i) => ({ id: i }));
        const verdict = applyRowsRule(data, config);
        expect(verdict).toBeNull();
    });

    it('truncates oversized arrays', () => {
        const data = Array.from({ length: 100 }, (_, i) => ({ id: i }));
        const verdict = applyRowsRule(data, config);
        expect(verdict).not.toBeNull();
        expect(verdict!.action).toBe('truncated');
        expect(data.length).toBe(51); // 50 items + truncation message
    });

    it('blocks in block mode', () => {
        const data = Array.from({ length: 100 }, (_, i) => ({ id: i }));
        const blockConfig = { ...config, action: 'block' as const };
        const verdict = applyRowsRule(data, blockConfig);
        expect(verdict!.action).toBe('blocked');
    });

    it('counts nested arrays', () => {
        const data = { items: Array.from({ length: 5 }, (_, i) => i) };
        expect(countRows(data)).toBe(5);
    });

    it('returns 0 for non-arrays', () => {
        expect(countRows({ a: 1, b: 2 })).toBe(0);
        expect(countRows(null)).toBe(0);
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Fields Rule
// ═══════════════════════════════════════════════════════════════════════════

describe('Fields Rule', () => {
    it('removes blocklisted fields', () => {
        const data = { id: 1, _id: 'abc', __v: 0, name: 'Test' };
        const config = DEFAULT_POLICY.rules.fields;
        const verdict = applyFieldsRule(data, config);
        expect(verdict).not.toBeNull();
        expect('_id' in data).toBe(false);
        expect('__v' in data).toBe(false);
        expect(data.name).toBe('Test');
    });

    it('keeps allowlisted fields only', () => {
        const data = { id: 1, name: 'Test', secret: 'val', extra: 'bye' } as Record<string, unknown>;
        const config = { mode: 'allowlist' as const, allowlist: ['id', 'name'], blocklist: [] };
        const verdict = applyFieldsRule(data, config);
        expect(verdict).not.toBeNull();
        expect('id' in data).toBe(true);
        expect('name' in data).toBe(true);
        expect('secret' in data).toBe(false);
    });

    it('returns null when no fields to remove', () => {
        const data = { id: 1, name: 'Test' };
        const config = DEFAULT_POLICY.rules.fields;
        const verdict = applyFieldsRule(data, config);
        expect(verdict).toBeNull();
    });

    it('filters fields in arrays', () => {
        const data = [{ id: 1, _id: 'abc' }, { id: 2, _id: 'def' }];
        const config = DEFAULT_POLICY.rules.fields;
        applyFieldsRule(data, config);
        expect('_id' in data[0]).toBe(false);
        expect('_id' in data[1]).toBe(false);
    });

    it('returns null for empty config', () => {
        const data = { a: 1 };
        const emptyConfig = { mode: 'blocklist' as const, allowlist: [], blocklist: [] };
        expect(applyFieldsRule(data, emptyConfig)).toBeNull();
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Tools Rule
// ═══════════════════════════════════════════════════════════════════════════

describe('Tools Rule', () => {
    it('allows tools not in blocklist', () => {
        const config = { allowlist: [], blocklist: ['danger_tool'] };
        expect(applyToolsRule('safe_tool', config)).toBeNull();
    });

    it('blocks blocklisted tools', () => {
        const config = { allowlist: [], blocklist: ['danger_tool'] };
        const verdict = applyToolsRule('danger_tool', config);
        expect(verdict).not.toBeNull();
        expect(verdict!.action).toBe('blocked');
    });

    it('blocks tools not in allowlist', () => {
        const config = { allowlist: ['safe_tool'], blocklist: [] };
        const verdict = applyToolsRule('unknown_tool', config);
        expect(verdict).not.toBeNull();
        expect(verdict!.action).toBe('blocked');
    });

    it('allows tools in allowlist', () => {
        const config = { allowlist: ['safe_tool'], blocklist: [] };
        expect(applyToolsRule('safe_tool', config)).toBeNull();
    });

    it('handles case-insensitive matching', () => {
        const config = { allowlist: [], blocklist: ['Danger_Tool'] };
        const verdict = applyToolsRule('danger_tool', config);
        expect(verdict!.action).toBe('blocked');
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Rate Limit Rule
// ═══════════════════════════════════════════════════════════════════════════

describe('Rate Limit Rule', () => {
    beforeEach(() => {
        resetRateLimiter();
    });

    it('allows calls under the limit', () => {
        const config = { maxCallsPerMinute: 5, action: 'block' as const };
        const verdict = applyRateLimitRule('tool_a', config);
        expect(verdict).toBeNull();
    });

    it('blocks calls over the limit', () => {
        const config = { maxCallsPerMinute: 3, action: 'block' as const };
        applyRateLimitRule('tool_b', config);
        applyRateLimitRule('tool_b', config);
        applyRateLimitRule('tool_b', config);
        const verdict = applyRateLimitRule('tool_b', config);
        expect(verdict).not.toBeNull();
        expect(verdict!.action).toBe('blocked');
    });

    it('warns in warn mode', () => {
        const config = { maxCallsPerMinute: 1, action: 'warn' as const };
        applyRateLimitRule('tool_c', config);
        const verdict = applyRateLimitRule('tool_c', config);
        expect(verdict!.action).toBe('warned');
    });

    it('tracks separate tools independently', () => {
        const config = { maxCallsPerMinute: 2, action: 'block' as const };
        applyRateLimitRule('tool_x', config);
        applyRateLimitRule('tool_x', config);
        expect(applyRateLimitRule('tool_x', config)?.action).toBe('blocked');
        expect(applyRateLimitRule('tool_y', config)).toBeNull();
    });

    it('returns null for zero limit', () => {
        const config = { maxCallsPerMinute: 0, action: 'block' as const };
        expect(applyRateLimitRule('any', config)).toBeNull();
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Secrets Rule
// ═══════════════════════════════════════════════════════════════════════════

describe('Secrets Rule', () => {
    const config = DEFAULT_POLICY.rules.secrets;

    it('detects OpenAI keys', () => {
        const text = 'config: sk-abcdefghij1234567890abcdef';
        const { verdict } = applySecretsRule(text, config);
        expect(verdict).not.toBeNull();
        expect(verdict!.rule).toBe('secrets');
    });

    it('redacts secrets from text', () => {
        const text = 'key is sk-abcdefghij1234567890abcdef here';
        const { text: cleaned } = applySecretsRule(text, config);
        expect(cleaned).toContain('[SECRET_REDACTED]');
        expect(cleaned).not.toContain('sk-abcdefghij');
    });

    it('detects GitHub tokens', () => {
        const text = 'token: ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456789a';
        const { verdict } = applySecretsRule(text, config);
        expect(verdict).not.toBeNull();
    });

    it('detects AWS keys', () => {
        const text = 'aws: AKIAIOSFODNN7EXAMPLE';
        const { verdict } = applySecretsRule(text, config);
        expect(verdict).not.toBeNull();
    });

    it('returns null for clean text', () => {
        const text = 'This is a normal response with no secrets.';
        const { verdict } = applySecretsRule(text, config);
        expect(verdict).toBeNull();
    });

    it('warns without redacting in warn mode', () => {
        const text = 'key: sk-abcdefghij1234567890abcdef';
        const warnConfig = { ...config, action: 'warn' as const };
        const { text: result, verdict } = applySecretsRule(text, warnConfig);
        expect(verdict!.action).toBe('warned');
        expect(result).toContain('sk-abcdefghij'); // Not redacted
    });

    it('handles empty patterns', () => {
        const { verdict } = applySecretsRule('any text', { patterns: [], action: 'redact' });
        expect(verdict).toBeNull();
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Engine
// ═══════════════════════════════════════════════════════════════════════════

describe('Engine', () => {
    it('isRequest detects requests', () => {
        expect(isRequest({ jsonrpc: '2.0', method: 'test', id: 1 })).toBe(true);
    });

    it('isResponse detects responses', () => {
        expect(isResponse({ jsonrpc: '2.0', id: 1, result: {} })).toBe(true);
    });

    it('isToolCallRequest detects tools/call', () => {
        expect(isToolCallRequest({ jsonrpc: '2.0', method: 'tools/call', id: 1 })).toBe(true);
        expect(isToolCallRequest({ jsonrpc: '2.0', method: 'other', id: 1 })).toBe(false);
    });

    it('extracts text content from tool results', () => {
        const msg = makeToolCallResult({ items: [1, 2, 3] });
        const text = extractTextContent(msg);
        expect(text).toBe(JSON.stringify({ items: [1, 2, 3] }));
    });

    it('tracks and resolves tool names', () => {
        const req = makeToolCallRequest('users.list', 42);
        trackRequest(req);
        expect(resolveToolName(42)).toBe('users.list');
        expect(resolveToolName(42)).toBeNull(); // Consumed
    });

    it('enforces PII redaction on responses', () => {
        const msg = makeToolCallResult({ name: 'John', password: 'secret123' });
        const result = enforce(msg, DEFAULT_POLICY, 'users.get');
        expect(result.verdicts.length).toBeGreaterThan(0);
        expect(result.verdicts.some(v => v.rule === 'pii')).toBe(true);
        expect(result.blocked).toBe(false);
    });

    it('blocks tools in blocklist', () => {
        const policy = structuredClone(DEFAULT_POLICY);
        policy.rules.tools.blocklist = ['danger_tool'];
        const req = makeToolCallRequest('danger_tool', 99);
        trackRequest(req);
        const result = enforce(req, policy, 'danger_tool');
        expect(result.blocked).toBe(true);
    });

    it('enforces field filtering', () => {
        const msg = makeToolCallResult({ id: 1, _id: 'mongo', __v: 0, name: 'Test' });
        const result = enforce(msg, DEFAULT_POLICY, 'items.list');
        expect(result.verdicts.some(v => v.rule === 'fields')).toBe(true);
    });

    it('passes clean responses without verdicts', () => {
        const msg = makeToolCallResult({ id: 1, name: 'Test' });
        const result = enforce(msg, DEFAULT_POLICY, 'items.get');
        expect(result.verdicts.length).toBe(0);
        expect(result.blocked).toBe(false);
    });

    it('handles non-JSON text gracefully', () => {
        const msg: JsonRpcMessage = {
            jsonrpc: '2.0',
            id: 1,
            result: {
                content: [{ type: 'text', text: 'Not JSON at all' }],
            },
        };
        const result = enforce(msg, DEFAULT_POLICY, 'tool');
        // Should still run text-level rules (secrets, payload) without crashing
        expect(result.blocked).toBe(false);
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Audit / Session
// ═══════════════════════════════════════════════════════════════════════════

describe('Session Summary', () => {
    it('builds a correct summary', () => {
        const verdicts = [
            { rule: 'pii' as const, action: 'redacted' as const, severity: 'critical' as const, title: 'a', detail: 'b' },
            { rule: 'fields' as const, action: 'redacted' as const, severity: 'info' as const, title: 'c', detail: 'd' },
            { rule: 'payload' as const, action: 'truncated' as const, severity: 'warning' as const, title: 'e', detail: 'f' },
        ];
        const summary = buildSessionSummary(verdicts, 10, 2, 5000, 3);
        expect(summary.totalCalls).toBe(10);
        expect(summary.totalVerdicts).toBe(3);
        expect(summary.totalBlocked).toBe(2);
        expect(summary.bySeverity.critical).toBe(1);
        expect(summary.bySeverity.warning).toBe(1);
        expect(summary.bySeverity.info).toBe(1);
        expect(summary.byRule.pii).toBe(1);
        expect(summary.byRule.fields).toBe(1);
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Reporter
// ═══════════════════════════════════════════════════════════════════════════

describe('Reporter', () => {
    it('renders enforcement report for verdicts', () => {
        const verdicts = [
            { rule: 'pii' as const, action: 'redacted' as const, severity: 'critical' as const, title: 'PII REDACTED', detail: 'Replaced password', affected: ['password'] },
        ];
        const output = renderEnforcement('users.get', verdicts, false);
        expect(output).toContain('MCP FIREWALL');
        expect(output).toContain('PII REDACTED');
        expect(output).toContain('npm install @vurb/core');
    });

    it('returns empty string for no verdicts', () => {
        expect(renderEnforcement('tool', [], false)).toBe('');
    });

    it('renders blocked status', () => {
        const verdicts = [
            { rule: 'tools' as const, action: 'blocked' as const, severity: 'critical' as const, title: 'TOOL BLOCKED', detail: 'Blocked' },
        ];
        const output = renderEnforcement('danger', verdicts, true);
        expect(output).toContain('BLOCKED');
    });

    it('renders session summary', () => {
        const summary = buildSessionSummary(
            [{ rule: 'pii' as const, action: 'redacted' as const, severity: 'critical' as const, title: 'a', detail: 'b' }],
            5, 1, 10000, 5,
        );
        const output = renderSessionSummary(summary);
        expect(output).toContain('Session Report');
        expect(output).toContain('Calls intercepted');
    });

    it('returns empty for zero-call sessions', () => {
        const summary = buildSessionSummary([], 0, 0, 0, 0);
        expect(renderSessionSummary(summary)).toBe('');
    });
});
