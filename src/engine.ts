/**
 * mcp-firewall — Policy Engine.
 *
 * Orchestrates all 7 rules in order against a parsed JSON-RPC response.
 * Returns the (possibly modified) message plus an array of verdicts.
 *
 * @module
 */
import type {
    FirewallPolicy,
    JsonRpcMessage,
    EnforcementResult,
    RuleVerdict,
} from './types.js';
import { applyPiiRule } from './rules/pii.js';
import { applyPayloadRule, truncatePayload } from './rules/payload.js';
import { applyRowsRule } from './rules/rows.js';
import { applyFieldsRule } from './rules/fields.js';
import { applyToolsRule } from './rules/tools.js';
import { applyRateLimitRule } from './rules/rate-limit.js';
import { applySecretsRule } from './rules/secrets.js';

// ─── JSON-RPC Helpers (reuse from mcp-proxy pattern) ────────────────────────

export function isRequest(msg: JsonRpcMessage): boolean {
    return 'method' in msg && typeof msg.method === 'string';
}

export function isToolCallRequest(msg: JsonRpcMessage): boolean {
    return isRequest(msg) && msg.method === 'tools/call';
}

export function isResponse(msg: JsonRpcMessage): boolean {
    return 'id' in msg && ('result' in msg || 'error' in msg);
}

export function isToolCallResult(msg: JsonRpcMessage): boolean {
    if (!isResponse(msg) || !msg.result) return false;
    const r = msg.result as Record<string, unknown>;
    return Array.isArray(r.content);
}

export function extractTextContent(msg: JsonRpcMessage): string | null {
    if (!msg.result) return null;
    const r = msg.result as Record<string, unknown>;
    if (!Array.isArray(r.content)) return null;
    const texts: string[] = [];
    for (const item of r.content) {
        if (item && typeof item === 'object' && 'type' in item && 'text' in item) {
            const i = item as { type: string; text: string };
            if (i.type === 'text') texts.push(i.text);
        }
    }
    return texts.length > 0 ? texts.join('\n') : null;
}

// ─── Request Tracker ────────────────────────────────────────────────────────

const pendingRequests = new Map<number | string, string>();

export function trackRequest(msg: JsonRpcMessage): void {
    if (isToolCallRequest(msg) && msg.id != null && msg.params) {
        const name = (msg.params as Record<string, unknown>).name;
        if (typeof name === 'string') {
            pendingRequests.set(msg.id, name);
        }
    }
}

export function resolveToolName(id: number | string | undefined): string | null {
    if (id == null) return null;
    const name = pendingRequests.get(id) ?? null;
    if (name) pendingRequests.delete(id);
    return name;
}

// ─── Policy Engine ──────────────────────────────────────────────────────────

/**
 * Apply all firewall rules to a JSON-RPC message.
 *
 * For requests: checks tool access control and rate limiting.
 * For responses: checks PII, payload, rows, fields, secrets.
 */
export function enforce(
    msg: JsonRpcMessage,
    policy: FirewallPolicy,
    toolName: string | null,
): EnforcementResult {
    const verdicts: RuleVerdict[] = [];
    let blocked = false;

    // ── Request-side rules ──────────────────────────────────────────────

    if (isToolCallRequest(msg) && toolName) {
        // 1. Tool access control
        const toolVerdict = applyToolsRule(toolName, policy.rules.tools);
        if (toolVerdict) {
            verdicts.push(toolVerdict);
            if (toolVerdict.action === 'blocked') blocked = true;
        }

        // 2. Rate limiting
        if (!blocked) {
            const rateVerdict = applyRateLimitRule(toolName, policy.rules.rateLimit);
            if (rateVerdict) {
                verdicts.push(rateVerdict);
                if (rateVerdict.action === 'blocked') blocked = true;
            }
        }

        if (blocked) {
            // Return a blocked response instead of forwarding
            return {
                message: createBlockedResponse(msg.id, verdicts),
                verdicts,
                blocked: true,
                toolName,
            };
        }

        return { message: msg, verdicts, blocked: false, toolName };
    }

    // ── Response-side rules ─────────────────────────────────────────────

    if (!isToolCallResult(msg)) {
        return { message: msg, verdicts, blocked: false, toolName };
    }

    const text = extractTextContent(msg);
    if (!text) {
        return { message: msg, verdicts, blocked: false, toolName };
    }

    // Try to parse JSON from the text content
    let parsed: unknown = null;
    try {
        parsed = JSON.parse(text);
    } catch {
        // Non-JSON text — only apply text-level rules
    }

    let modifiedText = text;

    if (parsed !== null) {
        // Deep clone for safe mutation
        parsed = structuredClone(parsed);

        // 3. PII Redaction
        const piiVerdict = applyPiiRule(parsed, policy.rules.pii);
        if (piiVerdict) {
            verdicts.push(piiVerdict);
            if (piiVerdict.action === 'blocked') {
                blocked = true;
            }
        }

        // 4. Field filtering
        if (!blocked) {
            const fieldsVerdict = applyFieldsRule(parsed, policy.rules.fields);
            if (fieldsVerdict) verdicts.push(fieldsVerdict);
        }

        // 5. Row truncation
        if (!blocked) {
            const rowsVerdict = applyRowsRule(parsed, policy.rules.rows);
            if (rowsVerdict) {
                verdicts.push(rowsVerdict);
                if (rowsVerdict.action === 'blocked') blocked = true;
            }
        }

        // Serialize back after mutations
        if (!blocked) {
            modifiedText = JSON.stringify(parsed);
        }
    }

    // 6. Secret detection (text-level)
    if (!blocked) {
        const { text: cleanedText, verdict: secretVerdict } = applySecretsRule(
            modifiedText,
            policy.rules.secrets,
        );
        modifiedText = cleanedText;
        if (secretVerdict) verdicts.push(secretVerdict);
    }

    // 7. Payload size check
    if (!blocked) {
        const payloadVerdict = applyPayloadRule(modifiedText, policy.rules.payload);
        if (payloadVerdict) {
            verdicts.push(payloadVerdict);
            if (payloadVerdict.action === 'blocked') {
                blocked = true;
            } else if (payloadVerdict.action === 'truncated') {
                modifiedText = truncatePayload(modifiedText, policy.rules.payload.maxBytes);
            }
        }
    }

    if (blocked) {
        return {
            message: createBlockedResponse(msg.id, verdicts),
            verdicts,
            blocked: true,
            toolName,
        };
    }

    // Rebuild message with modified text
    const modifiedMsg = rebuildMessage(msg, modifiedText);

    return { message: modifiedMsg, verdicts, blocked, toolName };
}

/**
 * Create a blocked response.
 */
function createBlockedResponse(
    id: number | string | undefined,
    verdicts: RuleVerdict[],
): JsonRpcMessage {
    const reasons = verdicts
        .filter(v => v.action === 'blocked')
        .map(v => v.title)
        .join('; ');

    return {
        jsonrpc: '2.0',
        id: id ?? 0,
        result: {
            content: [{
                type: 'text',
                text: `[mcp-firewall] Response blocked: ${reasons}`,
            }],
            isError: true,
        },
    };
}

/**
 * Rebuild a tool call result with modified text content.
 */
function rebuildMessage(msg: JsonRpcMessage, newText: string): JsonRpcMessage {
    const result = msg.result as Record<string, unknown>;
    const content = result.content as Array<Record<string, unknown>>;

    // Replace the first text content item
    const rebuilt = content.map(item => {
        if (item.type === 'text') {
            return { ...item, text: newText };
        }
        return item;
    });

    return {
        ...msg,
        result: { ...result, content: rebuilt },
    };
}
