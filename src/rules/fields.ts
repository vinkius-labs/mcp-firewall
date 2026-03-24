/**
 * Field Filter Rule — allowlist/blocklist fields from responses.
 * External equivalent of vurb.ts's Egress Firewall (Presenter schema).
 * @module
 */
import type { FieldsRuleConfig, RuleVerdict } from '../types.js';

/**
 * Remove fields from an object based on a blocklist.
 * Mutates in-place. Returns removed field names.
 */
function removeBlocklisted(obj: unknown, blocklist: string[]): string[] {
    if (obj === null || obj === undefined || typeof obj !== 'object') return [];

    if (Array.isArray(obj)) {
        const removed: string[] = [];
        for (const item of obj) {
            removed.push(...removeBlocklisted(item, blocklist));
        }
        return removed;
    }

    const record = obj as Record<string, unknown>;
    const removed: string[] = [];

    for (const field of blocklist) {
        if (field in record) {
            delete record[field];
            if (!removed.includes(field)) removed.push(field);
        }
    }

    // Recurse into nested objects
    for (const val of Object.values(record)) {
        if (typeof val === 'object' && val !== null) {
            removed.push(...removeBlocklisted(val, blocklist));
        }
    }

    return [...new Set(removed)];
}

/**
 * Keep only allowlisted fields, removing everything else.
 * Mutates in-place. Returns removed field names.
 */
function keepAllowlisted(obj: unknown, allowlist: string[]): string[] {
    if (obj === null || obj === undefined || typeof obj !== 'object') return [];

    if (Array.isArray(obj)) {
        const removed: string[] = [];
        for (const item of obj) {
            removed.push(...keepAllowlisted(item, allowlist));
        }
        return removed;
    }

    const record = obj as Record<string, unknown>;
    const removed: string[] = [];
    const allowSet = new Set(allowlist.map(f => f.toLowerCase()));

    for (const key of Object.keys(record)) {
        if (!allowSet.has(key.toLowerCase())) {
            delete record[key];
            if (!removed.includes(key)) removed.push(key);
        }
    }

    return [...new Set(removed)];
}

/**
 * Apply field filter rule.
 */
export function applyFieldsRule(
    data: unknown,
    config: FieldsRuleConfig,
): RuleVerdict | null {
    if (config.mode === 'blocklist' && config.blocklist.length === 0) return null;
    if (config.mode === 'allowlist' && config.allowlist.length === 0) return null;

    let removed: string[];

    if (config.mode === 'allowlist') {
        removed = keepAllowlisted(data, config.allowlist);
    } else {
        removed = removeBlocklisted(data, config.blocklist);
    }

    if (removed.length === 0) return null;

    return {
        rule: 'fields',
        action: 'redacted',
        severity: 'info',
        title: `FIELDS FILTERED — ${removed.length} field(s) removed`,
        detail: `Removed ${config.mode === 'allowlist' ? 'non-allowlisted' : 'blocklisted'} fields: ${removed.join(', ')}.`,
        affected: removed,
    };
}
