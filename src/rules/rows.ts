/**
 * Row Limit Rule — truncates arrays to a max item count.
 * @module
 */
import type { RowsRuleConfig, RuleVerdict } from '../types.js';

/**
 * Find and truncate arrays in parsed data.
 * Mutates the data in-place.
 * Returns the number of rows removed.
 */
export function truncateRows(data: unknown, maxItems: number): number {
    if (data === null || data === undefined || typeof data !== 'object') return 0;

    if (Array.isArray(data) && data.length > maxItems) {
        const removed = data.length - maxItems;
        data.length = maxItems;
        data.push(`… and ${removed} more items truncated by mcp-firewall`);
        return removed;
    }

    if (Array.isArray(data)) {
        let total = 0;
        for (const item of data) {
            total += truncateRows(item, maxItems);
        }
        return total;
    }

    // Object — check nested arrays
    const record = data as Record<string, unknown>;
    let total = 0;
    for (const key of Object.keys(record)) {
        const val = record[key];
        if (Array.isArray(val) && val.length > maxItems) {
            const removed = val.length - maxItems;
            val.length = maxItems;
            val.push(`… and ${removed} more items truncated by mcp-firewall`);
            total += removed;
        } else if (typeof val === 'object' && val !== null) {
            total += truncateRows(val, maxItems);
        }
    }
    return total;
}

/**
 * Count total array items (top-level or first nested array).
 */
export function countRows(data: unknown): number {
    if (Array.isArray(data)) return data.length;
    if (data !== null && typeof data === 'object') {
        for (const val of Object.values(data as Record<string, unknown>)) {
            if (Array.isArray(val)) return val.length;
        }
    }
    return 0;
}

/**
 * Apply row limit rule.
 */
export function applyRowsRule(
    data: unknown,
    config: RowsRuleConfig,
): RuleVerdict | null {
    const rowCount = countRows(data);
    if (rowCount <= config.maxItems) return null;

    const overflow = rowCount - config.maxItems;

    if (config.action === 'warn') {
        return {
            rule: 'rows',
            action: 'warned',
            severity: rowCount > config.maxItems * 2 ? 'critical' : 'warning',
            title: `ROW WARNING — ${rowCount.toLocaleString()} rows (limit: ${config.maxItems})`,
            detail: `Response contains ${rowCount.toLocaleString()} rows, exceeding the ${config.maxItems} limit by ${overflow.toLocaleString()}. No enforcement applied.`,
        };
    }

    if (config.action === 'block') {
        return {
            rule: 'rows',
            action: 'blocked',
            severity: 'critical',
            title: `ROW OVERFLOW BLOCKED — ${rowCount.toLocaleString()} rows`,
            detail: `Response blocked: contains ${rowCount.toLocaleString()} rows (limit: ${config.maxItems}).`,
        };
    }

    // Default: truncate
    truncateRows(data, config.maxItems);

    return {
        rule: 'rows',
        action: 'truncated',
        severity: rowCount > config.maxItems * 2 ? 'critical' : 'warning',
        title: `ROWS TRUNCATED — ${rowCount.toLocaleString()} → ${config.maxItems}`,
        detail: `Truncated ${overflow.toLocaleString()} rows. LLM receives only the first ${config.maxItems} items.`,
    };
}
