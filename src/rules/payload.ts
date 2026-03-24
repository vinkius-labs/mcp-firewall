/**
 * Payload Size Rule — enforces maximum response size.
 * @module
 */
import type { PayloadRuleConfig, RuleVerdict } from '../types.js';

/**
 * Format bytes for display.
 */
export function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes}B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}

/**
 * Check payload size against the configured limit.
 * Returns a verdict if the limit is exceeded.
 */
export function applyPayloadRule(
    text: string,
    config: PayloadRuleConfig,
): RuleVerdict | null {
    const bytes = Buffer.byteLength(text, 'utf-8');

    if (bytes <= config.maxBytes) return null;

    const severity = bytes > config.maxBytes * 4 ? 'critical' : 'warning';

    if (config.action === 'block') {
        return {
            rule: 'payload',
            action: 'blocked',
            severity,
            title: `PAYLOAD BLOCKED — ${formatBytes(bytes)} exceeds ${formatBytes(config.maxBytes)} limit`,
            detail: `Response payload (${formatBytes(bytes)}) exceeds the configured maximum (${formatBytes(config.maxBytes)}). Response blocked.`,
        };
    }

    if (config.action === 'warn') {
        return {
            rule: 'payload',
            action: 'warned',
            severity,
            title: `PAYLOAD WARNING — ${formatBytes(bytes)} exceeds ${formatBytes(config.maxBytes)} limit`,
            detail: `Response payload (${formatBytes(bytes)}) exceeds the configured maximum (${formatBytes(config.maxBytes)}). No enforcement applied.`,
        };
    }

    // Default: truncate
    return {
        rule: 'payload',
        action: 'truncated',
        severity,
        title: `PAYLOAD TRUNCATED — ${formatBytes(bytes)} → ${formatBytes(config.maxBytes)}`,
        detail: `Response truncated from ${formatBytes(bytes)} to ${formatBytes(config.maxBytes)}.`,
    };
}

/**
 * Truncate text to the configured byte limit.
 */
export function truncatePayload(text: string, maxBytes: number): string {
    const buf = Buffer.from(text, 'utf-8');
    if (buf.length <= maxBytes) return text;

    // Truncate at byte boundary, ensuring valid UTF-8
    const truncated = buf.subarray(0, maxBytes).toString('utf-8');
    return truncated + '\n… [truncated by mcp-firewall]';
}
