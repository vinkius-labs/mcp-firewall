/**
 * Rate Limit Rule — sliding window per-tool rate limiter.
 * @module
 */
import type { RateLimitRuleConfig, RuleVerdict } from '../types.js';

/** Sliding window state: timestamps of recent calls per tool. */
const callHistory = new Map<string, number[]>();

/**
 * Record a call and check rate limit.
 */
export function applyRateLimitRule(
    toolName: string,
    config: RateLimitRuleConfig,
): RuleVerdict | null {
    if (config.maxCallsPerMinute <= 0) return null;

    const now = Date.now();
    const windowMs = 60_000; // 1 minute

    // Get or create call history for this tool
    let history = callHistory.get(toolName);
    if (!history) {
        history = [];
        callHistory.set(toolName, history);
    }

    // Prune timestamps outside the window
    const cutoff = now - windowMs;
    while (history.length > 0 && history[0]! < cutoff) {
        history.shift();
    }

    // Record this call
    history.push(now);

    // Check limit
    if (history.length > config.maxCallsPerMinute) {
        if (config.action === 'warn') {
            return {
                rule: 'rate_limit',
                action: 'warned',
                severity: 'warning',
                title: `RATE LIMIT WARNING — "${toolName}" (${history.length}/${config.maxCallsPerMinute}/min)`,
                detail: `Tool "${toolName}" called ${history.length} times in the last minute (limit: ${config.maxCallsPerMinute}).`,
                affected: [toolName],
            };
        }

        return {
            rule: 'rate_limit',
            action: 'blocked',
            severity: 'warning',
            title: `RATE LIMITED — "${toolName}" (${history.length}/${config.maxCallsPerMinute}/min)`,
            detail: `Tool "${toolName}" exceeded rate limit: ${history.length} calls in the last minute (limit: ${config.maxCallsPerMinute}).`,
            affected: [toolName],
        };
    }

    return null;
}

/** Reset rate limiter state (for testing). */
export function resetRateLimiter(): void {
    callHistory.clear();
}
