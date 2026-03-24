/**
 * Tool Access Control Rule — allowlist/blocklist tool names.
 * @module
 */
import type { ToolsRuleConfig, RuleVerdict } from '../types.js';

/**
 * Check if a tool call should be blocked.
 * Returns a verdict if blocked, null if allowed.
 */
export function applyToolsRule(
    toolName: string,
    config: ToolsRuleConfig,
): RuleVerdict | null {
    // If allowlist is configured and non-empty, only allow those tools
    if (config.allowlist.length > 0) {
        const allowed = config.allowlist.some(
            t => t.toLowerCase() === toolName.toLowerCase(),
        );
        if (!allowed) {
            return {
                rule: 'tools',
                action: 'blocked',
                severity: 'critical',
                title: `TOOL BLOCKED — "${toolName}" not in allowlist`,
                detail: `Tool "${toolName}" is not in the allowed tools list. Allowed: ${config.allowlist.join(', ')}.`,
                affected: [toolName],
            };
        }
    }

    // Check blocklist
    if (config.blocklist.length > 0) {
        const blocked = config.blocklist.some(
            t => t.toLowerCase() === toolName.toLowerCase(),
        );
        if (blocked) {
            return {
                rule: 'tools',
                action: 'blocked',
                severity: 'critical',
                title: `TOOL BLOCKED — "${toolName}" is blocklisted`,
                detail: `Tool "${toolName}" is in the blocked tools list.`,
                affected: [toolName],
            };
        }
    }

    return null;
}
