/**
 * Secret Detection Rule — detects API keys, tokens, and secrets in response text.
 * @module
 */
import type { SecretsRuleConfig, RuleVerdict } from '../types.js';

/**
 * Compile regex patterns from config.
 */
function compilePatterns(patterns: string[]): RegExp[] {
    const compiled: RegExp[] = [];
    for (const p of patterns) {
        try {
            compiled.push(new RegExp(p, 'g'));
        } catch {
            // Skip invalid patterns
        }
    }
    return compiled;
}

/**
 * Detect and optionally redact secrets in text.
 * Returns the modified text and a verdict.
 */
export function applySecretsRule(
    text: string,
    config: SecretsRuleConfig,
): { text: string; verdict: RuleVerdict | null } {
    if (config.patterns.length === 0) return { text, verdict: null };

    const regexes = compilePatterns(config.patterns);
    const detected: string[] = [];
    let modified = text;

    for (const regex of regexes) {
        regex.lastIndex = 0;
        const matches = text.matchAll(regex);
        for (const match of matches) {
            // Store a masked preview of the detected secret
            const val = match[0];
            const preview = val.length > 8
                ? `${val.substring(0, 4)}…${val.substring(val.length - 4)}`
                : '****';

            if (!detected.includes(preview)) {
                detected.push(preview);
            }
        }
    }

    if (detected.length === 0) return { text, verdict: null };

    if (config.action === 'redact') {
        for (const regex of regexes) {
            modified = modified.replace(new RegExp(regex.source, 'g'), '[SECRET_REDACTED]');
        }
    }

    const action = config.action === 'warn' ? 'warned' as const : 'redacted' as const;

    return {
        text: config.action === 'redact' ? modified : text,
        verdict: {
            rule: 'secrets',
            action,
            severity: 'critical',
            title: `SECRETS ${config.action === 'redact' ? 'REDACTED' : 'DETECTED'} — ${detected.length} pattern(s)`,
            detail: `Detected ${detected.length} potential secret(s): ${detected.join(', ')}.`,
            affected: detected,
        },
    };
}
