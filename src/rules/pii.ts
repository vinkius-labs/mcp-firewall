/**
 * PII Redaction Rule — replaces sensitive field values with a censor string.
 * @module
 */
import type { PiiRuleConfig, RuleVerdict } from '../types.js';

/** PII field name patterns (case-insensitive). */
const PII_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
    { pattern: /^password/i,           label: 'password' },
    { pattern: /^senha/i,              label: 'senha' },
    { pattern: /^secret/i,             label: 'secret' },
    { pattern: /^token/i,              label: 'token' },
    { pattern: /^api[_-]?key/i,        label: 'api_key' },
    { pattern: /^ssn$/i,               label: 'ssn' },
    { pattern: /social.?security/i,    label: 'social_security' },
    { pattern: /credit.?card/i,        label: 'credit_card' },
    { pattern: /card.?number/i,        label: 'card_number' },
    { pattern: /^cvv$/i,               label: 'cvv' },
    { pattern: /^cpf$/i,               label: 'cpf' },
    { pattern: /^cnpj$/i,              label: 'cnpj' },
    { pattern: /^rg$/i,                label: 'rg' },
    { pattern: /date.?of.?birth/i,     label: 'date_of_birth' },
    { pattern: /^dob$/i,               label: 'dob' },
    { pattern: /bank.?account/i,       label: 'bank_account' },
    { pattern: /routing.?number/i,     label: 'routing_number' },
    { pattern: /^passport/i,           label: 'passport' },
    { pattern: /^phone/i,              label: 'phone' },
    { pattern: /^email$/i,             label: 'email' },
    { pattern: /^address$/i,           label: 'address' },
    { pattern: /national.?id/i,        label: 'national_id' },
    { pattern: /driver.?licen[sc]e/i,  label: 'driver_license' },
    { pattern: /^ip[_-]?address/i,     label: 'ip_address' },
    { pattern: /^private[_-]?key/i,    label: 'private_key' },
];

/**
 * Check if a field name matches any configured PII pattern.
 */
function isPiiField(fieldName: string, configuredFields: string[]): boolean {
    const baseName = fieldName.split('.').pop() || fieldName;

    // Check configured fields (exact match, case-insensitive)
    for (const cf of configuredFields) {
        if (baseName.toLowerCase() === cf.toLowerCase()) return true;
    }

    // Check built-in patterns
    for (const { pattern } of PII_PATTERNS) {
        if (pattern.test(baseName)) return true;
    }

    return false;
}

/**
 * Recursively redact PII fields in an object.
 * Returns the list of redacted field paths.
 */
function redactObject(
    obj: unknown,
    configuredFields: string[],
    censor: string,
    path: string = '',
): string[] {
    const redacted: string[] = [];

    if (obj === null || obj === undefined || typeof obj !== 'object') {
        return redacted;
    }

    if (Array.isArray(obj)) {
        for (let i = 0; i < obj.length; i++) {
            redacted.push(...redactObject(obj[i], configuredFields, censor, `${path}[${i}]`));
        }
        return redacted;
    }

    const record = obj as Record<string, unknown>;
    for (const key of Object.keys(record)) {
        const fullPath = path ? `${path}.${key}` : key;

        if (isPiiField(key, configuredFields)) {
            if (record[key] !== null && record[key] !== undefined) {
                record[key] = censor;
                redacted.push(fullPath);
            }
        } else if (typeof record[key] === 'object' && record[key] !== null) {
            redacted.push(...redactObject(record[key], configuredFields, censor, fullPath));
        }
    }

    return redacted;
}

/**
 * Apply PII redaction to a parsed JSON payload.
 * Mutates the data in-place and returns a verdict.
 */
export function applyPiiRule(
    data: unknown,
    config: PiiRuleConfig,
): RuleVerdict | null {
    if (config.action === 'warn') {
        // In warn mode, detect but don't redact
        const clone = structuredClone(data);
        const fields = redactObject(clone, config.fields, config.censor);
        if (fields.length === 0) return null;

        return {
            rule: 'pii',
            action: 'warned',
            severity: 'critical',
            title: `PII DETECTED — ${fields.length} sensitive field(s)`,
            detail: `Fields with potential PII: ${[...new Set(fields.map(f => f.split('.').pop()))].join(', ')}. Action is set to warn-only.`,
            affected: fields,
        };
    }

    if (config.action === 'block') {
        const clone = structuredClone(data);
        const fields = redactObject(clone, config.fields, config.censor);
        if (fields.length === 0) return null;

        return {
            rule: 'pii',
            action: 'blocked',
            severity: 'critical',
            title: `PII BLOCKED — ${fields.length} sensitive field(s)`,
            detail: `Response blocked: ${[...new Set(fields.map(f => f.split('.').pop()))].join(', ')} contain PII.`,
            affected: fields,
        };
    }

    // Default: redact
    const fields = redactObject(data, config.fields, config.censor);
    if (fields.length === 0) return null;

    return {
        rule: 'pii',
        action: 'redacted',
        severity: 'critical',
        title: `PII REDACTED — ${fields.length} field(s)`,
        detail: `Replaced with "${config.censor}": ${[...new Set(fields.map(f => f.split('.').pop()))].join(', ')}.`,
        affected: fields,
    };
}
