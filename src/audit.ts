/**
 * mcp-firewall — Audit Logger.
 *
 * Writes structured JSONL entries to a file for compliance.
 *
 * @module
 */
import { appendFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { AuditConfig, RuleVerdict, AuditEntry } from './types.js';

export class AuditLogger {
    private readonly path: string;
    private readonly enabled: boolean;
    private entryCount = 0;

    constructor(config: AuditConfig) {
        this.enabled = config.enabled;
        this.path = resolve(config.path);
    }

    /**
     * Log an enforcement result.
     */
    log(entry: Omit<AuditEntry, 'timestamp'>): void {
        if (!this.enabled) return;
        if (entry.verdicts.length === 0) return; // Only log when rules fired

        const full: AuditEntry = {
            timestamp: new Date().toISOString(),
            ...entry,
        };

        try {
            const line = JSON.stringify(full) + '\n';
            appendFileSync(this.path, line, 'utf-8');
            this.entryCount++;
        } catch {
            // Silently ignore audit write failures (don't break the proxy)
        }
    }

    /**
     * Get total entries written.
     */
    getEntryCount(): number {
        return this.entryCount;
    }
}

/**
 * Create a summary object for the session.
 */
export interface SessionSummary {
    totalCalls: number;
    totalVerdicts: number;
    totalBlocked: number;
    bySeverity: { critical: number; warning: number; info: number };
    byRule: Record<string, number>;
    durationMs: number;
    auditEntries: number;
}

export function buildSessionSummary(
    verdicts: RuleVerdict[],
    totalCalls: number,
    blockedCount: number,
    durationMs: number,
    auditEntries: number,
): SessionSummary {
    const bySeverity = { critical: 0, warning: 0, info: 0 };
    const byRule: Record<string, number> = {};

    for (const v of verdicts) {
        bySeverity[v.severity]++;
        byRule[v.rule] = (byRule[v.rule] || 0) + 1;
    }

    return {
        totalCalls,
        totalVerdicts: verdicts.length,
        totalBlocked: blockedCount,
        bySeverity,
        byRule,
        durationMs,
        auditEntries,
    };
}
