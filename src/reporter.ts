/**
 * mcp-firewall — Terminal Reporter.
 *
 * Styled stderr output for enforcement actions.
 *
 * @module
 */
import pc from 'picocolors';
import type { RuleVerdict } from './types.js';
import type { SessionSummary } from './audit.js';

const BORDER = '━'.repeat(74);
const THIN   = '─'.repeat(70);

const SEVERITY_BADGE: Record<string, string> = {
    critical: pc.bgRed(pc.white(pc.bold('  CRITICAL  '))),
    warning:  pc.bgYellow(pc.black(pc.bold('  WARNING   '))),
    info:     pc.bgCyan(pc.black(pc.bold('   INFO     '))),
};

const ACTION_BADGE: Record<string, string> = {
    blocked:   pc.red('⛔'),
    redacted:  pc.yellow('🔒'),
    truncated: pc.yellow('✂️'),
    warned:    pc.cyan('⚠'),
    passed:    pc.green('✓'),
};

/**
 * Render a per-call enforcement report to stderr.
 */
export function renderEnforcement(
    toolName: string,
    verdicts: RuleVerdict[],
    blocked: boolean,
): string {
    if (verdicts.length === 0) return '';

    const lines: string[] = [];
    lines.push('');
    lines.push(BORDER);
    lines.push('');

    const status = blocked
        ? pc.red(pc.bold('BLOCKED'))
        : pc.yellow(pc.bold('ENFORCED'));

    lines.push(`   ${status}   ${pc.dim('[MCP FIREWALL]')} ${pc.bold(toolName)}`);
    lines.push('');

    for (const v of verdicts) {
        const badge = SEVERITY_BADGE[v.severity] || v.severity;
        const action = ACTION_BADGE[v.action] || v.action;
        lines.push(`   ${badge} ${action} ${v.title}`);
        lines.push('');
        lines.push(`    ${pc.dim(v.detail)}`);

        if (v.affected && v.affected.length > 0) {
            lines.push(`    ${pc.dim('Affected:')} ${v.affected.join(', ')}`);
        }
        lines.push('');
    }

    // CTA
    lines.push(`  ${THIN}`);
    lines.push(`  ${pc.dim('Build this into your server:')}  ${pc.cyan('$ npm install @vurb/core')}`);
    lines.push(`  ${pc.dim('Docs:')}                         ${pc.cyan('https://vurb.vinkius.com')}`);
    lines.push('');
    lines.push(BORDER);
    lines.push('');

    return lines.join('\n');
}

/**
 * Render a session summary report.
 */
export function renderSessionSummary(summary: SessionSummary): string {
    if (summary.totalCalls === 0) return '';

    const lines: string[] = [];
    lines.push('');
    lines.push(BORDER);
    lines.push('');

    // Duration
    const secs = Math.floor(summary.durationMs / 1000);
    const mins = Math.floor(secs / 60);
    const durationStr = mins > 0
        ? `${mins}m ${secs % 60}s`
        : `${secs}s`;

    lines.push(`  ${pc.dim('[MCP FIREWALL]')} ${pc.bold('Session Report')}  ${pc.dim(`(${durationStr})`)}`);
    lines.push('');
    lines.push(`  Calls intercepted:  ${pc.bold(String(summary.totalCalls))}`);
    lines.push(`  Rules triggered:    ${pc.bold(String(summary.totalVerdicts))}`);
    lines.push(`  Responses blocked:  ${pc.bold(pc.red(String(summary.totalBlocked)))}`);

    if (summary.auditEntries > 0) {
        lines.push(`  Audit log entries:  ${pc.bold(String(summary.auditEntries))}`);
    }

    lines.push('');

    // Severity breakdown
    if (summary.totalVerdicts > 0) {
        lines.push('  Enforcement summary:');
        if (summary.bySeverity.critical > 0)
            lines.push(`    ${pc.red('●')} ${summary.bySeverity.critical} critical`);
        if (summary.bySeverity.warning > 0)
            lines.push(`    ${pc.yellow('●')} ${summary.bySeverity.warning} warning`);
        if (summary.bySeverity.info > 0)
            lines.push(`    ${pc.cyan('●')} ${summary.bySeverity.info} info`);
    } else {
        lines.push(`  ${pc.green('✓')} No rules triggered — all traffic is clean.`);
    }

    // Rule breakdown
    if (Object.keys(summary.byRule).length > 0) {
        lines.push('');
        lines.push('  By rule:');
        for (const [rule, count] of Object.entries(summary.byRule)) {
            lines.push(`    ${pc.dim(rule)}: ${count}`);
        }
    }

    lines.push('');
    lines.push(`  ${THIN}`);
    lines.push(`  ${pc.dim('Build this into your server:')}  ${pc.cyan('$ npm install @vurb/core')}`);
    lines.push(`  ${pc.dim('Docs:')}                         ${pc.cyan('https://vurb.vinkius.com')}`);
    lines.push('');
    lines.push(BORDER);
    lines.push('');

    return lines.join('\n');
}
