#!/usr/bin/env node
/**
 * mcp-firewall — CLI entry point.
 *
 * An active policy enforcement proxy for MCP servers.
 * Redacts PII, enforces limits, filters fields, controls tools,
 * and generates compliance audit logs.
 *
 * @example
 * ```bash
 * npx @mcp-firewall/enforce -- node dist/server.js
 * npx @mcp-firewall/enforce --policy strict.yaml -- python server.py
 * ```
 *
 * @module
 */
import pc from 'picocolors';
import { loadPolicy, generateDefaultPolicyYaml } from './policy.js';
import { startFirewall } from './proxy.js';
import type { FirewallOptions } from './types.js';

// Re-export public API
export type {
    FirewallPolicy, FirewallOptions, RuleVerdict, EnforcementResult,
    AuditEntry, JsonRpcMessage, PolicyAction, RuleName, VerdictAction,
} from './types.js';
export { loadPolicy, generateDefaultPolicyYaml, DEFAULT_POLICY } from './policy.js';
export { enforce, trackRequest, resolveToolName } from './engine.js';
export { AuditLogger, buildSessionSummary } from './audit.js';
export { renderEnforcement, renderSessionSummary } from './reporter.js';
export { startFirewall } from './proxy.js';
export { applyPiiRule } from './rules/pii.js';
export { applyPayloadRule, truncatePayload, formatBytes } from './rules/payload.js';
export { applyRowsRule, truncateRows, countRows } from './rules/rows.js';
export { applyFieldsRule } from './rules/fields.js';
export { applyToolsRule } from './rules/tools.js';
export { applyRateLimitRule, resetRateLimiter } from './rules/rate-limit.js';
export { applySecretsRule } from './rules/secrets.js';

// ─── CLI ──────────────────────────────────────────────────────────

const HELP = `
${pc.bold('mcp-firewall')} — Active policy enforcement proxy for MCP servers.
Powered by ${pc.cyan('vurb.ts')} — The Express.js for MCP Servers.

${pc.bold('Usage:')}
  npx @mcp-firewall/enforce [options] -- <command> [args...]

${pc.bold('Options:')}
  --policy <file>  Path to firewall.yaml (default: ./firewall.yaml)
  --init           Generate a default firewall.yaml in the current directory
  --quiet          Only show blocked actions and session summary
  --json           Output enforcement log as JSON to stderr
  -h, --help       Show this help message

${pc.bold('Examples:')}
  npx @mcp-firewall/enforce -- node dist/server.js
  npx @mcp-firewall/enforce --policy strict.yaml -- python server.py
  npx @mcp-firewall/enforce --init

${pc.bold('Cursor / Claude Desktop config:')}
  ${pc.dim('{')}
  ${pc.dim('  "mcpServers": {')}
  ${pc.dim('    "my-server": {')}
  ${pc.dim('      "command": "npx",')}
  ${pc.dim('      "args": ["@mcp-firewall/enforce", "--", "node", "dist/server.js"]')}
  ${pc.dim('    }')}
  ${pc.dim('  }')}
  ${pc.dim('}')}

${pc.bold('Docs:')} ${pc.cyan('https://vurb.vinkius.com')}
`;

async function main(): Promise<void> {
    const argv = process.argv.slice(2);

    const separatorIndex = argv.indexOf('--');
    const optionArgs = separatorIndex >= 0 ? argv.slice(0, separatorIndex) : argv;
    const commandArgs = separatorIndex >= 0 ? argv.slice(separatorIndex + 1) : [];

    // Help
    if (optionArgs.includes('-h') || optionArgs.includes('--help')) {
        process.stderr.write(HELP);
        process.exit(0);
    }

    // Init
    if (optionArgs.includes('--init')) {
        const { writeFileSync } = await import('node:fs');
        const yaml = generateDefaultPolicyYaml();
        writeFileSync('firewall.yaml', yaml, 'utf-8');
        process.stderr.write(pc.green('✓ Created firewall.yaml in current directory.\n'));
        process.exit(0);
    }

    // No command
    if (commandArgs.length === 0) {
        process.stderr.write(HELP);
        process.exit(1);
    }

    // Parse options
    const policyIndex = optionArgs.indexOf('--policy');
    const policyPath = policyIndex >= 0 ? optionArgs[policyIndex + 1] : undefined;

    const options: FirewallOptions = {
        policyPath,
        quiet: optionArgs.includes('--quiet'),
        json:  optionArgs.includes('--json'),
    };

    // Load policy
    const policy = loadPolicy(options.policyPath);

    const [command, ...childArgs] = commandArgs;
    if (!command) {
        process.stderr.write(pc.red('Error: No command specified after --\n'));
        process.exit(1);
    }

    // Banner
    if (!options.json) {
        process.stderr.write(
            pc.dim(`[MCP FIREWALL] Enforcing policy on: ${command} ${childArgs.join(' ')}\n`),
        );

        if (!options.policyPath) {
            process.stderr.write(
                pc.dim(`[MCP FIREWALL] Using default policy (create firewall.yaml with --init)\n`),
            );
        }
    }

    const exitCode = await startFirewall(command, childArgs, policy, options);
    process.exit(exitCode);
}

main().catch((err) => {
    process.stderr.write(
        `[MCP FIREWALL] Fatal: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(1);
});
