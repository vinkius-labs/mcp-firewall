/**
 * mcp-firewall — Stdio Proxy (Active Enforcement).
 *
 * Spawns a child MCP server and intercepts stdio traffic.
 * Unlike mcp-proxy, this proxy MODIFIES responses based on policy rules.
 *
 * @module
 */
import { spawn } from 'node:child_process';
import type { FirewallPolicy, FirewallOptions, JsonRpcMessage, RuleVerdict } from './types.js';
import { enforce, trackRequest, resolveToolName, isToolCallRequest } from './engine.js';
import { AuditLogger, buildSessionSummary } from './audit.js';
import { renderEnforcement, renderSessionSummary } from './reporter.js';

/**
 * Start the firewall proxy.
 */
export async function startFirewall(
    command: string,
    args: string[],
    policy: FirewallPolicy,
    options: FirewallOptions = {},
): Promise<number> {
    return new Promise((resolve) => {
        const child = spawn(command, args, {
            stdio: ['pipe', 'pipe', 'inherit'],
            shell: process.platform === 'win32',
        });

        const audit = new AuditLogger(policy.audit);
        const startTime = Date.now();
        const allVerdicts: RuleVerdict[] = [];
        let totalCalls = 0;
        let blockedCount = 0;
        let stdinBuffer = '';
        let stdoutBuffer = '';

        // ── stdin: Client → Firewall → Server ───────────────────────────
        process.stdin.on('data', (chunk: Buffer) => {
            stdinBuffer += chunk.toString('utf-8');
            const lines = stdinBuffer.split('\n');
            stdinBuffer = lines.pop() || '';

            for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed) {
                    child.stdin.write('\n');
                    continue;
                }

                try {
                    const msg = JSON.parse(trimmed) as JsonRpcMessage;

                    // Track requests for tool name resolution
                    if (isToolCallRequest(msg)) {
                        const toolName = (msg.params as Record<string, unknown>)?.name as string;
                        trackRequest(msg);

                        // Apply request-side rules (tool access, rate limiting)
                        const result = enforce(msg, policy, toolName);
                        allVerdicts.push(...result.verdicts);

                        if (result.blocked) {
                            totalCalls++;
                            blockedCount++;

                            // Log audit entry
                            audit.log({
                                toolName,
                                messageId: msg.id ?? null,
                                verdicts: result.verdicts,
                                bytesBefore: Buffer.byteLength(trimmed),
                                bytesAfter: 0,
                                blocked: true,
                            });

                            // Send blocked response to client
                            if (!options.quiet) {
                                process.stderr.write(
                                    renderEnforcement(toolName, result.verdicts, true),
                                );
                            }

                            // Write blocked response to stdout (back to client)
                            process.stdout.write(
                                JSON.stringify(result.message) + '\n',
                            );
                            continue; // Don't forward to server
                        }
                    }

                    // Forward to server
                    child.stdin.write(trimmed + '\n');
                } catch {
                    // Non-JSON — pass through
                    child.stdin.write(line + '\n');
                }
            }
        });

        // ── stdout: Server → Firewall → Client ─────────────────────────
        child.stdout.on('data', (chunk: Buffer) => {
            stdoutBuffer += chunk.toString('utf-8');
            const lines = stdoutBuffer.split('\n');
            stdoutBuffer = lines.pop() || '';

            for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed) {
                    process.stdout.write('\n');
                    continue;
                }

                try {
                    const msg = JSON.parse(trimmed) as JsonRpcMessage;

                    // Resolve tool name from tracked requests
                    const toolName = msg.id != null
                        ? resolveToolName(msg.id)
                        : null;

                    // Apply response-side rules
                    const result = enforce(msg, policy, toolName);
                    totalCalls++;
                    allVerdicts.push(...result.verdicts);

                    if (result.blocked) blockedCount++;

                    // Log audit entry
                    if (result.verdicts.length > 0) {
                        const outputStr = JSON.stringify(result.message);
                        audit.log({
                            toolName: result.toolName,
                            messageId: msg.id ?? null,
                            verdicts: result.verdicts,
                            bytesBefore: Buffer.byteLength(trimmed),
                            bytesAfter: Buffer.byteLength(outputStr),
                            blocked: result.blocked,
                        });

                        // Report to stderr
                        if (!options.quiet || result.blocked) {
                            process.stderr.write(
                                renderEnforcement(
                                    result.toolName || `msg#${msg.id}`,
                                    result.verdicts,
                                    result.blocked,
                                ),
                            );
                        }
                    }

                    // Forward (possibly modified) response to client
                    process.stdout.write(JSON.stringify(result.message) + '\n');
                } catch {
                    // Non-JSON — pass through
                    process.stdout.write(line + '\n');
                }
            }
        });

        // ── Cleanup ─────────────────────────────────────────────────────

        process.stdin.on('end', () => {
            child.stdin.end();
        });

        child.on('close', (code) => {
            // Flush buffers
            if (stdinBuffer.trim()) child.stdin.write(stdinBuffer + '\n');
            if (stdoutBuffer.trim()) process.stdout.write(stdoutBuffer + '\n');

            // Session summary
            if (!options.json) {
                const summary = buildSessionSummary(
                    allVerdicts,
                    totalCalls,
                    blockedCount,
                    Date.now() - startTime,
                    audit.getEntryCount(),
                );
                process.stderr.write(renderSessionSummary(summary));
            }

            resolve(code ?? 0);
        });

        child.on('error', (err) => {
            process.stderr.write(
                `[MCP FIREWALL] Failed to start: ${err.message}\n`,
            );
            resolve(1);
        });
    });
}
