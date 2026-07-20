/**
 * MCP Extractor
 *
 * Extracts audit-relevant fields from MCP `callTool` invocations.
 * MCP tool calls are synchronous JSON request/response - no streaming.
 *
 * @packageDocumentation
 */

/**
 * Format MCP tool call arguments as prompt text.
 * Consistent with the OpenAI Agents pattern: `[MCP Tool call: toolName(args)]`
 */
export function extractMcpPrompt(
  toolName: string,
  args: Record<string, unknown> | undefined,
): string {
  const argsStr = args !== undefined ? JSON.stringify(args) : "";
  return `[MCP Tool call: ${toolName}(${argsStr})]`;
}

/**
 * Format MCP tool call result as response text.
 */
export function extractMcpResponse(result: unknown): string {
  if (result === undefined || result === null) return "";
  if (typeof result === "string") return result;
  return JSON.stringify(result);
}
