/**
 * Debug Logger
 *
 * Conditional logging that respects the debug flag in config.
 *
 * @packageDocumentation
 */

import type { ResolvedConfig } from "../proxy/types.js";
import { LOG_PREFIX as PREFIX } from "../constants.js";

/**
 * Log a debug message if debug mode is enabled
 */
export function debugLog(
  config: ResolvedConfig | null,
  level: "info" | "warn" | "error",
  message: string,
  ...args: unknown[]
): void {
  if (!config?.debug) {
    return;
  }

  const timestamp = new Date().toISOString();
  const fullMessage = `${PREFIX} ${timestamp} ${message}`;

  switch (level) {
    case "info":
      console.log(fullMessage, ...args);
      break;
    case "warn":
      console.warn(fullMessage, ...args);
      break;
    case "error":
      console.error(fullMessage, ...args);
      break;
  }
}

/**
 * Create a logger bound to a specific config
 */
export function createLogger(config: ResolvedConfig) {
  return {
    info: (message: string, ...args: unknown[]) =>
      debugLog(config, "info", message, ...args),
    warn: (message: string, ...args: unknown[]) =>
      debugLog(config, "warn", message, ...args),
    error: (message: string, ...args: unknown[]) =>
      debugLog(config, "error", message, ...args),
  };
}
