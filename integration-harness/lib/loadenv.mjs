/**
 * Minimal .env loader (no dependency). Reads the harness-root .env once and
 * populates process.env WITHOUT overwriting anything already set in the shell.
 * Imported for its side effect by mock-ingest.mjs, so every test + the runner
 * pick up OBSVR_API_KEY / OBSVR_INGEST_URL / provider keys automatically.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ENV_PATH = join(dirname(dirname(fileURLToPath(import.meta.url))), ".env");

try {
  const text = readFileSync(ENV_PATH, "utf8");
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    // strip matching surrounding quotes
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (key && process.env[key] === undefined) process.env[key] = val;
  }
} catch {
  // no .env file — that's fine, rely on shell env
}
