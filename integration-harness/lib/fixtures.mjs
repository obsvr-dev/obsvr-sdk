/**
 * Resolve the conformance fixtures THROUGH the resolved package (never a
 * hardcoded absolute path), so the harness cross-checks against exactly the SDK
 * build it is running against.
 *
 * @obsvr/sdk is ESM-only: its exports map defines only the "import" condition, so
 * `require.resolve("@obsvr/sdk")` throws ERR_PACKAGE_PATH_NOT_EXPORTED. Use the
 * ESM resolver instead, then realpath (follow the dependency symlink) and walk up:
 *   .../sdk-typescript/dist/index.js -> up 2 -> .../sdk-typescript -> ../conformance/fixtures
 * The fixtures live at the repo root (sibling of sdk-typescript/).
 *
 * This is why nothing here needs to know where the checkout is: `file:` in the
 * dependency list, an npm link, or a published tarball all resolve the same way.
 */
import { readFileSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Absolute path to the resolved @obsvr/sdk package root (symlink followed).
 * Exported because suites that drive the SHIPPED binaries (the device-seal
 * suite runs `dist/cli-verify.js`) need the same anchor, and a suite that
 * hardcodes the path instead only runs on the machine it was written on.
 */
export function sdkPkgRoot() {
  const main = realpathSync(fileURLToPath(import.meta.resolve("@obsvr/sdk")));
  return dirname(dirname(main)); // dist/index.js -> dist -> package root
}

/** Absolute path to the linked SDK's conformance/fixtures directory. */
export function fixturesDir() {
  return join(sdkPkgRoot(), "..", "conformance", "fixtures");
}

/** Load and parse conformance/fixtures/<name>.json (name without extension). */
export function loadFixture(name) {
  return JSON.parse(readFileSync(join(fixturesDir(), `${name}.json`), "utf8"));
}

/** The `version` from the LINKED @obsvr/sdk package.json (the manifest). Used to
 *  assert the runtime sdk_version stamp hasn't drifted from the manifest — the
 *  exact bug class where a 0.9.0 package stamped node/2.0.0. */
export function linkedSdkVersion() {
  return JSON.parse(readFileSync(join(sdkPkgRoot(), "package.json"), "utf8")).version;
}
