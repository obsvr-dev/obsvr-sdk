import * as fs from "node:fs";
import * as path from "node:path";
import * as url from "node:url";
import {
  AARM_COMPATIBILITY_PROFILE_VERSION,
  AARM_OUTCOMES,
  AarmOutcomeMappingError,
  mapAarmOutcome,
} from "../../src/governance/aarm-outcome";
import type { ActionTaken } from "../../src/governance/action-taken";

const HERE = path.dirname(url.fileURLToPath(import.meta.url));
const FIXTURE = JSON.parse(
  fs.readFileSync(
    path.resolve(HERE, "../../../conformance/fixtures/aarm_outcomes.json"),
    "utf8",
  ),
) as {
  claimable: boolean;
  profile_version: string;
  outcomes: string[];
  mapping_cases: FixtureCase[];
  rejection_cases: FixtureCase[];
};

interface FixtureCase {
  id: string;
  input: {
    action_taken: ActionTaken;
    approval_required?: boolean;
    deferred?: boolean;
  };
  expect?: string;
}

function mapCase(c: FixtureCase) {
  return mapAarmOutcome({
    actionTaken: c.input.action_taken,
    approvalRequired: c.input.approval_required,
    deferred: c.input.deferred,
  });
}

describe("Obsvr-authored AARM compatibility outcome mapping", () => {
  it("pins the profile version and outcome vocabulary", () => {
    expect(AARM_COMPATIBILITY_PROFILE_VERSION).toBe(FIXTURE.profile_version);
    expect([...AARM_OUTCOMES]).toEqual(FIXTURE.outcomes);
    expect(FIXTURE.claimable).toBe(false);
  });

  for (const c of FIXTURE.mapping_cases) {
    it(c.id, () => {
      expect(mapCase(c)).toBe(c.expect);
    });
  }

  for (const c of FIXTURE.rejection_cases) {
    it(`rejects ${c.id}`, () => {
      expect(() => mapCase(c)).toThrow(AarmOutcomeMappingError);
    });
  }
});
