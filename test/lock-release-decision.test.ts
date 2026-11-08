// F-N26-1 (MR-C): the one decision `lock release` takes for every platform before its typed confirmation.
import { describe, expect, it } from "vitest";
import { lockReleaseDecision, type LockReleaseFacts } from "../src/cli/lock-release-decision.js";

const base: LockReleaseFacts = { ownershipUnresolved: true, ownerLiveness: "dead", liveChildren: 0, descendants: 0, scanOk: true, force: false };
const decide = (o: Partial<LockReleaseFacts>) => lockReleaseDecision({ ...base, ...o });

describe("lockReleaseDecision (F-N26-1)", () => {
  it("a live or unconfirmed owner of a lock whose ownership is not unresolved is refused, with or without --force", () => {
    for (const ownerLiveness of ["alive", "alive_unconfirmed"]) {
      for (const force of [false, true]) {
        for (const scanOk of [false, true]) {
          expect(decide({ ownershipUnresolved: false, ownerLiveness, force, scanOk })).toMatchObject({ proceed: false, reason: "owner_live" });
        }
      }
    }
  });

  it("an unreadable process table refuses without --force, also when no process is listed", () => {
    expect(decide({ scanOk: false })).toMatchObject({ proceed: false, reason: "descendants_unverified" });
    // An unresolved lock goes past the owner check whatever the owner's liveness reads (unchanged).
    expect(decide({ scanOk: false, ownerLiveness: "alive_unconfirmed" })).toMatchObject({ proceed: false, reason: "descendants_unverified" });
  });

  it("processes still running refuse without --force (checked before the table's availability)", () => {
    expect(decide({ liveChildren: 1 })).toMatchObject({ proceed: false, reason: "processes_running" });
    expect(decide({ descendants: 2 })).toMatchObject({ proceed: false, reason: "processes_running" });
    expect(decide({ liveChildren: 1, scanOk: false })).toMatchObject({ proceed: false, reason: "processes_running" });
  });

  it("--force goes on to the confirmation, with a warning for an unverified table or for running processes", () => {
    const unverified = decide({ scanOk: false, force: true });
    expect(unverified).toMatchObject({ proceed: true });
    expect(unverified.proceed && unverified.warnings.join(" ")).toMatch(/NOT verified as ended/);
    const running = decide({ descendants: 1, force: true });
    expect(running.proceed && running.warnings.join(" ")).toMatch(/still running/);
  });

  it("a readable table with nothing running goes on to the confirmation without a warning, with or without --force", () => {
    expect(decide({})).toEqual({ proceed: true, warnings: [] });
    expect(decide({ force: true })).toEqual({ proceed: true, warnings: [] });
    expect(decide({ ownershipUnresolved: false, ownerLiveness: "dead" })).toEqual({ proceed: true, warnings: [] });
  });
});
