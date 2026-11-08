// MR-C: whether `code-parley lock release` may go on to its typed confirmation. One decision for every
// platform (F-N26-1): the process table is evidence of survivors, never proof that none exist
// (process/proc-table.ts), so a table that could not be read leaves the descendants unverified and the
// release is refused unless the user passes --force, as for processes seen still running.
//
// --force keeps its one meaning: release although processes may still be running. It never overrides a
// live or unconfirmed owner, the typed confirmation or the re-read of the lock before it is cleared.

export interface LockReleaseFacts {
  /** The lock was flagged ownership_unresolved (its server died during checks). */
  ownershipUnresolved: boolean;
  /** The owner's liveness classification: "dead", or anything else (live, unknown). */
  ownerLiveness: string;
  /** Recorded children not known to be dead. */
  liveChildren: number;
  /** Descendants of the recorded children found in the process table. */
  descendants: number;
  /** The process table was read (false: descendants were not checked). */
  scanOk: boolean;
  force: boolean;
}

export type LockReleaseDecision =
  | { proceed: false; reason: "owner_live" | "processes_running" | "descendants_unverified"; message: string }
  | { proceed: true; warnings: string[] };

export function lockReleaseDecision(f: LockReleaseFacts): LockReleaseDecision {
  if (!f.ownershipUnresolved && f.ownerLiveness !== "dead") {
    return { proceed: false, reason: "owner_live", message: "the lock is held by a live (or unconfirmed) owner; it is not released. Stop that operation instead." };
  }
  const running = f.liveChildren > 0 || f.descendants > 0;
  if (!f.force) {
    if (running) return { proceed: false, reason: "processes_running", message: "processes started by the check are still running; end them first, or pass --force to release anyway" };
    if (!f.scanOk) {
      return {
        proceed: false,
        reason: "descendants_unverified",
        message:
          "the process table could not be read, so processes the check started could not be verified as ended; the lock was not released. " +
          "Run `code-parley lock show` again, or, once you have confirmed that nothing the recorded commands started is still running, pass --force to release anyway",
      };
    }
    return { proceed: true, warnings: [] };
  }
  const warnings: string[] = [];
  if (!f.scanOk) warnings.push("WARNING: --force: the process table could not be read, so processes the check started were NOT verified as ended; releasing lets another operation use this worktree while they may still run.");
  else if (running) warnings.push("WARNING: --force: processes started by the check are still running; releasing lets another operation use this worktree while they run.");
  return { proceed: true, warnings };
}
