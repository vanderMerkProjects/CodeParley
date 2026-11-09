// POST-1 Fix Withdraw (contract revision 2): the operator permanently withdraws one confirmed, unconsumed delegated fix.
//
//   fix withdraw <run-id> <proposal> --repo <path>   (operator, interactive) the direct form
//   fix review                                       the guided form: a confirmed fix waiting for its application is
//                                                    listed with a number, and offers [w]ithdraw / [l]eave
//
// The custodian selects the fix's current confirmation, binds it into the prepared withdrawal and refuses its commit if the
// fix was withdrawn, consumed or ended since. This command prints the custodian's statement of what is withdrawn and what is
// not undone, checks that the prepared withdrawal is the one selected, and commits only the word typed at an interactive
// terminal. Presentation, not authority: only the operator surface prepares and commits (CALLER_NOT_AUTHORIZED otherwise),
// and no MCP tool, hook or server module reaches this module (test/delegated-fix-layering).

import { DomainError, isDomainError } from "../common/errors.js";
import { isUuid } from "../common/ids.js";
import { deliveryOutcomeOf } from "../custodian/grants.js";
import { escapeText, unescapedIn } from "../custodian/render-escape.js";
import type { CustodianTransport } from "../custodian/transport.js";
import { commitFixWithdrawal, prepareFixWithdrawal, prepareGuidedFixWithdrawal, type FixListingEntry, type PreparedFixWithdrawal } from "../engine/fix-decision.js";
import { hostOperatorAssurance } from "../schemas/user-authority.js";
import type { CliIo } from "./cli.js";

export const FIX_WITHDRAW_NOT_INTERACTIVE =
  "A delegated fix's confirmation is withdrawn only at an interactive terminal, with the word typed by you: run this command yourself in a terminal (stdin and stdout must be a terminal; there is no flag that skips this). Nothing was recorded.";

export const FIX_WITHDRAW_OLD_CUSTODIAN =
  "This custodian predates `fix withdraw`. Ending the run (`code-parley runs stop <run-id> --close --repo <path>`) retires its confirmed fixes, and everything else in the run. Or upgrade the custodian. Nothing was recorded.";

/** The outcome of one withdrawal attempt: recorded, already withdrawn (the end state holds; nothing written), not recorded
 * (cancelled or refused), or unknown (the commit's answer was lost). */
export type WithdrawOutcome = "withdrawn" | "already" | "not_recorded" | "refused" | "unknown" | "old_custodian";

const text = (s: string) => escapeText(s);

function olderCustodian(e: unknown): boolean {
  return isDomainError(e) && (e.details as { custodian_code?: string } | undefined)?.custodian_code === "UNKNOWN_OPERATION";
}

/** Why a prepared withdrawal is not the one selected (null: it is). */
export function preparedWithdrawalMismatch(p: PreparedFixWithdrawal, want: { repoKey?: string; runId: string; operationId: string; confirmationId?: string; proposalDigest?: string; renderingDigest?: string }): string | null {
  const f = p.facts;
  if (want.repoKey !== undefined && f.repoKey !== want.repoKey) return "another repository identity";
  if (f.runId !== want.runId || f.operationId !== want.operationId) return "another run or fix";
  if (want.confirmationId !== undefined && f.confirmationId !== want.confirmationId) return "another confirmation";
  if (want.proposalDigest !== undefined && f.proposalDigest !== want.proposalDigest) return "another proposal";
  if (want.renderingDigest !== undefined && f.renderingDigest !== want.renderingDigest) return "another confirmed rendering";
  for (const line of p.rendering.split("\n")) if (unescapedIn(line) !== null) return "its statement holds an unescaped character";
  return null;
}

/** Prepare, show, ask for the word, commit and report one withdrawal. `prepare` is the direct or the guided preparation. */
async function withdrawOnce(transport: CustodianTransport, io: CliIo, prompt: (q: string) => Promise<string>, prepare: () => Promise<PreparedFixWithdrawal>,
  want: Parameters<typeof preparedWithdrawalMismatch>[1]): Promise<WithdrawOutcome> {
  let prepared: PreparedFixWithdrawal;
  try {
    prepared = await prepare();
  } catch (e) {
    if (olderCustodian(e)) {
      io.err(FIX_WITHDRAW_OLD_CUSTODIAN);
      return "old_custodian";
    }
    if (!isDomainError(e)) throw e;
    // A withdrawal observed at prepare: the end state holds; nothing was prepared or written (contract C1).
    if (e.code === "CONFIRMATION_WITHDRAWN") {
      io.out(`Already withdrawn: ${text(e.message)}`);
      return "already";
    }
    if (deliveryOutcomeOf(e) === "unknown") {
      io.err(`The custodian's answer to the preparation was lost (${text(e.message)}). Nothing was recorded: a preparation records nothing.`);
      return "refused";
    }
    io.err(`The custodian did not prepare the withdrawal: ${e.code}: ${text(e.message)}`);
    io.err("Nothing was recorded.");
    return "refused";
  }
  const mismatch = preparedWithdrawalMismatch(prepared, want);
  if (mismatch) {
    io.err(`The prepared withdrawal is not the one you selected (${mismatch}). Nothing was recorded; it expires unused.`);
    return "refused";
  }
  io.out("The CodeParley custodian prepared this withdrawal (nothing is recorded until you type it):");
  io.out("");
  for (const line of prepared.rendering.replace(/\n$/, "").split("\n")) io.out(`  ${line}`);
  io.out("");
  io.out(`This prepared withdrawal expires at ${text(prepared.expiresAt)}.`);
  const word = (await prompt('Type "withdraw" to record this (anything else cancels): ')).trim().toLowerCase();
  if (word !== "withdraw") {
    io.out("Not recorded (the prepared withdrawal expires unused).");
    return "not_recorded";
  }
  let out: Awaited<ReturnType<typeof commitFixWithdrawal>>;
  try {
    out = await commitFixWithdrawal(transport, prepared.authorizationRequestId);
  } catch (e) {
    if (deliveryOutcomeOf(e) === "unknown") {
      io.err("The custodian's answer was lost after the withdrawal was sent: CodeParley does not know whether it was recorded and does not send it again. Check with `code-parley fix show <run-id> <proposal> --repo <path>` or `code-parley fix review`.");
      return "unknown";
    }
    if (!isDomainError(e)) throw e;
    // A commit prepared before the fix was withdrawn or consumed elsewhere never claims a withdrawal (contract C1).
    io.err(`The custodian did not record the withdrawal: ${e.code}: ${text(e.message)}`);
    io.err("This commit recorded nothing.");
    return "refused";
  }
  if (out.confirmationId !== prepared.facts.confirmationId) {
    io.err(`The custodian's answer names another confirmation (${text(out.confirmationId)}): treat it as not recorded and check with fix show.`);
    return "unknown";
  }
  io.out(`Withdrawn by the custodian: delegated fix ${text(prepared.facts.operationId)} of run ${text(prepared.facts.runId)}, confirmation ${text(out.confirmationId)} (rendering ${text(out.renderingDigest)}), at ${text(out.withdrawnAt)} (assurance ${hostOperatorAssurance()}).`);
  io.out("It can never be applied: an apply_fix of it is refused, also after a restart, a new configuration or a resumed session.");
  io.out("Not undone: nothing was applied by it, so no file changed; a fix applied earlier stays as it is; the run, the repository's configuration and every other fix are unchanged.");
  return "withdrawn";
}

/** The direct form: `fix withdraw <run-id> <proposal> --repo <path>`. Exit 0 withdrawn or already withdrawn; 1 refused;
 * 2 not recorded (cancelled) or an older custodian; 4 the outcome is unknown (the answer was lost). */
export async function runFixWithdraw(transport: CustodianTransport, io: CliIo, refs: string[], repo: string | undefined): Promise<number> {
  const runId = (refs[0] ?? "").trim().toLowerCase();
  const proposal = refs[1];
  if (!isUuid(runId)) throw new DomainError("INVALID_ARGUMENT", "give the full run id (as fix show prints it): code-parley fix withdraw <run-id> <proposal> --repo <path>");
  if (!proposal) throw new DomainError("INVALID_ARGUMENT", `name the fix: code-parley fix withdraw ${runId} <proposal> --repo <path>`);
  if (!repo) throw new DomainError("INVALID_ARGUMENT", `name the run's repository: code-parley fix withdraw ${runId} ${proposal} --repo <path> (the custodian holds the run under that repository's identity)`);
  if (!io.interactive || !io.prompt) throw new DomainError("INTERACTIVE_TERMINAL_REQUIRED", FIX_WITHDRAW_NOT_INTERACTIVE);
  const outcome = await withdrawOnce(transport, io, io.prompt, () => prepareFixWithdrawal(transport, repo, runId, proposal), { runId, operationId: proposal });
  switch (outcome) {
    case "withdrawn":
    case "already":
      return 0;
    case "unknown":
      return 4;
    case "not_recorded":
    case "old_custodian":
      return 2;
    case "refused":
      return 1;
  }
}

/** The guided form, from `fix review`: one listed, withdrawable fix. The choice is offered first; nothing is prepared on
 * "leave". */
export async function withdrawListed(transport: CustodianTransport, io: CliIo, prompt: (q: string) => Promise<string>, entry: FixListingEntry): Promise<WithdrawOutcome | "left"> {
  io.out(`Delegated fix ${text(entry.operationId)} of run ${text(entry.runId)} is confirmed and waiting for the session to apply it${entry.confirmationExpiresAt ? ` (until ${text(entry.confirmationExpiresAt)})` : ""}.`);
  io.out(`  confirmation ${text(entry.confirmationId ?? "-")}, confirmed rendering ${text(entry.confirmedRenderingDigest ?? "-")}`);
  for (let i = 0; i < 5; i++) {
    const c = (await prompt("[w]ithdraw this confirmation  [l]eave it: ")).trim().toLowerCase();
    if (c === "l" || c === "leave" || c === "") {
      io.out("Left as it is: nothing was sent.");
      return "left";
    }
    if (c === "w" || c === "withdraw") {
      return withdrawOnce(transport, io, prompt, () => prepareGuidedFixWithdrawal(transport, entry), {
        repoKey: entry.repoKey, runId: entry.runId, operationId: entry.operationId, confirmationId: entry.confirmationId ?? "", proposalDigest: entry.proposalDigest, renderingDigest: entry.confirmedRenderingDigest ?? "",
      });
    }
  }
  return "left";
}
