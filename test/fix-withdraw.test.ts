// POST-1 Fix Withdraw (contract revision 2): `code-parley fix withdraw` and the withdrawal offered by `fix review`, against the
// simulated custodian with the real engine (a delegated fix proposed by the fake fixer and confirmed at the operator terminal),
// and with a transport that alters the custodian's answers for the cases a correct custodian never produces. The custodian's
// side (the state machine, the races, the limits) is in the shared run corpus; both real custodians run it too.
import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { runCli, type CliIo } from "../src/cli/cli.js";
import { preparedWithdrawalMismatch } from "../src/cli/fix-withdraw.js";
import { applyFix } from "../src/engine/fix-apply.js";
import { delegateFix } from "../src/engine/fix-operation.js";
import type { CustodianOp, CustodianResponse, CustodianSurface } from "../src/custodian/protocol.js";
import type { CustodianTransport } from "../src/custodian/transport.js";
import type { PreparedFixWithdrawal } from "../src/custodian/operator.js";
import { supported } from "./helpers/git-fixture.js";
import { MATH_V1 } from "./helpers/review-fixture.js";
import type { ContFixture } from "./helpers/continuation-fixture.js";
import { TASK, confirmFix, editing, protectedRun, storeFixSelfTest_ } from "./helpers/delegated-fix.js";
import type { RunHandle } from "../src/engine/engine-env.js";

const BOUND = { timeout: 240_000 };

/** A scripted operator at an interactive terminal. */
function terminal(answer: (question: string) => string | Promise<string>, interactive = true) {
  const lines: string[] = [];
  const errors: string[] = [];
  const questions: string[] = [];
  const io: CliIo & { lines: string[]; errors: string[]; questions: string[] } = {
    lines, errors, questions, interactive, env: process.env, cwd: process.cwd(), terminalSize: () => ({ columns: 120, rows: 400 }),
    out: (l) => lines.push(l), err: (l) => errors.push(l),
    prompt: interactive ? async (q) => {
      questions.push(q);
      if (questions.length > 100) throw new Error(`the terminal script ran away at: ${q}`);
      return answer(q);
    } : null,
  };
  return io;
}

const script = (...answers: string[]) => (q: string) => {
  const a = answers.shift();
  if (a === undefined) throw new Error(`no scripted answer for: ${q}`);
  return a;
};

const hooks = (f: ContFixture, transport?: CustodianTransport) =>
  transport ? { ...f.le.env.testHooks!, custodian: { ...f.le.env.testHooks!.custodian!, transport } } : f.le.env.testHooks!;

const cli = (f: ContFixture, args: string[], io: CliIo, transport?: CustodianTransport) =>
  runCli([...args, "--home", f.dataHome, "--git", f.git], { ...io, engineTestHooks: hooks(f, transport) });

const withdraw = (f: ContFixture, run: RunHandle, op: string, io: CliIo, transport?: CustodianTransport) => cli(f, ["fix", "withdraw", run.runId, op, "--repo", f.repo], io, transport);

const sent = (f: ContFixture, op: CustodianOp) => f.custodian.received.filter((r) => r.op === op).length;
const math = (f: ContFixture): Promise<string> => readFile(join(f.repo, "src", "math.js"), "utf8");

/** A transport that passes requests to `inner` and lets a test change the answer to one operation. */
function altered(inner: CustodianTransport, op: CustodianOp, change: (res: CustodianResponse) => CustodianResponse): CustodianTransport {
  return { send: async (surface: CustodianSurface, o: CustodianOp, args: Record<string, unknown>, requestId: string) => {
    const res = await inner.send(surface, o, args, requestId);
    return o === op ? change(structuredClone(res)) : res;
  } } as CustodianTransport;
}

/** A delegated fix proposed and confirmed by the owner at the operator terminal (`fix confirm`). */
async function confirmed(): Promise<{ f: ContFixture; run: RunHandle; op: string; before: string }> {
  const { f, run } = await protectedRun(2);
  await storeFixSelfTest_(f);
  await confirmFix(f);
  const r = await delegateFix(f.le, run, TASK, { launch: editing("src/math.js", MATH_V1) });
  expect(r.status, r.detail ?? "").toBe("proposed");
  const before = await math(f);
  const io = terminal(script("confirm"));
  expect(await cli(f, ["fix", "confirm", run.runId, r.operation_id, "--repo", f.repo], io), io.errors.join(" | ")).toBe(0);
  return { f, run, op: r.operation_id, before };
}

describe.skipIf(!supported)("POST-1 Fix Withdraw: fix withdraw and fix review (simulated custodian, real engine)", BOUND, () => {
  it("W1, W2: the direct withdrawal shows the custodian's statement, records only the typed word, and apply_fix is then refused; nothing is written", async () => {
    const { f, run, op, before } = await confirmed();
    const io = terminal(script("withdraw"));
    expect(await withdraw(f, run, op, io), io.errors.join(" | ")).toBe(0);
    const out = io.lines.join("\n");
    expect(out).toContain("The CodeParley custodian prepared this withdrawal (nothing is recorded until you type it):");
    expect(out).toContain(`Withdraw the confirmation of delegated fix ${op} of run ${run.runId}:`);
    expect(out).toContain("A fix applied earlier is not reverted.");
    expect(out).toMatch(/Withdrawn by the custodian: delegated fix .* confirmation [0-9a-f-]{36} \(rendering [0-9a-f]{64}\)/);
    expect(out).toContain("Not undone: nothing was applied by it, so no file changed");
    // The direct form names no confirmation: the custodian selects and binds it.
    const prepare = f.custodian.received.find((r) => r.op === "prepare_fix_withdrawal")!;
    expect(Object.keys(prepare.args).sort()).toEqual(["operationId", "repositoryRoot", "runId"]);
    await expect(applyFix(f.le, run, { proposal_id: op })).rejects.toThrow(/CONFIRMATION_WITHDRAWN|withdrew/);
    expect(await math(f)).toBe(before);
    // W4 (C1): a withdrawal observed at prepare: already withdrawn, exit 0, nothing prepared or committed.
    const commits = sent(f, "commit");
    const again = terminal(script());
    expect(await withdraw(f, run, op, again), again.errors.join(" | ")).toBe(0);
    expect(again.lines.join("\n")).toMatch(/^Already withdrawn: delegated fix .* is already withdrawn/m);
    expect(again.questions).toEqual([]);
    expect(sent(f, "commit")).toBe(commits);
  });

  it("W12: a word other than withdraw records nothing (exit 2) and the fix stays applicable; a non-interactive terminal is refused before anything is sent", async () => {
    const { f, run, op } = await confirmed();
    const io = terminal(script("yes"));
    expect(await withdraw(f, run, op, io)).toBe(2);
    expect(io.lines.join("\n")).toContain("Not recorded (the prepared withdrawal expires unused).");
    const prepares = sent(f, "prepare_fix_withdrawal");
    const batch = terminal(script(), false);
    expect(await withdraw(f, run, op, batch)).not.toBe(0);
    expect(batch.errors.join("\n")).toMatch(/interactive terminal/);
    expect(sent(f, "prepare_fix_withdrawal")).toBe(prepares);
    const applied = await applyFix(f.le, run, { proposal_id: op });
    expect(applied.status, JSON.stringify(applied)).toBe("applied");
    expect(await math(f)).toBe(MATH_V1);
    // W7: an applied fix cannot be withdrawn; the refusal says its files stay (a withdrawal never reverts files).
    const late = terminal(script());
    expect(await withdraw(f, run, op, late)).toBe(1);
    expect(late.errors.join("\n")).toMatch(/CONFIRMATION_CONSUMED: .*Its files stay as they are \(a withdrawal never reverts files\)/);
    expect(await math(f)).toBe(MATH_V1);
  });

  it("W17 (C1): a withdrawal committed elsewhere between this prepare and its commit: the commit refuses (exit 1) and says it recorded nothing", async () => {
    const { f, run, op } = await confirmed();
    const io = terminal(async () => {
      // Another operator terminal withdraws the same fix while this one waits for its word.
      const rid = "other-withdrawal";
      const p = await f.custodian.send("operator", "prepare_fix_withdrawal", { repositoryRoot: f.repo, runId: run.runId, operationId: op }, rid);
      expect(p.ok).toBe(true);
      expect((await f.custodian.send("operator", "commit", { authorizationRequestId: rid }, "other-commit")).ok).toBe(true);
      return "withdraw";
    });
    expect(await withdraw(f, run, op, io)).toBe(1);
    expect(io.errors.join("\n")).toMatch(/CONFIRMATION_WITHDRAWN: .*by another withdrawal since this one was prepared; this commit recorded nothing/);
    expect(io.errors.join("\n")).toContain("This commit recorded nothing.");
    expect(io.lines.join("\n")).not.toContain("Withdrawn by the custodian");
  });

  it("W12 (C1): the commit's answer is lost: exit 4, nothing is sent again, and the operator is told how to check", async () => {
    const { f, run, op } = await confirmed();
    const io = terminal(() => {
      f.custodian.failNext("commit", "lost_response");
      return "withdraw";
    });
    const commits = sent(f, "commit");
    expect(await withdraw(f, run, op, io)).toBe(4);
    expect(io.errors.join("\n")).toMatch(/answer was lost after the withdrawal was sent: CodeParley does not know whether it was recorded and does not send it again/);
    expect(sent(f, "commit")).toBe(commits + 1);
    // The custodian did record it (the connection broke after): fix show reports it.
    await expect(applyFix(f.le, run, { proposal_id: op })).rejects.toThrow(/CONFIRMATION_WITHDRAWN|withdrew/);
  });

  it("an older custodian (UNKNOWN_OPERATION): the run-end recovery is named, exit 2, nothing recorded", async () => {
    const { f, run, op } = await confirmed();
    const old = altered(f.custodian, "prepare_fix_withdrawal", () => ({ ok: false, code: "UNKNOWN_OPERATION", error: "unknown operation 'prepare_fix_withdrawal'" }));
    const commits = sent(f, "commit");
    const io = terminal(script());
    expect(await withdraw(f, run, op, io, old)).toBe(2);
    expect(io.errors.join("\n")).toContain("This custodian predates `fix withdraw`. Ending the run");
    expect(sent(f, "commit")).toBe(commits);
    expect(io.questions).toEqual([]);
  });

  it("W10: the implementer surface cannot prepare a withdrawal (CALLER_NOT_AUTHORIZED), nor commit one", async () => {
    const { f, run, op } = await confirmed();
    const r = await f.custodian.send("implementer", "prepare_fix_withdrawal", { repositoryRoot: f.repo, runId: run.runId, operationId: op }, "impl-withdraw");
    expect(r).toMatchObject({ ok: false, code: "CALLER_NOT_AUTHORIZED" });
    const p = await f.custodian.send("operator", "prepare_fix_withdrawal", { repositoryRoot: f.repo, runId: run.runId, operationId: op }, "op-withdraw");
    expect(p.ok).toBe(true);
    expect(await f.custodian.send("implementer", "commit", { authorizationRequestId: "op-withdraw" }, "impl-commit")).toMatchObject({ ok: false, code: "CALLER_NOT_AUTHORIZED" });
    const applied = await applyFix(f.le, run, { proposal_id: op });
    expect(applied.status, JSON.stringify(applied)).toBe("applied");
  });

  it("the guided withdrawal (fix review): a confirmed fix is listed by number, offers withdraw or leave, names all four expected values, and apply_fix is then refused", async () => {
    const { f, run, op, before } = await confirmed();
    // Leave first: nothing prepared.
    const io1 = terminal(script("1", "l", "q"));
    expect(await cli(f, ["fix", "review"], io1), io1.errors.join(" | ")).toBe(0);
    expect(io1.lines.join("\n")).toMatch(/^ +1 {2}.*confirmed, waiting for the session to apply it.*; you can withdraw it/m);
    expect(sent(f, "prepare_fix_withdrawal")).toBe(0);
    const io = terminal(script("1", "w", "withdraw", "q"));
    expect(await cli(f, ["fix", "review"], io), io.errors.join(" | ")).toBe(0);
    expect(io.lines.join("\n")).toMatch(/Withdrawn by the custodian: delegated fix /);
    const prepare = f.custodian.received.find((r) => r.op === "prepare_fix_withdrawal")!;
    expect(Object.keys(prepare.args).filter((k) => k.startsWith("expected")).sort()).toEqual(["expectedConfirmationId", "expectedProposalDigest", "expectedRenderingDigest", "expectedRepoKey"]);
    // After the withdrawal the listing no longer offers it.
    expect(io.lines.join("\n")).toMatch(/No delegated fix is waiting for your decision\./);
    await expect(applyFix(f.le, run, { proposal_id: op })).rejects.toThrow(/CONFIRMATION_WITHDRAWN|withdrew/);
    expect(await math(f)).toBe(before);
  });

  it("the guided withdrawal refuses a prepared withdrawal that is not the one selected; nothing is committed", async () => {
    const { f, run, op } = await confirmed();
    const swapped = altered(f.custodian, "prepare_fix_withdrawal", (res) => {
      const facts = (res.data as Record<string, unknown>)["fixWithdrawal"] as Record<string, unknown>;
      facts["confirmationId"] = "00000000-0000-4000-8000-000000000009";
      return res;
    });
    const commits = sent(f, "commit");
    const io = terminal(script("1", "w", "q"));
    expect(await cli(f, ["fix", "review"], io, swapped), io.errors.join(" | ")).toBe(0);
    expect(io.errors.join("\n")).toContain("The prepared withdrawal is not the one you selected (another confirmation)");
    expect(sent(f, "commit")).toBe(commits);
    const applied = await applyFix(f.le, run, { proposal_id: op });
    expect(applied.status, JSON.stringify(applied)).toBe("applied");
  });
});

describe("POST-1 Fix Withdraw: the prepared withdrawal's check (unit)", () => {
  const prepared = (over: Record<string, unknown> = {}, rendering = "Withdraw the confirmation of delegated fix fop-1 of run r:\n"): PreparedFixWithdrawal => ({
    authorizationRequestId: "a", rendering, expiresAt: "t",
    facts: { repoKey: "k", repositoryRoot: null, runId: "r", operationId: "fop-1", confirmationId: "c", proposalDigest: "p", renderingDigest: "d", confirmationExpiresAt: null, alreadyNotApplicable: false, ...over } as PreparedFixWithdrawal["facts"],
  });
  const want = { repoKey: "k", runId: "r", operationId: "fop-1", confirmationId: "c", proposalDigest: "p", renderingDigest: "d" };
  it("each selected identity must be the prepared one; an unescaped control in the statement is refused", () => {
    expect(preparedWithdrawalMismatch(prepared(), want)).toBeNull();
    expect(preparedWithdrawalMismatch(prepared({ repoKey: "x" }), want)).toBe("another repository identity");
    expect(preparedWithdrawalMismatch(prepared({ operationId: "fop-2" }), want)).toBe("another run or fix");
    expect(preparedWithdrawalMismatch(prepared({ confirmationId: "z" }), want)).toBe("another confirmation");
    expect(preparedWithdrawalMismatch(prepared({ proposalDigest: "z" }), want)).toBe("another proposal");
    expect(preparedWithdrawalMismatch(prepared({ renderingDigest: "z" }), want)).toBe("another confirmed rendering");
    expect(preparedWithdrawalMismatch(prepared({}, "Withdraw \u001b[2J now\n"), want)).toBe("its statement holds an unescaped character");
    // The direct form names only the run and the fix.
    expect(preparedWithdrawalMismatch(prepared({ confirmationId: "anything" }), { runId: "r", operationId: "fop-1" })).toBeNull();
  });
});
