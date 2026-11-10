// Step 7.2 (S1 status clarity; F-S71-2, O-1; TD STEP-7.2-CONTRACT-CONDITIONAL-PASS): `status` and `setup` count an S1 or
// FIX confirmation as current only for the stored self-test protected execution would use, judged with the execution
// path's own functions; what this account cannot read is `unverified` (not established), never ready or misconfigured.
//
//   T1–T10  the S1 and FIX rows, one case each (unit, with the evidence the production observation produces);
//   T9      observeStoredSelfTests: inaccessible, not compared, probe failure, Linux operator by design;
//   T11     the agreement table: on the simulated custodian, every row's "in force" equals the enforcement's decision;
//   T12     F-S71-2 end to end: S1 and FIX re-runs, a missing record, revocation, lapse, S2, setup's confirmations;
//   T13     Q4: an explicit Codex or backend protected execution cannot use is refused before anything is recorded;
//   T14     the Linux proposal handoff (which proposals the custodian already holds) and setup's exit 3;
//   T15     O-1: a re-confirmation refused CONFIG_MISMATCH is not retried; setup offers `config set` (typed);
//   T16     layering: the status module imports no fixer module; the FIX reader is the CLI's.
//
// Evidence class: simulation (the native VMs run the real custodians).

import { describe, it, expect } from "vitest";
import { chmod, copyFile, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { doctorOutcome, runCli } from "../src/cli/cli.js";
import { proposalConfirmed } from "../src/cli/setup-commands.js";
import { remedyFor } from "../src/common/remedies.js";
import { observeStoredSelfTests, repositoryRecords, repositoryStateOf, type FixEvidence, type Observed, type RecordState, type S1Evidence } from "../src/engine/protected-status.js";
import { confirmedFixSelfTest, confirmedSelfTest, heldAcceptanceApplies, protectedIsolationDecision, reviewBackends, selfTestRecordDigest, storedS1SelfTest } from "../src/engine/protected-config.js";
import { storedFixSelfTest, fixBackendFor } from "../src/engine/fix-confirmation.js";
import { probeCodex } from "../src/agents/codex/probe.js";
import { configSectionOf, CustodianGrants } from "../src/custodian/grants.js";
import { CONFIG_VIEW_RUN, type ConfigSection, type HeldAcceptance, type HeldSelftestConfirmation } from "../src/custodian/protocol.js";
import type { SelfTestRecord } from "../src/schemas/review.js";
import { REDUCED_ISOLATION_STATEMENT_SHA256, type IsolationDecision } from "../src/agents/codex/isolation.js";
import { compatRowFor } from "../src/agents/codex/compat.js";
import type { CodexProbe } from "../src/agents/codex/probe.js";
import { fixEvidenceReader } from "../src/cli/status-fix-evidence.js";
import { backendsFor, type SandboxBackend } from "../src/agents/codex/argv.js";
import type { Loaded } from "../src/engine/engine-env.js";
import { supported } from "./helpers/git-fixture.js";
import { okScenario, output } from "./helpers/review-fixture.js";
import { cli, contFixture, fixtureBackend, operatorIo, storeFixtureSelfTest, syntheticRuntime, SYNTHETIC_RUNTIME_GIT, type ContFixture } from "./helpers/continuation-fixture.js";
import { storeFixSelfTest, fixSelfTestKey } from "../src/agents/codex/fix-selftest.js";
import { fixProfileDigest } from "../src/agents/codex/fix-profile.js";
import { fixProfileFor } from "../src/engine/fix-confirmation.js";
import { storeLayout } from "../src/store/paths.js";
import { sha } from "./helpers/delegated-fix.js";
import { spawnSync } from "node:child_process";
import { doctorExitCode, type ProtectedDoctorFacts } from "../src/engine/doctor.js";

// ---------------------------------------------------------------------------
// Unit: the rows against the evidence (T1–T10)
// ---------------------------------------------------------------------------

const H = (c: string) => c.repeat(64);
const rec = (over: Partial<SelfTestRecord> = {}): SelfTestRecord => ({
  schema: "arl.codex-selftest.v1", selftest_id: "st-1", key: H("a"), codex_version: "0.160.0", backend: "mxc", mode: "S1", profile_digest: H("b"), created_at: "2026-11-07T00:00:00Z",
  profile_runs: true, rejection_reason: null, rows: [], s1_available: true, complete: true, ...over,
});
const conf = (r: SelfTestRecord, over: Partial<HeldSelftestConfirmation> = {}): HeldSelftestConfirmation => ({
  confirmationId: "c-1", globalRevision: 1, recordedAt: "t", selftestId: r.selftest_id, codexVersion: r.codex_version, backend: r.backend, mode: "S1", profileDigest: r.profile_digest,
  s1Available: true, rowsSummary: { total: 1, passed: 1, failed: [] }, recordDigest: selfTestRecordDigest(r), revoked: false, lapsed: false, lapsedAtRecoveryId: null, usable: true, ...over,
});
const fixConf = (over: Partial<HeldSelftestConfirmation> = {}): HeldSelftestConfirmation => ({
  confirmationId: "f-1", globalRevision: 1, recordedAt: "t", selftestId: "fx-1", codexVersion: "0.160.0", backend: "mxc", mode: "FIX", profileDigest: H("c"), s1Available: true,
  rowsSummary: { total: 1, passed: 1, failed: [] }, recordDigest: H("d"), codexSha256: H("e"), revoked: false, lapsed: false, lapsedAtRecoveryId: null, usable: true, ...over,
});
const acceptance = (over: Partial<HeldAcceptance> = {}): HeldAcceptance => ({ acceptanceId: "a-1", globalRevision: 1, recordedAt: "t", accepted: ["unrestricted_reads", "advisory_network"], backend: "mxc", codexVersionRange: "0.160", statementSha256: H("f"), revoked: false, lapsed: false, lapsedAtRecoveryId: null, usable: true, ...over });
const installation = { path: "C:\\codex\\codex.exe", form: "native_pe", fileId: "1-2", size: 10, sha256: H("9") };
const repository = { configRevision: 1, recordedAt: "t", usable: true, revoked: false, lapsed: false, lapsedAtRecoveryId: null, codexInstallation: installation } as unknown as NonNullable<ConfigSection["repository"]>;
const section = (selftestConfirmations: HeldSelftestConfirmation[], acceptances: HeldAcceptance[] = []): ConfigSection => ({ globalRevision: 1, repository, acceptances, selftestConfirmations, engineRuntime: null });

/** The review's decision for the evidence: S1 when a stored record is covered by a usable confirmation, else S2 by an
 * acceptance (as decideIsolation), else refused. */
const decisionFor = (s: ConfigSection, recs: (SelfTestRecord | null)[], backends: string[]): IsolationDecision => {
  for (const r of recs) if (r && r.s1_available && r.profile_runs && confirmedSelfTest(s, r)) return { ok: true, isolation: { mode: "S1", backend: r.backend, selftest_id: r.selftest_id, acceptance_id: null } } as unknown as IsolationDecision;
  const a = s.acceptances.find((x) => x.usable && backends.includes(x.backend));
  if (a) return { ok: true, isolation: { mode: "S2", backend: a.backend, selftest_id: null, acceptance_id: a.acceptanceId } } as unknown as IsolationDecision;
  return { ok: false, reasons: ["refused"], missingSelfTests: [] };
};
const s1ev = (s: ConfigSection, stored: (SelfTestRecord | null)[], backends = ["mxc"], codexVersion = "0.160.0"): Observed<S1Evidence> => ({
  ok: true, value: { codexVersion, backends: backends as SandboxBackend[], stored: backends.map((b, i) => ({ backend: b as SandboxBackend, record: stored[i] ?? null })), decision: decisionFor(s, stored, backends) },
});
const fixev = (local: FixEvidence["local"], why: string | null = null): Observed<FixEvidence> => ({ ok: true, value: { codexVersion: "0.160.0", backend: "mxc", local, why } });
const rows = async (s: ConfigSection, o: { s1?: Observed<S1Evidence>; fix?: Observed<FixEvidence>; platform?: NodeJS.Platform } = {}) =>
  repositoryRecords({ platform: o.platform ?? "win32", root: "C:\\r", repoKey: "k", section: s, grants: [], hashFile: async () => installation.sha256, nowMs: Date.now(), exists: async () => true, implementerHome: "C:\\impl", ...(o.s1 ? { s1: o.s1 } : {}), ...(o.fix ? { fix: o.fix } : {}) });
const row = async (s: ConfigSection, name: RecordState["record"], o: Parameters<typeof rows>[1] = {}) => (await rows(s, o)).find((r) => r.record === name)!;

describe("Step 7.2 — the S1 row against the stored record a protected review uses (T1–T7, T10)", () => {
  it("T1: an S1 self-test re-run under the same key after its confirmation is unconfirmed, not in force (F-S71-2)", async () => {
    const old = rec({ selftest_id: "st-old" });
    const now = rec({ selftest_id: "st-new" });
    const s = section([conf(old)]);
    expect(await row(s, "isolation", { s1: s1ev(s, [old]) })).toMatchObject({ state: "in_force", detail: expect.stringContaining("covers the stored self-test st-old") });
    const r = await row(s, "isolation", { s1: s1ev(s, [now]) });
    expect(r).toMatchObject({ state: "unconfirmed", reason: "record_changed", resumable: true, required: true, restore: 'code-parley setup --resume --repo C:\\r --home "C:\\impl"' });
    expect(r.detail).toMatch(/stored S1 self-test st-new .* is not the one confirmed \(confirmation c-1 covers self-test st-old/);
    expect(r.detail).toContain("CODEX_ISOLATION_UNAVAILABLE");
    expect(repositoryStateOf(await rows(s, { s1: s1ev(s, [now]) }))).toBe("misconfigured");
    // Linux: the implementer proposes the stored record; the operator confirms it (no new self-test needed).
    expect((await row(s, "isolation", { s1: s1ev(s, [now]), platform: "linux" })).restore).toBe("the implementer: code-parley config propose-selftest --repo C:\\r --out <file>; then /usr/local/sbin/code-parley-operator setup --resume --repo C:\\r --proposal-file <file>");
  });

  it("T2/T9b: a missing local record is unconfirmed (record_missing) and names the self-test to run; a failed one record_failed", async () => {
    const old = rec();
    const s = section([conf(old)]);
    expect(await row(s, "isolation", { s1: s1ev(s, [null]) })).toMatchObject({ state: "unconfirmed", reason: "record_missing", restore: expect.stringMatching(/^the implementer: code-parley codex selftest --backend mxc in an interactive desktop session; then code-parley setup --resume/) });
    expect(await row(s, "isolation", { s1: s1ev(s, [rec({ selftest_id: "st-2", s1_available: false })]) })).toMatchObject({ state: "unconfirmed", reason: "record_failed" });
  });

  it("T3: a Codex update (another version: no stored record for it) and another binary are not in force", async () => {
    const old = rec();
    const s = section([conf(old)]);
    const r = await row(s, "isolation", { s1: s1ev(s, [null], ["mxc"], "0.161.0") });
    expect(r).toMatchObject({ state: "unconfirmed", reason: "record_missing", detail: expect.stringContaining("Codex 0.161.0") });
    // FIX: the same version, another binary — the delegation's predicate (binary SHA-256) does not hold.
    const f = section([fixConf()]);
    expect(await row(f, "fix_confirmation", { fix: fixev({ selftestId: "fx-1", codexSha256: H("7"), profileDigest: H("c") }) })).toMatchObject({ state: "unconfirmed", reason: "record_changed", required: false });
  });

  it("T4: a backend or profile other than the confirmed one is unconfirmed (the review's backends decide)", async () => {
    const old = rec();
    const s = section([conf(old)]);
    expect(await row(s, "isolation", { s1: s1ev(s, [rec({ backend: "elevated" })], ["elevated"]) })).toMatchObject({ state: "unconfirmed", reason: "record_changed" });
    expect(await row(s, "isolation", { s1: s1ev(s, [rec({ profile_digest: H("8") })]) })).toMatchObject({ state: "unconfirmed", reason: "record_changed" });
  });

  it("T5: revocation is kept: the stored record's revoked confirmation is revoked (not resumable), even beside a usable non-matching one", async () => {
    const r1 = rec();
    const only = section([conf(r1, { revoked: true, usable: false })]);
    expect(await row(only, "isolation", { s1: s1ev(only, [r1]) })).toMatchObject({ state: "revoked", resumable: false, restore: 'code-parley setup --repo C:\\r --home "C:\\impl"' });
    const beside = section([conf(r1, { revoked: true, usable: false }), conf(rec({ selftest_id: "st-other" }), { confirmationId: "c-2" })]);
    expect(await row(beside, "isolation", { s1: s1ev(beside, [r1]) })).toMatchObject({ state: "revoked", resumable: false });
    // Without any stored record, revocations only: revoked (as the custodian reports), never in force.
    expect(await row(only, "isolation", { s1: s1ev(only, [null]) })).toMatchObject({ state: "revoked" });
  });

  it("T6: the stored record's lapsed confirmation is lapsed (resume re-confirms it); a lapsed one of another record is unconfirmed", async () => {
    const r1 = rec();
    const s = section([conf(r1, { lapsed: true, usable: false, lapsedAtRecoveryId: "rec-1" })]);
    expect(await row(s, "isolation", { s1: s1ev(s, [r1]) })).toMatchObject({ state: "lapsed", resumable: true });
    expect(await row(s, "isolation", { s1: s1ev(s, [rec({ selftest_id: "st-new" })]) })).toMatchObject({ state: "unconfirmed", reason: "record_changed" });
  });

  it("T7: explicitly accepted S2 is in force only where the review would use it, with the S1 state named beside it", async () => {
    const s = section([conf(rec({ selftest_id: "st-old" }))], [acceptance()]);
    const r = await row(s, "isolation", { s1: s1ev(s, [rec({ selftest_id: "st-new" })]) });
    expect(r).toMatchObject({ state: "in_force", detail: expect.stringMatching(/^reduced isolation \(S2\): the operator's acceptance a-1 for mxc; S1 is not established \(the stored S1 self-test st-new/) });
    // An acceptance for another backend is not used by the review: not in force.
    const other = section([conf(rec({ selftest_id: "st-old" }))], [acceptance({ backend: "elevated" })]);
    expect(await row(other, "isolation", { s1: s1ev(other, [rec({ selftest_id: "st-new" })]) })).toMatchObject({ state: "unconfirmed" });
    // Not compared from this account, but the review would use S2 anyway: in force by the acceptance, said so.
    const nc: Observed<S1Evidence> = { ok: false, reason: "not_compared", why: "x", verify: "v", s2: { acceptanceId: "a-1", backend: "mxc" } };
    expect(await row(s, "isolation", { s1: nc })).toMatchObject({ state: "in_force", detail: expect.stringContaining("whether a confirmed S1 self-test applies was not compared") });
  });

  it("T10: older or partial custodian responses never read as in force", async () => {
    // A FIX confirmation without codexSha256 (before Phase 4 Increment 2): the delegation's predicate cannot hold.
    const f = section([fixConf({ codexSha256: undefined } as Partial<HeldSelftestConfirmation>)]);
    expect(await row(f, "fix_confirmation", { fix: fixev({ selftestId: "fx-1", codexSha256: H("e"), profileDigest: H("c") }) })).toMatchObject({ state: "unconfirmed" });
    // A confirmation of an unknown mode is never an S1 basis.
    const r1 = rec();
    const m = section([conf(r1, { mode: "S9" })]);
    expect((await row(m, "isolation", { s1: s1ev(m, [r1]) })).state).not.toBe("in_force");
    // A section whose confirmations lack recordDigest is refused whole (status: unknown), as before.
    expect(configSectionOf({ globalRevision: 1, repository: null, acceptances: [], selftestConfirmations: [{ confirmationId: "x", usable: true }] })).toBeNull();
    // No engineRuntime (a custodian before P3.4C-5): the engine runtime row is missing, as before.
    expect((await rows(section([]))).find((x) => x.record === "engine_runtime")).toMatchObject({ state: "missing" });
  });
});

// Review finding #10: the evidence with the review's REAL isolation decision (protectedIsolationDecision over the held
// acceptances, the current statement digest and the compatibility row), so a lapse counts only where enforcement would
// rest on the record it names.
const probeFor = (version = "0.160.0"): CodexProbe => ({ compat: compatRowFor(version, "win32")!, version, installDir: "C:\\codex", userHooksPresent: false }) as unknown as CodexProbe;
const s1evReal = (s: ConfigSection, stored: (SelfTestRecord | null)[], backends: SandboxBackend[] = ["mxc"], codexVersion = "0.160.0"): Observed<S1Evidence> => {
  const selfTests = new Map(backends.map((b, i) => [b, stored[i] && confirmedSelfTest(s, stored[i]!) ? stored[i]! : null] as const));
  return { ok: true, value: { codexVersion, backends, stored: backends.map((b, i) => ({ backend: b, record: stored[i] ?? null })), decision: protectedIsolationDecision(s, probeFor(codexVersion), backends, selfTests) } };
};
const realAcceptance = (over: Partial<HeldAcceptance> = {}): HeldAcceptance => acceptance({ statementSha256: REDUCED_ISOLATION_STATEMENT_SHA256, ...over });
const lapsedOf = (a: HeldAcceptance): HeldAcceptance => ({ ...a, lapsed: true, usable: false, lapsedAtRecoveryId: "rec-1" });

describe("Step 7.2 — review finding #10: a revocation is never masked by a lapse of another record", () => {
  // Acceptances the review on mxc with Codex 0.160.0 does not rest on (the decision's own rule), and one it does.
  const inapplicable: [string, HeldAcceptance][] = [
    ["another backend", realAcceptance({ backend: "elevated" })],
    ["another Codex version range", realAcceptance({ codexVersionRange: "0.159" })],
    ["an earlier statement", realAcceptance({ statementSha256: H("f") })],
    ["one accepted capability only", realAcceptance({ accepted: ["unrestricted_reads"] })],
  ];
  const applicable = realAcceptance();

  it("the stored record's revoked confirmation stays revoked beside an unrelated or an applicable lapsed acceptance (setup --resume never restores it)", async () => {
    const r1 = rec();
    for (const [what, a] of [...inapplicable, ["the review's own", applicable] as [string, HeldAcceptance]]) {
      const s = section([conf(r1, { revoked: true, usable: false })], [lapsedOf(a)]);
      expect(await row(s, "isolation", { s1: s1evReal(s, [r1]) }), what).toMatchObject({ state: "revoked", resumable: false, restore: 'code-parley setup --repo C:\\r --home "C:\\impl"' });
      expect(repositoryStateOf(await rows(s, { s1: s1evReal(s, [r1]) })), what).toBe("misconfigured");
    }
  });

  it("T6 kept: the stored record's own lapsed confirmation is lapsed, also beside another record's revoked one", async () => {
    const r1 = rec();
    const s = section([conf(r1, { lapsed: true, usable: false, lapsedAtRecoveryId: "rec-1" }), conf(rec({ selftest_id: "st-other" }), { confirmationId: "c-2", revoked: true, usable: false })]);
    expect(await row(s, "isolation", { s1: s1evReal(s, [r1]) })).toMatchObject({ state: "lapsed", resumable: true });
  });

  it("a lapsed acceptance counts as lapsed only if the review could rest on it; an inapplicable one leaves the S1 row unconfirmed", async () => {
    const stored = rec({ selftest_id: "st-new" });
    const s = section([conf(rec({ selftest_id: "st-old" }))], [lapsedOf(applicable)]);
    expect(await row(s, "isolation", { s1: s1evReal(s, [stored]) })).toMatchObject({ state: "lapsed", resumable: true });
    for (const [what, a] of inapplicable) {
      const t = section([conf(rec({ selftest_id: "st-old" }))], [lapsedOf(a)]);
      expect(await row(t, "isolation", { s1: s1evReal(t, [stored]) }), what).toMatchObject({ state: "unconfirmed", reason: "record_changed", resumable: true });
    }
    // Another Codex version than the acceptance's range: inapplicable for this review, though the acceptance itself is fine.
    // (No compatibility row exists for 0.161.0, so the evidence's decision is the refusal any unsupported version gets.)
    expect(await row(s, "isolation", { s1: s1ev(s, [null], ["mxc"], "0.161.0") })).toMatchObject({ state: "unconfirmed", reason: "record_missing" });
  });

  it("agreement with the enforcement predicate: a lapsed acceptance reads lapsed exactly when, restored, the review's decision would rest on it", async () => {
    const stored = rec({ selftest_id: "st-new" });
    for (const [what, a] of [...inapplicable, ["the review's own", applicable] as [string, HeldAcceptance]]) {
      const lapsed = section([conf(rec({ selftest_id: "st-old" }))], [lapsedOf(a)]);
      const restored = section([conf(rec({ selftest_id: "st-old" }))], [a]);
      const decision = protectedIsolationDecision(restored, probeFor(), ["mxc"], new Map([["mxc", null]]));
      expect(heldAcceptanceApplies(lapsedOf(a), ["mxc"], "0.160.0"), what).toBe(decision.ok);
      expect((await row(lapsed, "isolation", { s1: s1evReal(lapsed, [stored]) })).state === "lapsed", what).toBe(decision.ok);
      // While lapsed the review refuses (CONFIG_LAPSED at the custodian): never in force.
      expect(protectedIsolationDecision(lapsed, probeFor(), ["mxc"], new Map([["mxc", null]])).ok, what).toBe(false);
      // Restored, status and the decision agree on in force.
      expect((await row(restored, "isolation", { s1: s1evReal(restored, [stored]) })).state === "in_force", what).toBe(decision.ok);
    }
    // A revoked acceptance never applies.
    expect(heldAcceptanceApplies({ ...applicable, revoked: true, usable: false }, ["mxc"], "0.160.0")).toBe(false);
  });

  it("not observed: a lapsed acceptance never masks a revoked S1 confirmation; alone it is lapsed (T6 kept)", async () => {
    const r1 = rec();
    const linux: Observed<S1Evidence> = { ok: false, reason: "store_inaccessible", why: "by design", verify: "the implementer: code-parley status --repo /r" };
    const revoked = section([conf(r1, { revoked: true, usable: false })], [lapsedOf(applicable)]);
    expect(await row(revoked, "isolation", { s1: linux, platform: "linux" })).toMatchObject({ state: "revoked", resumable: false });
    expect(await row(section([], [lapsedOf(applicable)]), "isolation", { s1: linux, platform: "linux" })).toMatchObject({ state: "lapsed", resumable: true });
    expect(await row(section([conf(r1, { lapsed: true, usable: false })], [lapsedOf(applicable)]), "isolation", { s1: linux, platform: "linux" })).toMatchObject({ state: "lapsed" });
  });
});

describe("Step 7.2 — the FIX row (T8) and the unverified rows (T9)", () => {
  it("T8: a FIX re-run is unconfirmed (optional: the repository's readiness is unaffected); its own lapse and revocation are kept", async () => {
    const local = { selftestId: "fx-1", codexSha256: H("e"), profileDigest: H("c") };
    const s = section([fixConf()]);
    expect(await row(s, "fix_confirmation", { fix: fixev(local) })).toMatchObject({ state: "in_force", detail: expect.stringContaining("covers the stored FIX self-test fx-1") });
    const rerun = await row(s, "fix_confirmation", { fix: fixev({ ...local, selftestId: "fx-2" }) });
    expect(rerun).toMatchObject({ state: "unconfirmed", reason: "record_changed", required: false, restore: 'code-parley setup --resume --repo C:\\r --fix --home "C:\\impl"' });
    expect(await row(s, "fix_confirmation", { fix: fixev(null, "no stored cp_fix self-test of Codex 0.160.0") })).toMatchObject({ state: "unconfirmed", reason: "record_missing", detail: expect.stringContaining("no stored cp_fix self-test") });
    expect(await row(section([fixConf({ lapsed: true, usable: false })]), "fix_confirmation", { fix: fixev(local) })).toMatchObject({ state: "lapsed" });
    expect(await row(section([fixConf({ revoked: true, usable: false })]), "fix_confirmation", { fix: fixev(local) })).toMatchObject({ state: "revoked", resumable: false });
    expect(await row(section([]), "fix_confirmation", { fix: fixev(local) })).toMatchObject({ state: "missing" });
  });

  it("T9: what this account cannot read is unverified with the command that compares it — the repository is unknown, never ready or misconfigured", async () => {
    const r1 = rec();
    const s = section([conf(r1), fixConf()]);
    const linux: Observed<S1Evidence> = { ok: false, reason: "store_inaccessible", why: "the implementer's self-test store is not readable from the operator account (by design)", verify: "the implementer: code-parley status --repo /r" };
    const all = await rows(s, { s1: linux, fix: linux as unknown as Observed<FixEvidence>, platform: "linux" });
    expect(all.find((x) => x.record === "isolation")).toMatchObject({ state: "unverified", reason: "store_inaccessible", restore: "the implementer: code-parley status --repo /r", resumable: false });
    expect(all.find((x) => x.record === "fix_confirmation")).toMatchObject({ state: "unverified", required: false });
    const inForce = (record: RecordState["record"]): RecordState => ({ record, state: "in_force", required: true, detail: "", restore: null, resumable: false });
    const selfTestRows = all.filter((x) => x.record === "isolation" || x.record === "fix_confirmation");
    expect(repositoryStateOf([inForce("engine_runtime"), inForce("repository"), ...selfTestRows])).toBe("unknown");
    // Not compared at all (no evidence): unverified too — never in force from the custodian's records alone.
    expect(await row(s, "isolation")).toMatchObject({ state: "unverified" });
    // Custodian-only facts need no local record: nothing usable at all is missing / lapsed as before.
    expect(await row(section([]), "isolation", { s1: linux })).toMatchObject({ state: "missing" });
    expect(await row(section([conf(r1, { lapsed: true, usable: false })]), "isolation", { s1: linux })).toMatchObject({ state: "lapsed" });
    // A known problem elsewhere decides: misconfigured, not unknown.
    expect(repositoryStateOf([{ record: "repository", state: "missing", required: true, detail: "", restore: null, resumable: false }, ...all])).toBe("misconfigured");
  });
});

// ---------------------------------------------------------------------------
// The observation itself, on the simulated custodian
// ---------------------------------------------------------------------------

function terminal(answers: string | string[] = "confirm") {
  const queue = Array.isArray(answers) ? [...answers] : null;
  const next = () => (queue ? (queue.shift() ?? "no") : (answers as string));
  const io = operatorIo("confirm");
  return { ...io, prompt: async (q: string) => { const a = next(); return /"allow"/.test(q) ? (a === "confirm" ? "allow" : a) : a; } };
}

async function setupArgs(f: ContFixture, backend = true): Promise<string[]> {
  return ["--codex", f.codexExe, ...(backend ? ["--backend", await fixtureBackend(f)] : []), "--runtime", await syntheticRuntime(f.scratch), "--runtime-git", SYNTHETIC_RUNTIME_GIT, "--loops", "1", "--minutes", "60"];
}

type Row = { record: string; state: string; detail: string; restore: string | null; reason?: string };
async function statusJson(f: ContFixture, home = f.dataHome) {
  const io = operatorIo("");
  const code = await runCli(["status", "--repo", f.repo, "--json", "--home", home, "--git", f.git], { ...io, engineTestHooks: f.le.env.testHooks! });
  return { code, s: JSON.parse(io.lines.join("\n")) as { state: string; repository: { state: string; read_on: string; records: Row[]; protected_path: { codex_path: string; s1_backends: string[]; fix_backend: string | null } | null } } };
}
const rowOf = (s: Awaited<ReturnType<typeof statusJson>>["s"], name: string) => s.repository.records.find((r) => r.record === name)!;

/** The custodian's config section as the implementer reads it (as protected execution does). */
async function heldSection(f: ContFixture): Promise<ConfigSection> {
  const listing = await new CustodianGrants(f.custodian).listUserRecords("implementer", f.repo, CONFIG_VIEW_RUN, ["config"]);
  return listing.config!;
}

/** T11: the enforcement's own decision — the review's S1 selection and isolation decision, and the delegation's stored
 * FIX record and predicate — over the custodian's records and the stored self-tests now. */
async function enforcement(f: ContFixture): Promise<{ s1: boolean; mode: string | null; fix: boolean }> {
  const section = await heldSection(f);
  const probe = await probeCodex({ configured: section.repository!.codexInstallation!.path, sourceEnv: process.env, testLauncher: f.le.env.testHooks!.review!.codexLauncher! });
  const backends = reviewBackends(process.platform, f.le.cfg.config.codex.windows_sandbox, probe);
  const selfTests = new Map<SandboxBackend, SelfTestRecord | null>();
  for (const b of backends) {
    const r = await storedS1SelfTest(f.le.layout.selftestDir, probe, b);
    selfTests.set(b, r && confirmedSelfTest(section, r) ? r : null);
  }
  const d = protectedIsolationDecision(section, probe, backends, selfTests);
  let fix = false;
  try {
    const l = await storedFixSelfTest(f.le.layout.selftestDir, f.le.dataHome, fixBackendFor(f.custodianPlatform, f.le.cfg.config.codex.windows_sandbox ?? null, probe), probe);
    fix = confirmedFixSelfTest(section, { selftestId: l.record.selftest_id, codexSha256: l.codexSha256, profileDigest: l.profileDigest }) !== undefined;
  } catch {
    fix = false;
  }
  return { s1: d.ok, mode: d.ok ? d.isolation.mode : null, fix };
}

/** T11: status's rows agree with the enforcement (in force exactly when protected execution would accept the basis). */
async function expectAgreement(f: ContFixture): Promise<Awaited<ReturnType<typeof statusJson>>["s"]> {
  const { s } = await statusJson(f);
  const e = await enforcement(f);
  expect(rowOf(s, "isolation").state === "in_force", `isolation row ${JSON.stringify(rowOf(s, "isolation"))} vs enforcement ${JSON.stringify(e)}`).toBe(e.s1);
  expect(rowOf(s, "fix_confirmation").state === "in_force", `FIX row ${JSON.stringify(rowOf(s, "fix_confirmation"))} vs enforcement ${JSON.stringify(e)}`).toBe(e.fix);
  return s;
}

/** Re-run the fixture's S1 self-test: a new record (another self-test id) under the same key. */
async function rerunS1(f: ContFixture): Promise<void> {
  await removeS1(f);
  await storeFixtureSelfTest(f);
}
async function removeS1(f: ContFixture): Promise<void> {
  const dir = f.le.layout.selftestDir;
  for (const n of await readdir(dir)) {
    if (!n.endsWith(".json")) continue;
    const o = JSON.parse(await readFile(join(dir, n), "utf8")) as { schema?: string };
    if (o.schema === "arl.codex-selftest.v1") await rm(join(dir, n));
  }
}
/** Store another cp_fix self-test record (a re-run: another self-test id) under the same key. */
async function rerunFix(f: ContFixture, id: string): Promise<void> {
  const probe = await probeCodex({ configured: f.codexExe, sourceEnv: process.env, testLauncher: { file: process.execPath, prefixArgs: [f.fakeScript] } });
  // The delegation's own backend rule (on a Linux host with the simulated Windows custodian it differs from the review's).
  const backend = fixBackendFor(f.custodianPlatform, f.le.cfg.config.codex.windows_sandbox ?? null, probe);
  const codexSha256 = sha(await readFile(f.codexExe));
  const profile = fixProfileFor(backend, probe, [join(f.dataHome, "fix-selftest-work", "tree"), join(f.dataHome, "fix-selftest-work", "scratch")], [probe.codexHome]);
  await storeFixSelfTest(storeLayout(f.dataHome).selftestDir, {
    schema: "arl.codex-fix-selftest.v1", selftest_id: id, key: fixSelfTestKey(probe.version, codexSha256, profile), codex_version: probe.version, codex_sha256: codexSha256, backend,
    profile_digest: fixProfileDigest(profile), created_at: new Date().toISOString(), profile_runs: true, rejection_reason: null,
    rows: [{ name: "native_edit_outside_denied", expectation: "denied", sandbox: "denied", positive_control: "ok", pass: true, detail: "test record" }], confinement_available: true, complete: true,
  });
}

describe.skipIf(!supported)("Step 7.2 — observeStoredSelfTests: missing, inaccessible, not compared, probe failure, Linux by design (T9)", () => {
  it("T9a–d: each reason from an observation; the Linux operator is told the store is inaccessible by design (nothing is probed)", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await storeFixtureSelfTest(f);
    expect((await cli(f, ["setup", "--repo", f.repo, ...(await setupArgs(f))], terminal())).code).toBe(0);
    const section = await heldSection(f);

    // Readable, with the record: observed.
    expect((await observeStoredSelfTests(f.le, { platform: "win32", root: f.repo, on: "implementer", section })).s1.ok).toBe(true);
    // T9a: a data home that does not exist is inaccessible (not "missing record").
    const gone = { ...f.le, dataHome: join(f.scratch, "no-such-home") } as Loaded;
    expect((await observeStoredSelfTests(gone, { platform: "win32", root: f.repo, on: "implementer", section })).s1).toMatchObject({ ok: false, reason: "store_inaccessible", why: expect.stringContaining("there is no CodeParley data home") });
    // T9c: a Windows operator without --home: not compared (another account's data home), with the command that compares.
    const noHome = { ...f.le, env: { ...f.le.env, launch: { ...f.le.env.launch, home: undefined } } } as unknown as Loaded;
    expect((await observeStoredSelfTests(noHome, { platform: "win32", root: f.repo, on: "operator", section })).s1).toMatchObject({ ok: false, reason: "not_compared", verify: expect.stringContaining('--home "<the implementer\'s data home>"') });
    // T9d: the approved Codex cannot be probed.
    const noProbe = { ...f.le, env: { ...f.le.env, testHooks: undefined } } as unknown as Loaded;
    const broken = { ...section, repository: { ...section.repository!, codexInstallation: { ...section.repository!.codexInstallation!, path: join(f.scratch, "no-codex.exe") } } };
    expect((await observeStoredSelfTests(noProbe, { platform: "win32", root: f.repo, on: "implementer", section: broken })).s1).toMatchObject({ ok: false, reason: "probe_failed" });
    // The Linux operator: inaccessible by design.
    expect((await observeStoredSelfTests(f.le, { platform: "linux", root: f.repo, on: "operator", section })).s1).toMatchObject({ ok: false, reason: "store_inaccessible", why: expect.stringContaining("by design") });
    // Review finding #7: the FIX reader. A readable Codex without a stored cp_fix record is the delegation's own refusal
    // (a missing record); a Codex executable that cannot be read leaves the record unidentifiable: store_inaccessible.
    const probe = await probeCodex({ configured: f.codexExe, sourceEnv: process.env, testLauncher: { file: process.execPath, prefixArgs: [f.fakeScript] } });
    expect(await fixEvidenceReader(f.le)(probe)).toMatchObject({ local: null, why: expect.stringContaining("no stored cp_fix self-test") });
    const unreadable = (p: CodexProbe): CodexProbe => ({ ...p, launcher: { ...p.launcher, exe: join(f.scratch, "unreadable-codex.exe") } });
    await expect(fixEvidenceReader(f.le)(unreadable(probe))).rejects.toThrow(/cannot be read to identify it: ENOENT/);
    const observed = await observeStoredSelfTests(f.le, { platform: "win32", root: f.repo, on: "implementer", section, fix: (p) => fixEvidenceReader(f.le)(unreadable(p)) });
    expect(observed.fix).toMatchObject({ ok: false, reason: "store_inaccessible", why: expect.stringContaining("cannot be read or identified") });
    expect(await row(section, "fix_confirmation", { fix: observed.fix })).toMatchObject({ state: "missing" });
    const withFix = { ...section, selftestConfirmations: [...section.selftestConfirmations, fixConf()] };
    expect(await row(withFix, "fix_confirmation", { fix: observed.fix })).toMatchObject({ state: "unverified", reason: "store_inaccessible", required: false });
    // T9b through status: a readable store without the record is a missing record (unconfirmed), not inaccessible.
    await removeS1(f);
    expect(rowOf((await statusJson(f)).s, "isolation")).toMatchObject({ state: "unconfirmed", reason: "record_missing" });
    // T9a through status: a data home that does not exist is not established (Windows). On Linux the engine creates its
    // own private data home when it loads (ensurePrivateDataHome, unchanged), so it is an empty, readable store there.
    const s = (await statusJson(f, join(f.scratch, "no-such-home"))).s;
    if (process.platform === "linux") expect(rowOf(s, "isolation")).toMatchObject({ state: "unconfirmed", reason: "record_missing" });
    else {
      expect(rowOf(s, "isolation")).toMatchObject({ state: "unverified", reason: "store_inaccessible" });
      expect(s.repository.state).toBe("unknown");
    }
  }, 240_000);
});

// ---------------------------------------------------------------------------
// T11 + T12: F-S71-2 end to end, with the agreement checked at every state
// ---------------------------------------------------------------------------

describe.skipIf(!supported)("Step 7.2 — F-S71-2 end to end: status agrees with enforcement; setup confirms what protected execution uses (T11, T12)", () => {
  it("S1 and FIX re-runs, a missing record, a revocation, a lapse and an S2 acceptance", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await storeFixtureSelfTest(f);
    // The FIX legs need the delegation's backend to be one this host's operator CLI accepts. On a real host it always is;
    // with this fixture's simulated Windows custodian on a Linux host it is not (the delegation selects mxc), so there the
    // FIX legs are left to T8 (unit) and the Linux VM rows.
    const probe = await probeCodex({ configured: f.codexExe, sourceEnv: process.env, testLauncher: { file: process.execPath, prefixArgs: [f.fakeScript] } });
    const fixLegs = (backendsFor() as readonly string[]).includes(fixBackendFor(f.custodianPlatform, f.le.cfg.config.codex.windows_sandbox ?? null, probe));
    if (fixLegs) await rerunFix(f, "fix-selftest-1");
    // With --fix no --backend (Q4: each confirmation uses the backend its own execution path selects).
    const ok = await cli(f, ["setup", ...(fixLegs ? ["--fix"] : []), "--repo", f.repo, ...(await setupArgs(f, false))], terminal());
    expect(ok.code, ok.err).toBe(0);
    if (fixLegs) expect(ok.out).toMatch(/confirm the stored FIX self-test/);
    let s = await expectAgreement(f);
    expect(s.repository.state).toBe("ready");
    expect(rowOf(s, "fix_confirmation").state).toBe(fixLegs ? "in_force" : "missing");
    expect(s.repository.protected_path).toMatchObject({ codex_path: expect.any(String), s1_backends: [await fixtureBackend(f)] });

    // T12 (F-S71-2): the S1 self-test is re-run after its confirmation: status says so, and enforcement agrees.
    await rerunS1(f);
    s = await expectAgreement(f);
    expect(rowOf(s, "isolation")).toMatchObject({ state: "unconfirmed", reason: "record_changed" });
    expect(s.repository.state).toBe("misconfigured");
    expect((await statusJson(f)).code).toBe(1);
    // A declined confirmation records nothing.
    const before = f.custodian.snapshot().config.selftestConfirmations.length;
    const declined = await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal("no"));
    expect(declined.code).toBe(2);
    expect(declined.out).toMatch(/Step 1: confirm the stored S1 self-test/);
    expect(f.custodian.snapshot().config.selftestConfirmations.length).toBe(before);
    // setup --resume confirms the stored record — of the approved installation, on the review's backend, by default.
    const confirmed = await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal());
    expect(confirmed.code, confirmed.err).toBe(0);
    s = await expectAgreement(f);
    expect(rowOf(s, "isolation").state).toBe("in_force");

    // T8: the FIX self-test is re-run: optional for readiness; setup --resume --fix confirms it.
    if (fixLegs) {
      await rerunFix(f, "fix-selftest-2");
      s = await expectAgreement(f);
      expect(rowOf(s, "fix_confirmation")).toMatchObject({ state: "unconfirmed", reason: "record_changed" });
      expect(s.repository.state).toBe("ready");
      expect((await cli(f, ["setup", "--resume", "--fix", "--repo", f.repo, "--no-grant"], terminal())).code).toBe(0);
      expect(rowOf(await expectAgreement(f), "fix_confirmation").state).toBe("in_force");

      // Review finding #6: the FIX confirmation is revoked; setup --resume --fix cannot restore it and does not report
      // success (exit 1, naming what is open); the repository stays ready for reviews. A new setup --fix confirms it anew.
      const fixId = f.custodian.snapshot().config.selftestConfirmations.filter((c) => c.mode === "FIX" && c.revokedAt === null && c.supersededAt === null).at(-1)!.confirmationId;
      expect((await cli(f, ["config", "revoke-selftest", "--repo", f.repo, fixId], terminal())).code).toBe(0);
      s = await expectAgreement(f);
      expect(rowOf(s, "fix_confirmation")).toMatchObject({ state: "revoked" });
      expect(s.repository.state).toBe("ready");
      const fixResumed = await cli(f, ["setup", "--resume", "--fix", "--repo", f.repo, "--no-grant"], terminal());
      expect(fixResumed.code, fixResumed.out).toBe(1);
      expect(fixResumed.out).toMatch(/is ready for protected reviews, but the FIX confirmation that --fix asked for is not in force \(REVOKED\).*Delegated fixes stay refused\. Next: /);
      expect(fixResumed.out).not.toMatch(/is set up for protected runs/);
      expect(fixResumed.out).not.toMatch(/confirm the stored FIX self-test/);
      // Without --fix the same state is complete for reviews (FIX stays optional for readiness).
      expect((await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal())).code).toBe(0);
      expect((await cli(f, ["setup", "--fix", "--repo", f.repo, "--no-grant"], terminal())).code).toBe(0);
      expect(rowOf(await expectAgreement(f), "fix_confirmation").state).toBe("in_force");
    }

    // T2: the stored S1 record is gone: setup cannot confirm it and names the self-test to run (nothing recorded).
    await removeS1(f);
    s = await expectAgreement(f);
    expect(rowOf(s, "isolation")).toMatchObject({ state: "unconfirmed", reason: "record_missing" });
    const blocked = await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal());
    expect(blocked.code).toBe(2);
    expect(blocked.out).toMatch(/Not possible yet: .*The implementer runs `code-parley codex selftest --backend \S+` first/);
    await storeFixtureSelfTest(f);
    expect((await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal())).code).toBe(0);

    // T5: the operator revokes the confirmation of the stored record: revoked; --resume never restores it.
    const id = f.custodian.snapshot().config.selftestConfirmations.filter((c) => c.mode === "S1" && c.revokedAt === null && c.supersededAt === null).at(-1)!.confirmationId;
    expect((await cli(f, ["config", "revoke-selftest", "--repo", f.repo, id], terminal())).code).toBe(0);
    s = await expectAgreement(f);
    expect(rowOf(s, "isolation")).toMatchObject({ state: "revoked" });
    const resumed = await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal());
    expect(resumed.out).not.toMatch(/confirm the stored S1 self-test/);
    expect(resumed.code).toBe(1);
    // Without --resume, the operator may confirm it anew (a new typed confirmation).
    expect((await cli(f, ["setup", "--repo", f.repo, "--no-grant"], terminal())).code).toBe(0);
    expect(rowOf(await expectAgreement(f), "isolation").state).toBe("in_force");

    // T6: a restart of the OS lapses it: lapsed (not in force), as the custodian refuses it (CONFIG_LAPSED).
    f.custodian.simulateRecoveryAfterNewBoot();
    expect(rowOf(await expectAgreement(f), "isolation").state).toBe("lapsed");
    expect((await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal())).code).toBe(0);
    expect(rowOf(await expectAgreement(f), "isolation").state).toBe("in_force");

    // T7: an explicit acceptance of reduced isolation, then an S1 re-run: in force by S2, as the review would decide.
    expect((await cli(f, ["config", "accept-isolation", "--repo", f.repo, "--backend", await fixtureBackend(f), "--codex", f.codexExe], terminal())).code).toBe(0);
    await rerunS1(f);
    s = await expectAgreement(f);
    expect((await enforcement(f)).mode).toBe("S2");
    expect(rowOf(s, "isolation")).toMatchObject({ state: "in_force", detail: expect.stringContaining("reduced isolation (S2)") });

    // Review finding #10 end to end: the stored record's S1 confirmation is revoked while the acceptance holds (S2), then a
    // restart lapses the acceptance. The row is revoked, not lapsed, and setup --resume never confirms the S1 record again.
    // (The row is in force by S2, so setup has nothing to confirm: the operator confirms the stored S1 record directly.)
    const s1Confirmed = await cli(f, ["config", "confirm-selftest", "--repo", f.repo, "--backend", await fixtureBackend(f), "--codex", f.codexExe], terminal());
    expect(s1Confirmed.code, s1Confirmed.err).toBe(0);
    expect((await enforcement(f)).mode).toBe("S1");
    const s1Id = f.custodian.snapshot().config.selftestConfirmations.filter((c) => c.mode === "S1" && c.revokedAt === null && c.supersededAt === null).at(-1)!.confirmationId;
    expect((await cli(f, ["config", "revoke-selftest", "--repo", f.repo, s1Id], terminal())).code).toBe(0);
    expect((await enforcement(f)).mode).toBe("S2");
    expect(rowOf(await expectAgreement(f), "isolation").state).toBe("in_force");
    f.custodian.simulateRecoveryAfterNewBoot();
    s = await expectAgreement(f);
    expect(rowOf(s, "isolation")).toMatchObject({ state: "revoked", detail: expect.stringContaining("was revoked (setup --resume does not restore it)") });
    const unrevoked = () => f.custodian.snapshot().config.selftestConfirmations.filter((c) => c.mode === "S1" && c.revokedAt === null).length;
    const beforeResume = unrevoked();
    const afterRevoke = await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal());
    expect(afterRevoke.out).not.toMatch(/confirm the stored S1 self-test/);
    expect(unrevoked()).toBe(beforeResume);
    await expectAgreement(f);
  }, 480_000);
});

// ---------------------------------------------------------------------------
// T13: Q4 — explicit selections protected execution cannot use
// ---------------------------------------------------------------------------

describe.skipIf(!supported)("Step 7.2 — Q4: an explicit Codex or backend protected execution cannot use is refused before anything is recorded (T13)", () => {
  it("refuses another installation than the approved one, and a backend the review does not use; nothing is recorded", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await storeFixtureSelfTest(f);
    expect((await cli(f, ["setup", "--repo", f.repo, ...(await setupArgs(f))], terminal())).code).toBe(0);
    await rerunS1(f);
    const other = join(f.scratch, "other-codex.exe");
    await copyFile(f.codexExe, other);
    const snap = JSON.stringify(f.custodian.snapshot().config);
    const codex = await cli(f, ["setup", "--resume", "--repo", f.repo, "--codex", other, "--no-grant"], terminal());
    expect(codex.code).toBe(1);
    expect(codex.err).toMatch(/--codex .* is not the Codex installation the custodian approved for this repository .*protected reviews and delegated fixes launch only that one.*Nothing was recorded/);
    const wrong = process.platform === "win32" ? "bwrap" : "mxc";
    const backend = await cli(f, ["setup", "--resume", "--repo", f.repo, "--backend", wrong, "--no-grant"], terminal());
    expect(backend.code).toBe(1);
    expect(backend.err).toMatch(new RegExp(`--backend ${wrong} is not a backend a protected review uses with this Codex: ${await fixtureBackend(f)}`));
    expect(JSON.stringify(f.custodian.snapshot().config)).toBe(snap);
    // The approved installation and the review's backend, named explicitly, are accepted.
    expect((await cli(f, ["setup", "--resume", "--repo", f.repo, "--codex", f.codexExe, "--backend", await fixtureBackend(f), "--no-grant"], terminal())).code).toBe(0);
  }, 240_000);

  it("review finding #4: an explicit --codex protected execution cannot launch is refused before any step records, also without --backend", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await storeFixtureSelfTest(f);
    // A first setup: the runtime approval and the configuration would be recorded before the confirmation step.
    const snap = JSON.stringify(f.custodian.snapshot().config);
    const missing = join(f.scratch, "no-such-codex.exe");
    const notNative = join(f.scratch, process.platform === "win32" ? "codex.cmd" : "codex-script");
    await copyFile(f.fakeScript, notNative);
    for (const codex of [missing, notNative]) {
      const args = (await setupArgs(f, false)).map((x) => (x === f.codexExe ? codex : x));
      const r = await cli(f, ["setup", "--repo", f.repo, ...args], terminal());
      expect(r.code, r.out + r.err).toBe(1);
      expect(r.err).toMatch(new RegExp(`--codex ${codex.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} is not a Codex installation protected execution can launch \\(CODEX_NOT_FOUND: .*Nothing was recorded`));
      expect(r.out).not.toMatch(/Step 1:/);
      expect(JSON.stringify(f.custodian.snapshot().config)).toBe(snap);
    }
    // The same run with the launchable installation records as before.
    expect((await cli(f, ["setup", "--repo", f.repo, ...(await setupArgs(f, false))], terminal())).code).toBe(0);
    const set = JSON.stringify(f.custodian.snapshot().config);
    // After a restart (a lapsed record a re-confirmation would record first) the named installation is still refused up
    // front — here as not the approved one (T13), the check that precedes the probe — and nothing is recorded.
    f.custodian.simulateRecoveryAfterNewBoot();
    const lapsedSnap = JSON.stringify(f.custodian.snapshot().config);
    expect(lapsedSnap).not.toBe(set);
    const r = await cli(f, ["setup", "--resume", "--repo", f.repo, "--codex", missing, "--no-grant"], terminal());
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/--codex .* is not the Codex installation the custodian approved .*Nothing was recorded/);
    expect(JSON.stringify(f.custodian.snapshot().config)).toBe(lapsedSnap);
  }, 240_000);
});

// ---------------------------------------------------------------------------
// T14: the Linux proposal handoff and the end of an operator-only setup
// ---------------------------------------------------------------------------

describe("Step 7.2 — the Linux proposal handoff (T14)", () => {
  it("a proposal counts as confirmed only for a usable confirmation of exactly its record", () => {
    const r1 = rec();
    const p = { selftestId: r1.selftest_id, codexVersion: r1.codex_version, backend: r1.backend, mode: "S1", profileDigest: r1.profile_digest, recordDigest: selfTestRecordDigest(r1) };
    expect(proposalConfirmed(section([conf(r1)]), p)).toBe(true);
    expect(proposalConfirmed(section([conf(r1, { usable: false, lapsed: true })]), p)).toBe(false);
    expect(proposalConfirmed(section([conf(r1, { usable: false, revoked: true })]), p)).toBe(false);
    expect(proposalConfirmed(section([conf(r1)]), { ...p, recordDigest: H("0") })).toBe(false);
    expect(proposalConfirmed(section([conf(r1)]), { ...p, selftestId: "st-other" })).toBe(false);
    expect(proposalConfirmed(section([conf(r1)]), null)).toBe(false);
    const fp = { mode: "FIX", selftestId: "fx-1", codexSha256: H("e"), profileDigest: H("c") };
    expect(proposalConfirmed(section([fixConf()]), fp)).toBe(true);
    expect(proposalConfirmed(section([fixConf()]), { ...fp, codexSha256: H("7") })).toBe(false);
    // An S1 confirmation never covers a FIX proposal, nor the reverse.
    expect(proposalConfirmed(section([conf(r1)]), { ...fp, selftestId: r1.selftest_id })).toBe(false);
  });
});

describe.skipIf(!supported)("Step 7.2 — an operator whose account cannot read the implementer's store completes its steps with exit 3 (T14)", () => {
  it("setup records what the operator can, never loops, and ends 'not verified from this account' with the implementer's command", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await storeFixtureSelfTest(f);
    // With a FIX confirmation held where the host's operator CLI accepts the delegation's backend (as in T12).
    const probe = await probeCodex({ configured: f.codexExe, sourceEnv: process.env, testLauncher: { file: process.execPath, prefixArgs: [f.fakeScript] } });
    const fixLegs = (backendsFor() as readonly string[]).includes(fixBackendFor(f.custodianPlatform, f.le.cfg.config.codex.windows_sandbox ?? null, probe));
    if (fixLegs) await rerunFix(f, "fix-selftest-1");
    const first = await cli(f, ["setup", ...(fixLegs ? ["--fix"] : []), "--repo", f.repo, ...(await setupArgs(f, !fixLegs))], terminal());
    expect(first.code, first.err).toBe(0);
    // The same custodian state, read as on Linux by the operator account: the implementer's store is inaccessible.
    const linuxOperator = { ...f.operatorHooks!, custodian: { ...f.operatorHooks!.custodian!, platform: "linux" as NodeJS.Platform } };
    const io = { ...terminal(), engineTestHooks: linuxOperator };
    const r = await cli(f, ["setup", "--repo", f.repo, "--no-grant"], io);
    expect(r.code, r.err + r.out).toBe(3);
    expect(r.out).toMatch(/Operator configuration is complete; it is NOT verified from this account .*Codex isolation \(S1\).*Verify: the implementer: code-parley status --repo/);
    expect(r.out).toMatch(/UNVERIFIED/);
    expect(r.out).not.toMatch(/Step \d+: confirm/);
    // Review finding #6: with --fix the FIX confirmation is part of the run; unverifiable from here, it is named in the
    // same exit 3 (never reported as set up).
    if (fixLegs) {
      const rf = await cli(f, ["setup", "--fix", "--repo", f.repo, "--no-grant"], io);
      expect(rf.code, rf.err + rf.out).toBe(3);
      expect(rf.out).toMatch(/Operator configuration is complete; it is NOT verified from this account .*Codex isolation \(S1\), FIX confirmation\)/);
      expect(rf.out).not.toMatch(/is set up for protected runs/);
    }
  }, 240_000);
});

// ---------------------------------------------------------------------------
// T15: O-1 — a re-confirmation refused CONFIG_MISMATCH
// ---------------------------------------------------------------------------

describe.skipIf(!supported)("Step 7.2 — O-1: after a refused re-confirmation setup offers `config set`, typed, and never retries it (T15)", () => {
  it("a Codex file replaced with the same bytes (a new file identity) after a restart: reconfirm refused → set again → ready; declining set records nothing", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await storeFixtureSelfTest(f);
    expect((await cli(f, ["setup", "--repo", f.repo, ...(await setupArgs(f))], terminal())).code).toBe(0);
    // The same bytes under a new file identity (a reinstall), then a restart of the OS.
    await copyFile(f.codexExe, `${f.codexExe}.new`);
    await rename(`${f.codexExe}.new`, f.codexExe);
    f.custodian.simulateRecoveryAfterNewBoot();
    const lapsed = await statusJson(f);
    expect(rowOf(lapsed.s, "repository").state).toBe("lapsed"); // the hash is unchanged: status cannot tell

    // Declined: the refused re-confirmation records nothing; the engine runtime that lapsed with the same restart is
    // re-confirmed (unchanged rule: before the repository record), and the operator declines the `set` step.
    const versions = f.custodian.snapshot().config.repositories.length;
    const declined = await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal(["confirm", "no"]));
    expect(declined.code).toBe(2);
    expect(declined.err).toMatch(/error CONFIG_MISMATCH: the Codex installation measured now differs from the one held/);
    expect(declined.out).toMatch(/Step 1: re-confirm the repository's configuration/);
    expect(declined.out).toMatch(/Step 2: re-confirm the engine runtime approval/);
    expect(declined.out).toMatch(/Step 3: set the repository's protected configuration again \(the custodian refused its re-confirmation\)/);
    expect(declined.out).toContain("Stopped: not confirmed");
    expect(f.custodian.snapshot().config.repositories.length).toBe(versions);

    // Confirmed: the set step's own rendering and typed confirmation, then the remaining lapsed records; never a second re-confirmation.
    const ok = await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal());
    expect(ok.code, ok.err).toBe(0);
    expect(ok.out.match(/re-confirm the repository's configuration/g)).toHaveLength(1);
    expect(ok.out).toMatch(/set the repository's protected configuration again/);
    expect(f.custodian.snapshot().config.repositories.length).toBe(versions + 1);
    expect((await statusJson(f)).s.repository.state).toBe("ready");
  }, 240_000);

  it("review finding #3: a runtime changed in place after a restart cannot be re-confirmed; the refusal names config approve-runtime, which recovers", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await storeFixtureSelfTest(f);
    const args = await setupArgs(f);
    expect((await cli(f, ["setup", "--repo", f.repo, ...args], terminal())).code).toBe(0);
    // The approved runtime's helper entry changes in place (same path), then a restart of the OS lapses the records.
    const runtime = args[args.indexOf("--runtime") + 1]!;
    await writeFile(join(runtime, "dist", "helper", "main.js"), "// synthetic helper entry, changed in place\n");
    f.custodian.simulateRecoveryAfterNewBoot();
    expect(rowOf((await statusJson(f)).s, "engine_runtime").state).toBe("lapsed");
    // The repository's re-confirmation (with the global records that lapsed) is refused at its commit: STALE_CONFIG.
    const first = await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal());
    expect(first.code).toBe(1);
    expect(first.err).toMatch(/error STALE_CONFIG: the engine runtime changed since this was prepared/);
    expect(first.err).toMatch(/fix: +approve the runtime again as it is now: the operator runs `\S+ config approve-runtime --repo <path> --runtime /);
    expect(first.err).not.toMatch(/run the same command again/);
    // Run again: refused again (on the real custodians the same STALE_CONFIG; the simulated custodian applies part of the
    // refused commit, so here the runtime's own re-confirmation is refused CONFIG_MISMATCH) — the same remedy either way.
    const again = await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal());
    expect(again.code).toBe(1);
    expect(again.err).toMatch(/error (STALE_CONFIG|CONFIG_MISMATCH): the engine runtime /);
    expect(again.err).toMatch(/fix: +approve the runtime again as it is now: the operator runs `\S+ config approve-runtime/);
    // The named recovery: approve the runtime as it is now, then resume what remains.
    expect((await cli(f, ["config", "approve-runtime", "--repo", f.repo, "--runtime", runtime, "--runtime-git", SYNTHETIC_RUNTIME_GIT], terminal())).code).toBe(0);
    expect((await cli(f, ["setup", "--resume", "--repo", f.repo, "--no-grant"], terminal())).code).toBe(0);
    expect((await statusJson(f)).s.repository.state).toBe("ready");
    // Other refusals of the same codes keep their remedies.
    expect(remedyFor("STALE_CONFIG", "win32", "the global configuration records changed since they were read (revision 3, prepared against 2)")!.fix).toMatch(/^run the same command again/);
    expect(remedyFor("CONFIG_MISMATCH", "win32", "the Codex installation measured now differs from the one held (file id)")!.fix).toMatch(/^approve the new one: the operator runs `code-parley setup --repo <path>`/);
    expect(remedyFor("CONFIG_MISMATCH", "linux", "the engine runtime measured now differs from the one approved (tree digest)")!.fix).toContain("`/usr/local/sbin/code-parley-operator config approve-runtime --repo <path> --runtime /opt/codeparley/engine/<version> --runtime-git-path /usr/bin/git`");
  }, 240_000);
});

// ---------------------------------------------------------------------------
// T16: layering
// ---------------------------------------------------------------------------

describe("Step 7.2 — layering: the status path imports no fixer module; no new authority (T16)", () => {
  const srcDir = join(fileURLToPath(new URL(".", import.meta.url)), "..", "src");
  const srcRel = (file: string): string => relative(srcDir, file).split(sep).join("/");
  const reachable = (entry: string): Set<string> => {
    const seen = new Set<string>();
    const stack = [entry];
    while (stack.length) {
      const rel = stack.pop()!;
      if (seen.has(rel)) continue;
      seen.add(rel);
      for (const m of readFileSync(join(srcDir, rel), "utf8").matchAll(/(?:from\s+|import\(\s*)["'](\.{1,2}\/[^"']+)\.js["']/g)) stack.push(srcRel(join(dirname(join(srcDir, rel)), m[1]! + ".ts")));
    }
    return seen;
  };
  const FIX = ["agents/codex/fix-profile.ts", "agents/codex/fix-selftest.ts", "agents/codex/fix-isolation.ts", "agents/codex/fix-launcher.ts", "engine/fix-operation.ts", "engine/fix-confirmation.ts", "engine/fix-apply.ts", "engine/fix-decision.ts"];

  it("engine/protected-status.ts and engine/protected-config.ts reach no fixer module; the shared FIX predicate is pure", () => {
    for (const m of ["engine/protected-status.ts", "engine/protected-config.ts"]) expect([...reachable(m)].filter((x) => FIX.includes(x)), m).toEqual([]);
    const text = readFileSync(join(srcDir, "engine", "protected-config.ts"), "utf8");
    const fn = /export function confirmedFixSelfTest[\s\S]*?\n}/.exec(text)![0];
    expect(fn).not.toMatch(/await|readFile|Date\.|process\./);
  });

  it("the FIX evidence reader is the CLI's only, and the hooks and the helper reach none of the Step 7.2 CLI modules", () => {
    const users = ["cli/cli.ts", "cli/setup-commands.ts"];
    for (const entry of ["hooks/main.ts", "hooks/adapter.ts", "helper/main.ts", "process/session-reaper-main.ts"]) {
      const r = reachable(entry);
      expect(r.has("cli/status-fix-evidence.ts") || r.has("cli/setup-commands.ts"), entry).toBe(false);
    }
    const importers = (target: string) => [...reachable("cli/main.ts")].filter((rel) => [...readFileSync(join(srcDir, rel), "utf8").matchAll(/(?:from\s+|import\(\s*)["'](\.{1,2}\/[^"']+)\.js["']/g)].some((m) => srcRel(join(dirname(join(srcDir, rel)), m[1]! + ".ts")) === target)).sort();
    expect(importers("cli/status-fix-evidence.ts")).toEqual(users);
  });
});

// ---------------------------------------------------------------------------
// POST-1 grouped operator-diagnostics correction (TD POST-1-DIAGNOSTICS-AND-STATIC-CORRECTION-AUTHORIZED): N-3, N-4, O-11
// ---------------------------------------------------------------------------

describe("POST-1 diagnostics — O-11: a lapsed S1 confirmation, a lapsed S2 acceptance and an unobserved lapse are told apart", () => {
  // The two platform models: the review's backend there, and the operator CLI's resume command.
  const models = [
    { platform: "win32" as NodeJS.Platform, backend: "mxc" as SandboxBackend, resume: "code-parley setup --resume --repo C:\\r" },
    { platform: "linux" as NodeJS.Platform, backend: "bwrap" as SandboxBackend, resume: "/usr/local/sbin/code-parley-operator setup --resume --repo C:\\r" },
  ];
  const linuxOperator: Observed<S1Evidence> = { ok: false, reason: "store_inaccessible", why: "by design", verify: "the implementer: code-parley status --repo /r" };

  for (const m of models) {
    const applicable = realAcceptance({ backend: m.backend });
    const ev = (s: ConfigSection, stored: (SelfTestRecord | null)[]) => s1ev(s, stored, [m.backend]);

    it(`${m.platform}: the stored record's own lapsed S1 confirmation keeps the S1 wording and restore`, async () => {
      const r1 = rec({ backend: m.backend });
      const s = section([conf(r1, { lapsed: true, usable: false, lapsedAtRecoveryId: "rec-1" })], [lapsedOf(applicable)]);
      const r = await row(s, "isolation", { s1: ev(s, [r1]), platform: m.platform });
      expect(r).toMatchObject({ state: "lapsed", required: true, resumable: true, detail: expect.stringMatching(/^the S1 self-test confirmation lapsed/) });
      expect(r.detail).not.toMatch(/reduced-isolation|not established/);
      if (m.platform === "linux") expect(r.restore).toMatch(/^the implementer: code-parley codex selftest, then code-parley config propose-selftest .*setup --resume --repo C:\\r --proposal-file <file>$/);
      else expect(r.restore).toBe('code-parley setup --resume --repo C:\\r --home "C:\\impl"');
    });

    it(`${m.platform}: an applicable lapsed S2 acceptance is named, with its id and backend, and restored by setup --resume`, async () => {
      const stored = rec({ selftest_id: "st-new", backend: m.backend });
      const s = section([conf(rec({ selftest_id: "st-old", backend: m.backend }))], [lapsedOf(applicable)]);
      const r = await row(s, "isolation", { s1: ev(s, [stored]), platform: m.platform });
      expect(r).toMatchObject({ state: "lapsed", required: true, resumable: true, restore: m.resume });
      expect(r.detail).toBe(`the reduced-isolation (S2) acceptance a-1 for ${m.backend} lapsed after a restart of the OS or a rollback (setup --resume re-confirms it with the repository's configuration)`);
      expect(r.detail).not.toMatch(/S1 self-test confirmation|new self-test/);
    });

    it(`${m.platform}: an inapplicable lapsed acceptance decides nothing, and a revoked S1 confirmation beside a lapsed acceptance stays revoked`, async () => {
      const stored = rec({ selftest_id: "st-new", backend: m.backend });
      const other = section([conf(rec({ selftest_id: "st-old", backend: m.backend }))], [lapsedOf(realAcceptance({ backend: m.backend, codexVersionRange: "0.159" }))]);
      expect(await row(other, "isolation", { s1: ev(other, [stored]), platform: m.platform })).toMatchObject({ state: "unconfirmed", reason: "record_changed" });
      const r1 = rec({ backend: m.backend });
      const revoked = section([conf(r1, { revoked: true, usable: false })], [lapsedOf(applicable)]);
      expect(await row(revoked, "isolation", { s1: ev(revoked, [r1]), platform: m.platform })).toMatchObject({ state: "revoked", resumable: false });
      expect(await row(revoked, "isolation", { s1: linuxOperator, platform: m.platform })).toMatchObject({ state: "revoked", resumable: false });
    });

    it(`${m.platform}: unobserved, a lapse says that the record or backend was not established`, async () => {
      const notObserved: Observed<S1Evidence> = m.platform === "linux" ? linuxOperator : { ok: false, reason: "not_compared", why: "another account's data home", verify: "v" };
      // Only an acceptance lapsed: named, with its restore; whether the review would rest on it is not established.
      const onlyAcc = await row(section([], [lapsedOf(applicable)]), "isolation", { s1: notObserved, platform: m.platform });
      expect(onlyAcc).toMatchObject({ state: "lapsed", resumable: true, restore: m.resume });
      expect(onlyAcc.detail).toBe(`the reduced-isolation (S2) acceptance a-1 for ${m.backend} lapsed after a restart of the OS or a rollback (setup --resume re-confirms it with the repository's configuration); whether a protected review would rest on it was not established from this account (${notObserved.ok ? "" : notObserved.why})`);
      // An S1 confirmation lapsed (with or without an acceptance): the S1 wording, which record not established.
      for (const accs of [[], [lapsedOf(applicable)]]) {
        const s1Lapse = await row(section([conf(rec({ backend: m.backend }), { lapsed: true, usable: false })], accs), "isolation", { s1: notObserved, platform: m.platform });
        expect(s1Lapse).toMatchObject({ state: "lapsed", resumable: true });
        expect(s1Lapse.detail).toMatch(/^the S1 self-test confirmation lapsed .*; which stored self-test a protected review would use was not established from this account \(/);
      }
      // No evidence at all: still not established, said so.
      expect((await row(section([], [lapsedOf(applicable)]), "isolation", { platform: m.platform })).detail).toMatch(/was not established from this account \(the stored self-test was not compared\)$/);
    });
  }
});

describe("POST-1 diagnostics — N-4: doctor's exit code", () => {
  it("problems decide first (1); with none, an unverified required record is 3; else 0", () => {
    expect(doctorExitCode(0, 0)).toBe(0);
    expect(doctorExitCode(1, 0)).toBe(1);
    expect(doctorExitCode(2, 3)).toBe(1);
    expect(doctorExitCode(0, 2)).toBe(3);
  });
});

describe.skipIf(!supported)("POST-1 diagnostics — N-3 and N-4 on the simulated custodian", () => {
  it("N-3: a Codex executable this account cannot read is store_inaccessible, not record_missing (Windows: an ACL denial; Linux: mode 000)", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await storeFixtureSelfTest(f);
    expect((await cli(f, ["setup", "--repo", f.repo, ...(await setupArgs(f))], terminal())).code).toBe(0);
    const held = await heldSection(f);
    const withFix = { ...held, selftestConfirmations: [...held.selftestConfirmations, fixConf()] };
    const probe = await probeCodex({ configured: f.codexExe, sourceEnv: process.env, testLauncher: { file: process.execPath, prefixArgs: [f.fakeScript] } });
    // A controlled copy in the fixture's scratch directory: the installed Codex is never touched.
    const copy = join(f.scratch, "unreadable-copy-codex.exe");
    await copyFile(f.codexExe, copy);
    const at = (p: CodexProbe): CodexProbe => ({ ...p, launcher: { ...p.launcher, exe: copy } });
    const user = `${process.env["USERDOMAIN"] ?? ""}\\${process.env["USERNAME"] ?? ""}`;
    if (process.platform === "win32") {
      const icacls = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "icacls.exe");
      const deny = spawnSync(icacls, [copy, "/deny", `${user}:(RD)`], { encoding: "utf8", windowsHide: true });
      expect(deny.status, deny.stdout + deny.stderr).toBe(0);
      try {
        await expect(readFile(copy)).rejects.toMatchObject({ code: expect.stringMatching(/^(EPERM|EACCES)$/) });
        await expect(fixEvidenceReader(f.le)(at(probe))).rejects.toThrow(/cannot be read to identify it: (EPERM|EACCES)/);
        const observed = await observeStoredSelfTests(f.le, { platform: "win32", root: f.repo, on: "implementer", section: held, fix: (p) => fixEvidenceReader(f.le)(at(p)) });
        expect(observed.fix).toMatchObject({ ok: false, reason: "store_inaccessible", why: expect.stringContaining("cannot be read or identified") });
        expect(await row(withFix, "fix_confirmation", { fix: observed.fix })).toMatchObject({ state: "unverified", reason: "store_inaccessible" });
      } finally {
        spawnSync(icacls, [copy, "/remove:d", user], { windowsHide: true });
      }
    } else if (process.getuid?.() !== 0) {
      await chmod(copy, 0o000);
      try {
        await expect(fixEvidenceReader(f.le)(at(probe))).rejects.toThrow(/cannot be read to identify it: EACCES/);
        const observed = await observeStoredSelfTests(f.le, { platform: "win32", root: f.repo, on: "implementer", section: held, fix: (p) => fixEvidenceReader(f.le)(at(p)) });
        expect(observed.fix).toMatchObject({ ok: false, reason: "store_inaccessible" });
      } finally {
        await chmod(copy, 0o755);
      }
    }
    // Readable again: the delegation's own refusal for want of a record, as before (a missing record).
    expect(await fixEvidenceReader(f.le)(at(probe))).toMatchObject({ local: null, why: expect.stringContaining("no stored cp_fix self-test") });
  }, 240_000);

  it("N-4: doctor --protected exits 0 / 3 / 1 by precedence, its headline says NOT VERIFIED, and --json agrees; doctor alone is unchanged", async () => {
    const f = await contFixture(okScenario(output({ findings: [] })), { accounts: true });
    await storeFixtureSelfTest(f);
    expect((await cli(f, ["setup", "--repo", f.repo, ...(await setupArgs(f))], terminal())).code).toBe(0);
    const doctorArgs = ["doctor", "--protected", "--repo", f.repo];
    const asImplementer = () => ({ ...operatorIo(""), engineTestHooks: f.le.env.testHooks! });
    const linuxOperator = { ...f.operatorHooks!, custodian: { ...f.operatorHooks!.custodian!, platform: "linux" as NodeJS.Platform } };
    const asLinuxOperator = () => ({ ...operatorIo(""), engineTestHooks: linuxOperator });

    // The base doctor (no --protected) is unchanged: 0 exactly when it is ok, no protected part. In this fixture it has
    // its own problems (the host's Node.js and Codex, no allowed roots), so the protected outcome is also checked below
    // with a clean base, through the same function the CLI uses.
    type Doc = { ok: boolean; problems: string[]; protected?: ProtectedDoctorFacts };
    const plainJson = await cli(f, ["doctor", "--json"], asImplementer());
    const base = JSON.parse(plainJson.out) as Doc;
    expect(base.protected).toBeUndefined();
    expect(plainJson.code).toBe(base.ok ? 0 : 1);
    const plain = await cli(f, ["doctor"], asImplementer());
    expect(plain.code).toBe(plainJson.code);
    expect(plain.out.split("\n").at(-1)).toBe(base.ok ? "doctor: OK" : `doctor: ${base.problems.length} problem(s)`);
    const clean = { ok: true, problems: [] as string[] };

    /** doctor --protected as `io`: the CLI's code, JSON and headline agree with doctorOutcome; returns the facts. */
    const run = async (io: () => ReturnType<typeof operatorIo>) => {
      const j = await cli(f, [...doctorArgs, "--json"], io());
      const doc = JSON.parse(j.out) as Doc;
      const want = doctorOutcome(base, doc.protected!);
      expect(j.code).toBe(want.code);
      expect(doc.ok).toBe(want.ok);
      const t = await cli(f, doctorArgs, io());
      expect(t.code).toBe(want.code);
      expect(t.out.split("\n").at(-1)).toBe(want.headline);
      // The readers-grant line reads the fixture repository's real access list (a host fact, not under test here).
      const prot = doc.protected!;
      return { prot: { ...prot, problems: prot.problems.filter((x) => !x.startsWith("repository readers grant")) }, text: t.out };
    };

    // Everything verified (the implementer; the Windows operator with --home): no problem, nothing unverified → 0, OK.
    for (const io of [asImplementer, () => operatorIo("")]) {
      const { prot, text } = await run(io);
      expect(prot.problems).toEqual([]);
      expect(prot.not_verified).toEqual([]);
      expect(text).not.toMatch(/NOT VERIFIED/);
      expect(doctorOutcome(clean, prot)).toEqual({ code: 0, ok: true, headline: "doctor: OK" });
    }

    // The Linux operator cannot read the implementer's store (by design): no problem, but not verified → 3, never OK.
    const nv = await run(asLinuxOperator);
    expect(nv.prot.problems).toEqual([]);
    expect(nv.prot.not_verified).toEqual([expect.stringMatching(/^isolation: unverified \(/)]);
    expect(nv.text).toMatch(/^NOT VERIFIED from this account: isolation: unverified/m);
    const three = doctorOutcome(clean, nv.prot);
    expect(three).toMatchObject({ code: 3, ok: false });
    expect(three.headline).toMatch(/^doctor: NOT VERIFIED from this account: Codex isolation \(S1\) \(no problem found/);
    // A base problem beside it decides: 1.
    expect(doctorOutcome({ ok: false, problems: ["x"] }, nv.prot)).toEqual({ code: 1, ok: false, headline: "doctor: 1 problem(s)" });

    // A protected problem beside it decides: 1. A restart lapses the repository's records, seen by the same operator.
    f.custodian.simulateRecoveryAfterNewBoot();
    const pr = await run(asLinuxOperator);
    expect(pr.prot.problems.length).toBeGreaterThan(0);
    expect(doctorOutcome(clean, pr.prot)).toMatchObject({ code: 1, ok: false, headline: `doctor: ${pr.prot.problems.length} problem(s)` });
    // And the base doctor still ignores the protected side.
    expect((await cli(f, ["doctor"], asImplementer())).code).toBe(plainJson.code);
  }, 240_000);
});
