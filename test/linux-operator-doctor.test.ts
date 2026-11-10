// POST-1 Linux operator doctor correction (TD POST-1-C1-CONDITIONAL-PASS §2): `doctor --protected --repo` names the
// repository as `status` and `setup` do (setup-commands.ts repositoryOf). On Linux, an operator who cannot resolve it
// locally (an untraversable implementer home, Git's ownership check) passes the plain absolute path, and the custodian
// resolves its identity; local resolution no longer stops the command. Windows, the implementer and N-4's exit codes are
// unchanged. Runs the real CLI without test hooks (no simulated custodian), as runs-admin does.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { chmod, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { git, gitExe, initRepo, linux, tempDir, writeFiles, commitFiles } from "./helpers/git-fixture.js";
import { doctorOutcome, runCli, type CliIo } from "../src/cli/cli.js";
import { repositoryOf } from "../src/cli/setup-commands.js";
import { custodianServicePresence } from "../src/custodian/service-presence.js";
import type { ProtectedDoctorFacts } from "../src/engine/doctor.js";
import type { Loaded } from "../src/engine/engine-env.js";

const io = () => {
  const lines: string[] = [];
  const errors: string[] = [];
  const x: CliIo = { out: (l) => lines.push(l), err: (l) => errors.push(l), prompt: null, interactive: false, env: process.env, cwd: process.cwd() };
  return { x, lines, errors };
};
/** A Loaded with only what repositoryOf reads: the launch's git, the source environment, whether test hooks are set. */
const loaded = (testHooks?: unknown) => ({ env: { launch: {}, sourceEnv: process.env, ...(testHooks ? { testHooks } : {}) } }) as unknown as Loaded;

describe("repositoryOf: the repository as an operator command names it", () => {
  let base = "";
  beforeAll(async () => {
    base = await tempDir("cp-linux-op-doctor-unit-");
  });

  it("returns the git top level when this account can resolve it, on every platform", async () => {
    const repo = await initRepo(join(base, "readable"));
    await writeFiles(repo, { "a.txt": "a\n" });
    commitFiles(repo);
    await mkdir(join(repo, "sub"));
    const top = git(repo, ["rev-parse", "--show-toplevel"]).stdout.trim();
    expect((await repositoryOf(loaded(), join(repo, "sub"))).replaceAll("\\", "/").toLowerCase()).toBe(top.replaceAll("\\", "/").toLowerCase());
  });

  it("on Linux falls back to the plain absolute path when it cannot; elsewhere, and with test hooks, the error stands", async () => {
    const missing = join(base, "no-such-home", "repo");
    if (linux) {
      expect(await repositoryOf(loaded(), missing)).toBe(missing);
      await expect(repositoryOf(loaded({}), missing)).rejects.toThrow();
      // Not a plain absolute path: refused, as for every Linux operator command.
      await expect(repositoryOf(loaded(), `${missing}/`)).rejects.toThrow(/plain absolute path/);
    } else {
      await expect(repositoryOf(loaded(), missing)).rejects.toThrow();
    }
  });
});

const root = typeof process.getuid === "function" && process.getuid() === 0;
const presence = linux ? await custodianServicePresence() : "absent";
const skip = !linux ? "the operator's plain-path fallback is Linux-only" : root ? "running as root, which traverses any home" : presence !== "absent" ? "a custodian is installed on this host (the CLI would require the approved runtime)" : null;
if (skip) console.warn(`linux-operator-doctor: the CLI tests are skipped: ${skip}`);

describe.skipIf(skip !== null)("doctor --protected --repo as a Linux operator who cannot traverse the implementer's home", () => {
  let base = "";
  let home = "";
  let repo = "";
  let data = "";
  beforeAll(async () => {
    base = await tempDir("cp-linux-op-doctor-");
    home = join(base, "implementer-home");
    repo = await initRepo(join(home, "repo"));
    await writeFiles(repo, { "a.txt": "a\n" });
    commitFiles(repo);
    data = join(base, "operator-data");
    await chmod(home, 0o000); // the separate operator account's view: no search permission on the home
  });
  afterAll(async () => {
    if (home) await chmod(home, 0o755);
  });

  const run = async (args: string[]) => {
    const c = io();
    const code = await runCli([...args, "--home", data, "--git", await gitExe()], c.x);
    return { code, out: c.lines.join("\n"), err: c.errors.join("\n") };
  };

  it("reaches the protected status with the plain path instead of failing at realpath, and keeps N-4's exit code", async () => {
    const base = JSON.parse((await run(["doctor", "--json"])).out) as { ok: boolean; problems: string[] };
    const j = await run(["doctor", "--protected", "--repo", repo, "--json"]);
    expect(j.err).not.toMatch(/EACCES|NOT_A_GIT_WORKTREE|not a git work tree/);
    const doc = JSON.parse(j.out) as { ok: boolean; protected?: ProtectedDoctorFacts };
    expect(doc.protected).toBeDefined();
    const want = doctorOutcome(base, doc.protected!);
    expect(j.code).toBe(want.code); // the exit still reflects the base doctor's problems and unverified records
    expect(doc.ok).toBe(want.ok);
    const t = await run(["doctor", "--protected", "--repo", repo]);
    expect(t.code).toBe(want.code);
    expect(t.out).toContain("--- protected (the custodian; a display: it decides nothing) ---");
    expect(t.out.split("\n").at(-1)).toBe(want.headline);
    // status names the repository the same way.
    const s = await run(["status", "--repo", repo, "--json"]);
    expect(s.err).not.toMatch(/EACCES|NOT_A_GIT_WORKTREE/);
    expect(JSON.parse(s.out)).toMatchObject({ state: doc.protected!.status.state });
  });

  it("still refuses a path that is not a plain absolute path", async () => {
    const r = await run(["doctor", "--protected", "--repo", `${repo}/`]);
    expect(r.code).not.toBe(0);
    expect(`${r.out}\n${r.err}`).toContain("plain absolute path");
  });
});
