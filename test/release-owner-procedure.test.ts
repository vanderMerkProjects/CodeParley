// TD C-1 correction (POST-1-C1-CONDITIONAL-PASS): the owner's source check in docs/releasing.md §4, RUN as documented.
// The first PowerShell block of "4. Sign (owner)" is taken from the document and executed by PowerShell 7 against
// disposable fixtures, with DISPOSABLE keys in a GnuPG home of its own: never the owner's keys or keyring. Only these
// substitutions are made: the typed answers come from the test; the pinned commit-key fingerprint is replaced by the
// disposable key's; the fixture's own scripts/package/verify-release.mjs is a stub that reports it ran. Every step
// must stop at its first failure, before any code from the clone runs.
// Windows with Gpg4win and PowerShell 7 only (the document's own tools); elsewhere the tests are skipped with the reason.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { git, initRepo, setupEnv, tempDir, writeFiles } from "./helpers/git-fixture.js";

const GPG = "C:\\Program Files\\GnuPG\\bin\\gpg.exe";
const PINNED = "261E3060E70B4904615F17BD026A2C3E92B42B25";
const pwsh = process.platform === "win32" ? spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.Major"], { encoding: "utf8", windowsHide: true }) : null;
const skip = process.platform !== "win32" ? "the owner's procedure is PowerShell with Gpg4win on Windows"
  : !existsSync(GPG) ? `Gpg4win is not installed (${GPG})`
  : pwsh?.status !== 0 ? "PowerShell 7 (pwsh) is not available"
  : null;
if (skip) console.warn(`release-owner-procedure: skipped: ${skip}`);

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const doc = readFileSync(join(root, "docs", "releasing.md"), "utf8");
const sign = doc.slice(doc.indexOf("### 4. Sign (owner)"), doc.indexOf("### 5. Publish"));
const open = sign.indexOf("```powershell\n") + "```powershell\n".length;
const BLOCK = sign.slice(open, sign.indexOf("```", open));

let base = "";
let home = "";
let origin = "";
const keys = { owner: "", stranger: "", strangerSub: "" };
const c = { base: "", good: "", unsigned: "", stranger: "" };

const gpg = (args: string[]) => {
  const r = spawnSync(GPG, ["--homedir", home, "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", "", ...args], { encoding: "utf8", windowsHide: true, timeout: 120_000 });
  if (r.status !== 0) throw new Error(`gpg ${args.join(" ")}: ${r.stderr}`);
  return r.stdout;
};
const primaryOf = (uid: string) => gpg(["--with-colons", "--fingerprint", "--list-keys", uid]).split(/\r?\n/).find((l) => l.startsWith("fpr:"))!.split(":")[9]!;
const env = () => setupEnv({ GNUPGHOME: home });

/** The document's block, with the test's answers, the disposable pinned key, and nothing else changed. */
function script(answers: Record<string, string>): string {
  let s = BLOCK.replace(/Read-Host '([^']*)'/g, (_m, prompt: string) => {
    if (!(prompt in answers)) throw new Error(`no answer for the prompt ${prompt}`);
    return `'${answers[prompt]!.replaceAll("'", "''")}'`;
  });
  // The block names the pinned key (release-signing.test.ts checks that it does); here it becomes the disposable one.
  s = s.replaceAll(PINNED, keys.owner);
  return `$ErrorActionPreference = 'Continue'\n${s}\n'PROCEDURE COMPLETED'\n`;
}

let n = 0;
/** A fresh clone of the fixture's origin, `prepare` applied to it, then the documented block for `commit`. */
function run(commit: string, prepare: (clone: string) => void = () => undefined) {
  const clone = join(base, `clone-${++n}`);
  git(base, ["clone", "-q", origin, clone]);
  prepare(clone);
  const file = join(base, `owner-${n}.ps1`);
  writeFileSync(file, script({
    "A fresh clone of https://github.com/vanderMerkProjects/CodeParley": clone,
    "Version, from the TD acceptance record": "1.0.1",
    "Source commit (40 hex), from the TD acceptance record": commit,
    "Manifest SHA-256 (64 hex), from the TD acceptance record": "0".repeat(64),
    "The signing package directory": join(base, "pkg"),
  }));
  const r = spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-File", file], { encoding: "utf8", windowsHide: true, env: env(), timeout: 180_000 });
  return { status: r.status, out: `${r.stdout}\n${r.stderr}`, ran: (r.stdout ?? "").includes("STUB verify-release ran"), completed: (r.stdout ?? "").includes("PROCEDURE COMPLETED") };
}

describe.skipIf(skip !== null)("TD C-1 correction: the owner's source check in releasing.md §4 fails closed, as documented", { timeout: 300_000 }, () => {
  beforeAll(async () => {
    base = await tempDir("cp-owner-proc-");
    home = join(base, "gnupg");
    mkdirSync(home);
    writeFileSync(join(home, "gpg-agent.conf"), "disable-scdaemon\nallow-loopback-pinentry\n");
    writeFileSync(join(home, "common.conf"), "");
    gpg(["--quick-gen-key", "Disposable Owner <owner@example.invalid>", "ed25519", "sign", "1d"]);
    keys.owner = primaryOf("Disposable Owner");
    gpg(["--quick-gen-key", "Disposable Stranger <stranger@example.invalid>", "ed25519", "cert", "1d"]);
    keys.stranger = primaryOf("Disposable Stranger");
    gpg(["--quick-add-key", keys.stranger, "ed25519", "sign", "1d"]);
    keys.strangerSub = gpg(["--with-colons", "--fingerprint", "--with-subkey-fingerprints", "--list-keys", keys.stranger]).split(/\r?\n/).filter((l) => l.startsWith("fpr:")).map((l) => l.split(":")[9]!)[1]!;
    origin = await initRepo(join(base, "origin"));
    const commit = async (files: Record<string, string>, msg: string, key: string | null) => {
      await writeFiles(origin, files);
      git(origin, ["add", "-A"]);
      git(origin, [...(key ? ["-c", `gpg.program=${GPG.replaceAll("\\", "/")}`, "-c", `user.signingkey=${key}`] : []), "commit", "-q", ...(key ? ["-S"] : []), "-m", msg], { env: { GNUPGHOME: home } });
      return git(origin, ["rev-parse", "HEAD"]).stdout.trim();
    };
    c.base = await commit({ "readme.txt": "base\n" }, "base", null);
    // The release source: its own verify-release.mjs is a stub that only reports that it ran, and from which commit.
    const stub = [
      "import { execFileSync } from 'node:child_process';",
      "import { fileURLToPath } from 'node:url';",
      "const clone = fileURLToPath(new URL('../..', import.meta.url));",
      "console.log(`STUB verify-release ran from ${execFileSync('git', ['-C', clone, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()}`);",
      "",
    ].join("\n");
    c.good = await commit({ "scripts/package/verify-release.mjs": stub, "state.txt": "good\n" }, "the owner-signed release source", keys.owner);
    c.unsigned = await commit({ "state.txt": "unsigned\n" }, "an unsigned commit", null);
    c.stranger = await commit({ "state.txt": "stranger\n" }, "signed by a stranger", `${keys.strangerSub}!`);
  });

  afterAll(() => {
    if (!base) return;
    spawnSync(join(GPG, "..", "gpgconf.exe"), ["--homedir", home, "--kill", "all"], { windowsHide: true });
    rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  });

  it("runs the verifier from the checked-out source only once its identity is established", () => {
    const r = run(c.good);
    expect(r.status, r.out).toBe(0);
    expect(r.out).toContain(`STUB verify-release ran from ${c.good}`);
    expect(r.completed).toBe(true);
  });

  it("stops on a source id that is not 40 hex digits", () => {
    const r = run(c.good.slice(0, 12));
    expect(r.out).toContain("STOP: the source commit must be its full 40-character id");
    expect([r.ran, r.completed]).toEqual([false, false]);
  });

  it("stops on a failed fetch", () => {
    const r = run(c.good, (clone) => git(clone, ["remote", "set-url", "origin", join(base, "no-such-origin")]));
    expect(r.out).toContain("STOP: the fetch failed");
    expect([r.ran, r.completed]).toEqual([false, false]);
  });

  it("stops before the checkout on a missing, foreign or unverifiable signature", () => {
    for (const [what, commit] of [["unsigned", c.unsigned], ["a stranger's", c.stranger]] as const) {
      const r = run(commit);
      expect(r.out, what).toContain(`STOP: the source commit is not signed by the commit key ${keys.owner}`);
      expect([r.ran, r.completed], what).toEqual([false, false]);
    }
    // The pinned key is not in the owner's keyring: GnuPG cannot verify the signature (no GOODSIG).
    const missing = run(c.good, () => {
      const r = spawnSync(GPG, ["--homedir", home, "--batch", "--yes", "--delete-secret-and-public-key", keys.owner], { encoding: "utf8", windowsHide: true });
      if (r.status !== 0) throw new Error(r.stderr);
    });
    expect(missing.out).toContain(`STOP: the source commit is not signed by the commit key ${keys.owner}`);
    expect([missing.ran, missing.completed]).toEqual([false, false]);
  });
});

describe.skipIf(skip !== null)("TD C-1 correction: the checkout must be exactly the accepted commit", { timeout: 300_000 }, () => {
  // A separate fixture, since the signature tests above delete the owner's key from its keyring.
  beforeAll(async () => {
    base = await tempDir("cp-owner-proc-co-");
    home = join(base, "gnupg");
    mkdirSync(home);
    writeFileSync(join(home, "gpg-agent.conf"), "disable-scdaemon\nallow-loopback-pinentry\n");
    writeFileSync(join(home, "common.conf"), "");
    gpg(["--quick-gen-key", "Disposable Owner <owner@example.invalid>", "ed25519", "sign", "1d"]);
    keys.owner = primaryOf("Disposable Owner");
    origin = await initRepo(join(base, "origin"));
    await writeFiles(origin, { "readme.txt": "base\n" });
    git(origin, ["add", "-A"]);
    git(origin, ["commit", "-q", "-m", "base"]);
    c.base = git(origin, ["rev-parse", "HEAD"]).stdout.trim();
    await writeFiles(origin, { "scripts/package/verify-release.mjs": "console.log('STUB verify-release ran');\n", "state.txt": "good\n" });
    git(origin, ["add", "-A"]);
    git(origin, ["-c", `gpg.program=${GPG.replaceAll("\\", "/")}`, "-c", `user.signingkey=${keys.owner}`, "commit", "-q", "-S", "-m", "the owner-signed release source"], { env: { GNUPGHOME: home } });
    c.good = git(origin, ["rev-parse", "HEAD"]).stdout.trim();
    await writeFiles(origin, { "state.txt": "later\n" });
    git(origin, ["add", "-A"]);
    git(origin, ["commit", "-q", "-m", "main moved on"]);
  });

  afterAll(() => {
    if (!base) return;
    spawnSync(join(GPG, "..", "gpgconf.exe"), ["--homedir", home, "--kill", "all"], { windowsHide: true });
    rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  });

  it("stops on a failed checkout", () => {
    // A local change to a file the checkout would overwrite: git refuses the checkout.
    const r = run(c.good, (clone) => writeFileSync(join(clone, "state.txt"), "edited\n"));
    expect(r.out).toContain("STOP: the checkout failed");
    expect([r.ran, r.completed]).toEqual([false, false]);
  });

  it("stops when HEAD is not the typed commit after the checkout, or the tree has changes", () => {
    // A post-checkout hook moves HEAD elsewhere: the checkout itself succeeds.
    const moved = run(c.good, (clone) => {
      const hook = join(clone, ".git", "hooks", "post-checkout");
      writeFileSync(hook, `#!/bin/sh\ngit update-ref --no-deref HEAD ${c.base}\n`);
    });
    expect(moved.out).toContain("STOP: the checkout is not exactly the accepted commit");
    expect([moved.ran, moved.completed]).toEqual([false, false]);
    // An untracked file in the clone.
    const dirty = run(c.good, (clone) => writeFileSync(join(clone, "extra.txt"), "x\n"));
    expect(dirty.out).toContain("STOP: the checkout is not exactly the accepted commit");
    expect([dirty.ran, dirty.completed]).toEqual([false, false]);
  });
});
