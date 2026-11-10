// Step 4: the release-signing workflow (scripts/package/prepare-signing.mjs, verify-release.mjs and
// lib/release-verify.mjs), end to end with DISPOSABLE keys made for the test in GnuPG homes of its own, with smart cards
// disabled: never the release key, never a YubiKey. A fixture repository carries the files the real one pins (the
// commit key in .github/ci/, the release key in docs/), so the scripts run their production checks with only the pinned
// fingerprints replaced. Platform-independent. The GnuPG tests are skipped, with the reason, only where no GnuPG is
// installed or where it is the known-incompatible MSYS build; any other GnuPG that fails the probe fails them.

import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { appendFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { gzipSync } from "node:zlib";
import { fileURLToPath, pathToFileURL } from "node:url";
import { git, initRepo, tempDir, writeFiles } from "./helpers/git-fixture.js";

interface Pins { primary: string; subkeys: { fpr: string; current: boolean }[] }
interface Sub { fpr: string; created: number; expires: number; validity: string; capabilities: string }
interface Key { primary: string; validity: string; created: number; expires: number; capabilities: string; subkeys: Sub[] }
interface Kr { gpg: string; home: string; base: string[] }
type Log = (s: string) => void;
interface Release { tag_name: string; draft: boolean; prerelease: boolean; id: number; html_url: string; assets: { name: string; size: number; digest: string; state: string }[] }
const lib = (await import(new URL("../scripts/package/lib/release-verify.mjs", import.meta.url).href)) as {
  defaultGpg(): string; sha256(b: Buffer | string): string; tagMessage(v: string, d: string): string;
  withKeyring<T>(gpg: string, keys: string[], fn: (kr: Kr) => T): T; listKeys(kr: Kr): Key[];
  pinProblems(p: unknown): string[]; signatureStatusProblems(s: string, code: number | null, p: Pins, keys?: Key[], o?: { expectSubkey?: string }): string[];
  verifyDetached(o: { gpg: string; keyArmored: string; pins: Pins; signatureFile: string; dataFile: string }): { problems: string[]; keyExpired: boolean };
  releaseKeyProblems(keys: Key[], pins: Pins, o?: { forSigning?: boolean; now?: number }): string[];
  RELEASE_KEY: Pins & { file: string }; COMMIT_KEY: { primary: string; file: string }; MAIN_REF: string;
  integrationOf(o: { repo: string; commit: string; mainRef?: string }): Integration;
  releaseSourceProblems(o: SourceArgs & { rehearsal?: boolean }): { problems: string[]; integration: Integration | null };
  stagingSourceGate(o: SourceArgs & { dirty: boolean; signature: string; testBuild: boolean }): { required: boolean; problems: string[]; integration: Integration | null; why: string };
};
interface Integration { problems: string[]; main: string | null; merge: string | null; tree: string | null }
interface SourceArgs { repo: string; commit: string; version: string; gpg: string; pins: Pins; commitPin: string; mainRef?: string }
const manifestLib = (await import(new URL("../scripts/package/lib/release-manifest.mjs", import.meta.url).href)) as {
  ARTIFACTS: { name: string }[]; buildId(i: Record<string, unknown>): Record<string, unknown>; buildManifest(i: Record<string, unknown>): Record<string, unknown> & { artifacts: { file: string }[] };
};
const { prepare } = (await import(new URL("../scripts/package/prepare-signing.mjs", import.meta.url).href)) as { prepare(argv: string[], deps: { pins: Pins; commitPin: string; repo: string; log: Log; now?: number }): number };
const { verify } = (await import(new URL("../scripts/package/verify-release.mjs", import.meta.url).href)) as {
  verify(argv: string[], deps: { pins: Pins; commitPin: string; repoPin?: { name: string; id: number }; github?: (p: string) => unknown; log: Log }): number;
};

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
// CP_RELEASE_TEST_GPG points the suite at another GnuPG (to check the probe below against a specific build).
const gpg = process.env.CP_RELEASE_TEST_GPG || lib.defaultGpg();
const gpgconf = /[\\/]/.test(gpg) ? join(dirname(gpg), process.platform === "win32" ? "gpgconf.exe" : "gpgconf") : "gpgconf";

/**
 * Whether this GnuPG can run the suite. Everything here (and in the tools) uses a temporary home of its own, so the probe
 * initializes one, isolated like the suite's homes, and requires its keyring to exist afterwards: an exit status alone
 * proves nothing (Git for Windows' MSYS gpg exits 0 after some fatal errors). Exactly two cases skip the GnuPG tests,
 * each with its reason: no GnuPG at all, and the known-incompatible MSYS build, which resolves `--homedir C:\...` under
 * the current directory (its `Home:` line shows the Windows path appended to a POSIX one). Any other GnuPG that cannot
 * initialize the keyring, a broken Gpg4win or Linux gpg included, makes the suite fail.
 */
function gpgSupport(): { skip?: string; broken?: string } {
  const h = mkdtempSync(join(tmpdir(), "cp-relsign-probe-"));
  try {
    writeFileSync(join(h, "gpg-agent.conf"), "disable-scdaemon\n");
    writeFileSync(join(h, "common.conf"), "");
    const version = spawnSync(gpg, ["--homedir", h, "--version"], { encoding: "utf8", windowsHide: true, timeout: 60_000 });
    if ((version.error as NodeJS.ErrnoException | undefined)?.code === "ENOENT") return { skip: `no GnuPG found (${gpg})` };
    const list = spawnSync(gpg, ["--homedir", h, "--batch", "--no-tty", "--list-keys"], { encoding: "utf8", windowsHide: true, timeout: 60_000 });
    const keyring = existsSync(join(h, "pubring.kbx"));
    if (list.status === 0 && keyring) return {};
    const reported = /^Home: (.*)$/m.exec(version.stdout ?? "")?.[1]?.trim() ?? "";
    const detail = `${gpg}: --list-keys exited ${list.status ?? list.error?.message}, keyring ${keyring ? "created" : "not created"}, Home: ${reported || "(none)"}`;
    if (process.platform === "win32" && reported.startsWith("/") && reported.endsWith(h)) {
      return { skip: `known-incompatible GnuPG, Git for Windows' MSYS build (it resolves a Windows --homedir under the current directory); install Gpg4win to run these tests. ${detail}` };
    }
    return { broken: `GnuPG cannot initialize an isolated keyring. ${detail}. ${(list.stderr ?? "").trim()}` };
  } finally {
    spawnSync(gpgconf, ["--homedir", h, "--kill", "all"], { windowsHide: true });
    rmSync(h, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
}
const support = gpgSupport();
if (support.skip) console.warn(`release-signing: the GnuPG tests are skipped: ${support.skip}`);
const VERSION = "1.0.1";
const ROTATED = "1.0.2";
const REHEARSAL = "1.0.1-rehearsal.1";
const LATER = "20300101T000000"; // long after the disposable subkeys' one-day expiry

let base = "";
let home = "";
let repo = "";
// c.main0, c.merge1, c.merge2: the fixture's main (refs/remotes/origin/main = c.merge2), as GitHub builds it: main before
// the milestone, then the GitHub merge of c.commit (the owner-signed release source) and the GitHub merge of c.rotated.
const c = { commit: "", other: "", rotated: "", main0: "", merge1: "", merge2: "" };
const keys = { commit: "", release: "", releaseSub: "", releaseSub2: "", stranger: "", strangerSub: "", expiring: "", expiringSub: "" };
const pub: Record<string, string> = {};

const gpgIn = (h: string, args: string[], input?: string) => {
  const r = spawnSync(gpg, ["--homedir", h, "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", "", ...args], { encoding: "utf8", windowsHide: true, input, timeout: 120_000 });
  if (r.status !== 0) throw new Error(`gpg ${args.join(" ")}: ${r.stderr}`);
  return r.stdout;
};
const g = (args: string[], input?: string) => gpgIn(home, args, input);
const fprsOf = (h: string, uid: string) => {
  const lines = gpgIn(h, ["--with-colons", "--fingerprint", "--with-subkey-fingerprints", "--list-keys", uid]).split(/\r?\n/);
  return { primary: lines.find((l, i) => l.startsWith("fpr:") && lines[i - 1]?.startsWith("pub:"))!.split(":")[9]!, subs: lines.filter((l, i) => l.startsWith("fpr:") && lines[i - 1]?.startsWith("sub:")).map((l) => l.split(":")[9]!) };
};
const newHome = (name: string) => {
  const h = join(base, name);
  mkdirSync(h);
  writeFileSync(join(h, "gpg-agent.conf"), "disable-scdaemon\nallow-loopback-pinentry\n");
  writeFileSync(join(h, "common.conf"), "");
  return h;
};
const sign = (key: string, file: string, out: string) => g(["--yes", "--armor", "--detach-sign", "--local-user", `${key}!`, "--output", out, file]);
const gitEnv = () => ({ GNUPGHOME: home });
const gpgProgram = () => gpg.replaceAll("\\", "/");
const P1 = (): Pins => ({ primary: keys.release, subkeys: [{ fpr: keys.releaseSub, current: true }] });
const P2 = (): Pins => ({ primary: keys.release, subkeys: [{ fpr: keys.releaseSub, current: false }, { fpr: keys.releaseSub2, current: true }] });
const quiet = () => {
  const out: string[] = [];
  return { log: (s: string) => void out.push(s), text: () => out.join("") };
};

/** A gzip-compressed ustar archive of `files`, like stage-release's `tar -czf … -C dir .`. */
function tarGz(files: Record<string, string>): Buffer {
  const blocks: Buffer[] = [];
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content);
    const h = Buffer.alloc(512);
    h.write(name, 0, 100);
    h.write("0000644\0", 100);
    h.write("0000000\0", 108);
    h.write("0000000\0", 116);
    h.write(`${data.length.toString(8).padStart(11, "0")}\0`, 124);
    h.write("00000000000\0", 136);
    h.write("        ", 148);
    h.write("0", 156);
    h.write("ustar\0", 257);
    h.write("00", 263);
    let sum = 0;
    for (const b of h) sum += b;
    h.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148);
    blocks.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

interface StageOptions { version?: string; commit?: string; testBuild?: boolean; tweak?: (name: string, id: Record<string, unknown>) => void; insideId?: (name: string, id: Record<string, unknown>) => void }
/** A staged release as stage-release.mjs writes it; `tweak` changes a BUILD-ID before anything is written. */
function stage(dir: string, o: StageOptions = {}): string {
  const version = o.version ?? VERSION;
  const at = o.commit ?? c.commit;
  mkdirSync(dir, { recursive: true });
  const entries = manifestLib.ARTIFACTS.map(({ name }) => {
    const id = manifestLib.buildId({ artifact: name, version, commit: at, signature: "verified", dirty: false, testBuild: o.testBuild ?? false, toolchain: { dotnetSdk: "10.0.403", node: "v24.11.0", npm: "11.6.1" }, builtAt: "2026-11-03T12:00:00.000Z" });
    if (name.startsWith("engine-runtime-")) id.node = "v24.21.0";
    o.tweak?.(name, id);
    const carried = JSON.parse(JSON.stringify(id)) as Record<string, unknown>;
    o.insideId?.(name, carried);
    const sidecar = name === "npm-tarball" || name.startsWith("installer-");
    const file = name === "npm-tarball" ? `code-parley-${version}.tgz` : name === "installer-windows" ? "codeparley-installer.ps1" : name === "installer-linux" ? "codeparley-installer.sh" : `${name}.tar.gz`;
    const data = sidecar ? Buffer.from(`${name} ${version}\n`) : tarGz({ "./BUILD-ID": `${JSON.stringify(carried, null, 2)}\n`, "./payload.txt": `${name}\n` });
    writeFileSync(join(dir, file), data);
    if (sidecar) writeFileSync(join(dir, `${file}.BUILD-ID`), `${JSON.stringify(carried, null, 2)}\n`);
    return { name, file, size: data.length, sha256: lib.sha256(data), buildId: id };
  });
  const m = manifestLib.buildManifest({ version, commit: at, signature: "verified", dirty: false, entries, testBuild: o.testBuild ?? false });
  const text = `${JSON.stringify(m, null, 2)}\n`;
  writeFileSync(join(dir, "release-manifest.json"), text);
  return lib.sha256(text);
}

interface RunOptions { version?: string; commit?: string; rehearsal?: boolean; pins?: Pins; gpg?: string; now?: number; github?: (p: string) => unknown; published?: boolean }
const args = (dir: string, digest: string, o: RunOptions = {}) => [
  "--version", o.version ?? VERSION, "--commit", o.commit ?? c.commit, "--manifest-sha256", digest, "--gpg", o.gpg ?? gpg, ...(o.rehearsal ? ["--rehearsal"] : []),
  ...(dir ? ["--dir", dir] : []),
];
const runPrepare = (staged: string, out: string, digest: string, o: RunOptions = {}) => {
  const q = quiet();
  const code = prepare(["--staged", staged, "--out", out, ...args("", digest, o)], { pins: o.pins ?? P1(), commitPin: keys.commit, repo, log: q.log, ...(o.now ? { now: o.now } : {}) });
  return { code, out: q.text() };
};
const noNetwork = () => { throw new Error("no network in this test"); };
const runVerify = (step: string, dir: string, digest: string, o: RunOptions = {}) => {
  const q = quiet();
  const code = verify([step, ...args(dir, digest, o), "--repo", repo, ...(o.published ? ["--published"] : [])], { pins: o.pins ?? P1(), commitPin: keys.commit, repoPin: { name: "example/CodeParley", id: 42 }, github: o.github ?? noNetwork, log: q.log });
  return { code, out: q.text() };
};
const report = (pkg: string, digest: string, o: RunOptions = {}) => {
  const q = quiet();
  expect(verify(["report", ...args(pkg, digest, o), "--repo", repo], { pins: o.pins ?? P1(), commitPin: keys.commit, log: q.log })).toBe(0);
  return readFileSync(join(pkg, "RELEASE-REPORT.md"), "utf8");
};
const row = (md: string, step: string) => md.split("\n").find((l) => l.startsWith(`| ${step} |`)) ?? "";
/** A fresh signing package of a fresh staged release: { pkg, digest, staged }. */
let n = 0;
function prepared(o: RunOptions = {}) {
  const dir = join(base, `case-${++n}`);
  const staged = join(dir, "staged");
  const digest = o.rehearsal ? stage(staged, { version: REHEARSAL, testBuild: true }) : stage(staged, { version: o.version, commit: o.commit });
  const pkg = join(dir, "pkg");
  const r = runPrepare(staged, pkg, digest, o.rehearsal ? { version: REHEARSAL, rehearsal: true } : o);
  if (r.code !== 0) throw new Error(r.out);
  return { pkg, digest, staged };
}
const signManifest = (pkg: string, key = keys.releaseSub) => sign(key, join(pkg, "release-manifest.json"), join(pkg, "release-manifest.json.asc"));
const tag = (name: string, target: string, message: string, key = keys.releaseSub) => {
  const msg = join(base, `tag-${++n}.txt`);
  writeFileSync(msg, message);
  git(repo, ["-c", `gpg.program=${gpgProgram()}`, "-c", `user.signingkey=${key}!`, "tag", "-s", name, target, "-F", msg], { env: gitEnv() });
};
const remove = (name: string) => git(repo, ["tag", "-d", name], { allowFail: true });
const GITHUB = "GitHub <noreply@github.com>";
let at = 1794079200;
/** A raw commit object, written as GitHub writes a web merge (C-1 research, D-107): unsigned here, since the release
 *  contract never verifies GitHub's own signature; `committer` makes the other shapes. */
const rawCommit = (tree: string, parents: string[], committer = GITHUB, msg = "Merge pull request #9 from example/milestone") =>
  git(repo, ["hash-object", "-t", "commit", "-w", "--stdin"], { input: `tree ${tree}\n${parents.map((p) => `parent ${p}\n`).join("")}author Fixture <fixture@example.invalid> ${++at} +0000\ncommitter ${committer} ${at} +0000\n\n${msg}\n` }).stdout.trim();
const treeOf = (commit: string) => git(repo, ["rev-parse", `${commit}^{tree}`]).stdout.trim();
/** A GitHub merge of `head` into `main`, with `head`'s tree (the milestone contains main). */
const githubMerge = (main: string, head: string, tree = treeOf(head)) => rawCommit(tree, [main, head]);
const setMain = (sha: string | null, ref = "refs/remotes/origin/main") => (sha ? git(repo, ["update-ref", ref, sha]) : git(repo, ["update-ref", "-d", ref]));
/** Run `fn` with the clone's fetched main at `sha`, then put the fixture's main back. */
const withMain = <T>(sha: string | null, fn: () => T): T => {
  setMain(sha);
  try { return fn(); } finally { setMain(c.merge2); }
};

describe("Step 4: release-signing workflow, with disposable keys", { timeout: 180_000 }, () => {
  // A skip carries its reason on every test; a broken GnuPG fails every test (in beforeAll, vitest would list them as
  // skipped).
  beforeEach(({ skip }) => {
    if (support.skip) skip(support.skip);
    if (support.broken) throw new Error(support.broken);
  });

  beforeAll(async () => {
    if (support.skip || support.broken) return;
    base = await tempDir("cp-relsign-");
    home = newHome("gnupg");
    g(["--quick-gen-key", "Disposable Commit <commit@example.invalid>", "ed25519", "sign", "1d"]);
    keys.commit = fprsOf(home, "Disposable Commit").primary;
    g(["--quick-gen-key", "Disposable Release <release@example.invalid>", "ed25519", "cert", "2y"]);
    keys.release = fprsOf(home, "Disposable Release").primary;
    g(["--quick-add-key", keys.release, "ed25519", "sign", "1d"]);
    keys.releaseSub = fprsOf(home, keys.release).subs[0]!;
    pub.releaseA = g(["--armor", "--export", keys.release]); // the key file before the rotation: one subkey
    g(["--quick-add-key", keys.release, "ed25519", "sign", "1d"]);
    keys.releaseSub2 = fprsOf(home, keys.release).subs.find((s) => s !== keys.releaseSub)!;
    pub.releaseB = g(["--armor", "--export", keys.release]); // after it: both subkeys
    g(["--quick-gen-key", "Disposable Stranger <stranger@example.invalid>", "ed25519", "cert", "1d"]);
    keys.stranger = fprsOf(home, "Disposable Stranger").primary;
    g(["--quick-add-key", keys.stranger, "ed25519", "sign", "1d"]);
    keys.strangerSub = fprsOf(home, keys.stranger).subs[0]!;
    g(["--quick-gen-key", "Disposable Expiring <expiring@example.invalid>", "ed25519", "cert", "2y"]);
    keys.expiring = fprsOf(home, "Disposable Expiring").primary;
    g(["--quick-add-key", keys.expiring, "ed25519", "sign", "1d"]);
    keys.expiringSub = fprsOf(home, keys.expiring).subs[0]!;
    pub.commit = g(["--armor", "--export", keys.commit]);
    pub.expiring = g(["--armor", "--export", keys.expiring]);
    repo = await initRepo(join(base, "repo"));
    const signed = async (files: Record<string, string>, msg: string) => {
      await writeFiles(repo, files);
      git(repo, ["add", "-A"]);
      git(repo, ["-c", `gpg.program=${gpgProgram()}`, "-c", `user.signingkey=${keys.commit}`, "commit", "-q", "-S", "--allow-empty", "-m", msg], { env: gitEnv() });
      return git(repo, ["rev-parse", "HEAD"]).stdout.trim();
    };
    c.commit = await signed({ "package.json": `${JSON.stringify({ name: "code-parley", version: VERSION })}\n`, ".github/ci/commit-signing-key.asc": pub.commit, "docs/codeparley-release-key.asc": pub.releaseA! }, "release source");
    c.other = await signed({}, "a later commit");
    c.rotated = await signed({ "package.json": `${JSON.stringify({ name: "code-parley", version: ROTATED })}\n`, "docs/codeparley-release-key.asc": pub.releaseB! }, "rotate the release signing subkey");
    // main, as GitHub builds it: it merged c.commit's pull request, then (main moved on) c.rotated's.
    c.main0 = rawCommit(git(repo, ["hash-object", "-t", "tree", "-w", "--stdin"], { input: "" }).stdout.trim(), [], "Fixture <fixture@example.invalid>", "main before the milestone");
    c.merge1 = githubMerge(c.main0, c.commit);
    c.merge2 = githubMerge(c.merge1, c.rotated);
    setMain(c.merge2);
  });

  afterAll(() => {
    if (!base) return;
    for (const h of readdirSync(base).filter((d) => d === "gnupg" || d.startsWith("gnupg-"))) spawnSync(gpgconf, ["--homedir", join(base, h), "--kill", "all"], { windowsHide: true });
    if (base) rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  });

  describe("prepare-signing", () => {
    it("copies a staged release byte for byte, with a comparison sheet that is not an authority", () => {
      const { pkg, digest, staged } = prepared();
      for (const f of readdirSync(staged)) expect(readFileSync(join(pkg, f)).equals(readFileSync(join(staged, f)))).toBe(true);
      expect(readdirSync(pkg).sort()).toEqual([...readdirSync(staged), "SIGNING-REQUEST.md", "signing-request.json"].sort());
      const req = JSON.parse(readFileSync(join(pkg, "signing-request.json"), "utf8")) as Record<string, unknown>;
      expect(req).toMatchObject({ version: VERSION, commit: c.commit, tag: "v1.0.1", rehearsal: false, manifest: { sha256: digest }, releaseKey: { primary: keys.release, signingSubkey: keys.releaseSub } });
      const md = readFileSync(join(pkg, "SIGNING-REQUEST.md"), "utf8");
      expect(md).toContain(digest);
      expect(md).toContain("It is not an authority and holds no commands");
      // C-1: nothing runnable, so nothing an owner could copy instead of typing the TD's values.
      expect(md).not.toMatch(/```|--detach-sign|tag -s|verify-release|Read-Host|--manifest-sha256|--local-user|\$gpg|gpg\.exe|& /);
      expect(md).not.toMatch(/REHEARSAL/);
    });

    it("is idempotent: a repeat, after an interruption or after signing, leaves the package unchanged", () => {
      const { pkg, digest, staged } = prepared();
      const before = readFileSync(join(pkg, "signing-request.json"), "utf8");
      mkdirSync(`${pkg}.partial-1-2`);
      writeFileSync(join(`${pkg}.partial-1-2`, "junk"), "x");
      const again = runPrepare(staged, pkg, digest);
      expect(again).toMatchObject({ code: 0 });
      expect(again.out).toContain("already prepared, unchanged");
      expect(existsSync(`${pkg}.partial-1-2`)).toBe(false);
      signManifest(pkg);
      expect(runPrepare(staged, pkg, digest).out).toContain("it holds release-manifest.json.asc");
      expect(readFileSync(join(pkg, "signing-request.json"), "utf8")).toBe(before);
    });

    it("never overwrites a package that differs, and leaves it as it was", () => {
      const { pkg, digest, staged } = prepared();
      appendFileSync(join(pkg, "codeparley-installer.sh"), "#");
      const r = runPrepare(staged, pkg, digest);
      expect(r.code).toBe(1);
      expect(r.out).toContain("exists and is not this package");
      expect(readFileSync(join(pkg, "codeparley-installer.sh"), "utf8").endsWith("#")).toBe(true);
    });

    it("fails closed on the digest, the commit, the version, the package location and unexpected content", () => {
      const dir = join(base, `refuse-${++n}`);
      const staged = join(dir, "staged");
      const digest = stage(staged);
      const out = join(dir, "pkg");
      expect(runPrepare(staged, out, "0".repeat(64)).out).toContain("not the accepted");
      expect(runPrepare(staged, out, digest, { commit: c.other }).out).toContain(`names commit ${c.commit}, not ${c.other}`);
      expect(runPrepare(staged, out, digest, { version: "1.0.3" }).out).toMatch(/package\.json at .* is version 1\.0\.1, not 1\.0\.3/);
      expect(runPrepare(staged, join(repo, "pkg"), digest).out).toContain("is inside the repository");
      expect(runPrepare(staged, out, digest, { rehearsal: true }).out).toContain("a rehearsal needs a --test-version build");
      writeFileSync(join(staged, "extra.txt"), "x");
      expect(runPrepare(staged, out, digest).out).toContain("unexpected entry extra.txt");
      expect(existsSync(out)).toBe(false);
    });

    it("fails closed on an altered artifact and on inconsistent BUILD-IDs", () => {
      const dir = join(base, `ids-${++n}`);
      const cases: [string, StageOptions, RegExp][] = [
        ["toolchain", { tweak: (name, id) => { if (name === "plugin-linux") (id.toolchain as Record<string, string>).dotnetSdk = "10.0.201"; } }, /plugin-linux: BUILD-ID toolchain .* differs/],
        ["built", { tweak: (name, id) => { if (name === "custodian-linux-x64") id.builtAt = "2026-11-03T13:00:00.000Z"; } }, /custodian-linux-x64: BUILD-ID build time .* differs/],
        ["inside", { insideId: (name, id) => { if (name === "custodian-windows-x64") id.commit = "b".repeat(40); } }, /custodian-windows-x64\.tar\.gz: the BUILD-ID it carries differs/],
        ["sidecar", { insideId: (name, id) => { if (name === "installer-linux") id.version = "9.9.9"; } }, /codeparley-installer\.sh: the BUILD-ID it carries differs/],
        ["candidate", { tweak: (name, id) => { if (name === "npm-tarball") id.releaseCandidate = false; } }, /npm-tarball: BUILD-ID's signature, dirty, testBuild or releaseCandidate differs/],
      ];
      for (const [label, o, want] of cases) {
        const staged = join(dir, label);
        const digest = stage(staged, o);
        expect(runPrepare(staged, join(dir, `${label}-pkg`), digest).out).toMatch(want);
      }
      const staged = join(dir, "altered");
      const digest = stage(staged);
      appendFileSync(join(staged, "engine-runtime-linux-x64.tar.gz"), "x");
      expect(runPrepare(staged, join(dir, "altered-pkg"), digest).out).toMatch(/engine-runtime-linux-x64\.tar\.gz is \d+ bytes.*\n.*has SHA-256/);
    });

    it("C-5: a new request names the current subkey, and is refused when the commit's key file lacks it or it has expired", () => {
      const rotated = prepared({ version: ROTATED, commit: c.rotated, pins: P2() });
      expect(JSON.parse(readFileSync(join(rotated.pkg, "signing-request.json"), "utf8"))).toMatchObject({ releaseKey: { signingSubkey: keys.releaseSub2 } });
      const dir = join(base, `cur-${++n}`);
      const staged = join(dir, "staged");
      const digest = stage(staged);
      expect(runPrepare(staged, join(dir, "a"), digest, { pins: P2() }).out).toContain(`the release key file has no current signing subkey ${keys.releaseSub2}`);
      expect(runPrepare(staged, join(dir, "b"), digest, { now: Date.parse("2030-01-01") / 1000 }).out).toContain(`the current subkey ${keys.releaseSub} has expired`);
      // The key file at the rotated commit holds a signing subkey the old pins never approved.
      const s2 = join(dir, "staged2");
      const d2 = stage(s2, { version: ROTATED, commit: c.rotated });
      expect(runPrepare(s2, join(dir, "c"), d2, { version: ROTATED, commit: c.rotated }).out).toContain(`a signing subkey ${keys.releaseSub2} that is not approved`);
    });
  });

  describe("verify-release", () => {
    it("package: passes on the prepared package; fails on an altered artifact, an unexpected file or another pinned key", () => {
      const { pkg, digest } = prepared();
      expect(runVerify("package", pkg, digest)).toMatchObject({ code: 0 });
      expect(JSON.parse(readFileSync(join(pkg, "verified-package.json"), "utf8"))).toMatchObject({ result: "PASS", step: "package", args: { version: VERSION, commit: c.commit, manifestSha256: digest, rehearsal: false } });
      const wrong = runVerify("package", pkg, digest, { pins: { primary: keys.stranger, subkeys: [{ fpr: keys.strangerSub, current: true }] } });
      expect(wrong.code).toBe(1);
      expect(wrong.out).toContain(`the release key file's primary key is ${keys.release}, not the pinned ${keys.stranger}`);
      expect(JSON.parse(readFileSync(join(pkg, "verified-package.json"), "utf8"))).toMatchObject({ result: "FAIL" }); // a failure is recorded too
      const copy = `${pkg}-altered`;
      cpSync(pkg, copy, { recursive: true });
      appendFileSync(join(copy, "plugin-windows.tar.gz"), "x");
      expect(runVerify("package", copy, digest).out).toContain("plugin-windows.tar.gz has SHA-256");
      const extra = `${pkg}-extra`;
      cpSync(pkg, extra, { recursive: true });
      writeFileSync(join(extra, "notes.txt"), "x");
      expect(runVerify("package", extra, digest).out).toContain("unexpected entry notes.txt");
    });

    it("C-1: the package's request is never an authority: values come only from the command line", () => {
      const { pkg, digest } = prepared();
      // No value, no verification: the request's own values are not used in their place.
      for (const drop of ["--version", "--commit", "--manifest-sha256"]) {
        const argv = ["package", ...args(pkg, digest), "--repo", repo];
        argv.splice(argv.indexOf(drop), 2);
        expect(() => verify(argv, { pins: P1(), commitPin: keys.commit, log: () => undefined }), drop).toThrow(/must be/);
      }
      // A package changed consistently (a new manifest and a request that names it) still fails against the TD's digest.
      const forged = `${pkg}-forged`;
      cpSync(pkg, forged, { recursive: true });
      const text = readFileSync(join(forged, "release-manifest.json"), "utf8").replace('"signed": false', '"signed": false ');
      writeFileSync(join(forged, "release-manifest.json"), text);
      const req = JSON.parse(readFileSync(join(forged, "signing-request.json"), "utf8")) as { manifest: { sha256: string } };
      req.manifest.sha256 = lib.sha256(text);
      writeFileSync(join(forged, "signing-request.json"), JSON.stringify(req));
      const r = runVerify("package", forged, digest);
      expect(r.code).toBe(1);
      expect(r.out).toContain(`has SHA-256 ${lib.sha256(text)}, not the accepted ${digest}`);
      expect(r.out).toContain("signing-request.json asks for another release than the command line");
      // A request cannot widen the keys: one naming an unapproved subkey fails, even before any signature.
      const widened = `${pkg}-widened`;
      cpSync(pkg, widened, { recursive: true });
      const w = JSON.parse(readFileSync(join(widened, "signing-request.json"), "utf8")) as { releaseKey: { signingSubkey: string } };
      w.releaseKey.signingSubkey = keys.strangerSub;
      writeFileSync(join(widened, "signing-request.json"), JSON.stringify(w));
      expect(runVerify("package", widened, digest).out).toContain("not the pinned primary with an approved signing subkey");
    });

    it("signature: passes for the release subkey; fails on an altered manifest, a stranger's key, the commit key and two signatures", () => {
      const { pkg, digest } = prepared();
      expect(runVerify("signature", pkg, digest).out).toContain("the owner has not signed the manifest");
      signManifest(pkg);
      const ok = runVerify("signature", pkg, digest);
      expect(ok).toMatchObject({ code: 0 });
      expect(ok.out).toContain(`signing subkey ${keys.releaseSub}`);

      // The manifest changed after signing (and the command names the changed manifest's digest): a bad signature.
      const altered = `${pkg}-altered`;
      cpSync(pkg, altered, { recursive: true });
      const text = readFileSync(join(altered, "release-manifest.json"), "utf8").replace('"signed": false', '"signed": false ');
      writeFileSync(join(altered, "release-manifest.json"), text);
      const req = JSON.parse(readFileSync(join(altered, "signing-request.json"), "utf8")) as { manifest: { sha256: string } };
      req.manifest.sha256 = lib.sha256(text);
      writeFileSync(join(altered, "signing-request.json"), JSON.stringify(req));
      const changed = runVerify("signature", altered, lib.sha256(text));
      expect(changed.code).toBe(1);
      expect(changed.out).toMatch(/BADSIG|no good signature/);

      for (const [label, key] of [["stranger", keys.strangerSub], ["commit", keys.commit], ["unpublished subkey", keys.releaseSub2]] as const) {
        const copy = `${pkg}-${label.replaceAll(" ", "-")}`;
        cpSync(pkg, copy, { recursive: true });
        signManifest(copy, key);
        const r = runVerify("signature", copy, digest);
        expect(r.code, label).toBe(1);
        expect(r.out, label).toMatch(/NO_PUBKEY|not an approved release signing subkey/);
      }

      const two = `${pkg}-two`;
      cpSync(pkg, two, { recursive: true });
      g(["--armor", "--detach-sign", "--local-user", `${keys.releaseSub}!`, "--local-user", `${keys.strangerSub}!`, "--output", join(two, "release-manifest.json.asc"), "--yes", join(two, "release-manifest.json")]);
      expect(runVerify("signature", two, digest).out).toContain("signatures, not one");
    });

    it("tag: passes for the exact signed tag on the commit; fails on another commit, another message, the commit key or a lightweight tag", () => {
      const { pkg, digest } = prepared();
      signManifest(pkg);
      const message = lib.tagMessage(VERSION, digest);
      const cases: [string, () => void, RegExp | null][] = [
        ["exact", () => tag("v1.0.1", c.commit, message), null],
        ["other commit", () => tag("v1.0.1", c.other, message), /points to commit .*, not commit/],
        ["other message", () => tag("v1.0.1", c.commit, "CodeParley 1.0.1\n"), /tag message is not exactly/],
        ["commit key", () => tag("v1.0.1", c.commit, message, keys.commit), /NO_PUBKEY|not an approved release signing subkey/],
        ["lightweight", () => git(repo, ["tag", "v1.0.1", c.commit]), /lightweight tag/],
        ["missing", () => undefined, /there is no tag v1\.0\.1/],
      ];
      for (const [label, make, want] of cases) {
        remove("v1.0.1");
        make();
        const r = runVerify("tag", pkg, digest);
        if (want === null) expect(r, label).toMatchObject({ code: 0 });
        else {
          expect(r.code, label).toBe(1);
          expect(r.out, label).toMatch(want);
        }
      }
      remove("v1.0.1");
    });

    it("payload and remote: the exact twelve files, then GitHub's REPORTED copy, without changing anything there", () => {
      const { pkg, digest } = prepared();
      signManifest(pkg);
      remove("v1.0.1");
      tag("v1.0.1", c.commit, lib.tagMessage(VERSION, digest));
      const p = runVerify("payload", pkg, digest);
      expect(p, p.out).toMatchObject({ code: 0 });
      expect(readFileSync(join(pkg, "codeparley-release-key.asc"), "utf8")).toBe(pub.releaseA);
      const payload = JSON.parse(readFileSync(join(pkg, "release-payload.json"), "utf8")) as { files: { name: string; size: number; sha256: string }[] };
      expect(payload.files.map((f) => f.name)).toEqual(["release-manifest.json", "release-manifest.json.asc", "codeparley-release-key.asc", "code-parley-1.0.1.tgz", "plugin-windows.tar.gz", "plugin-linux.tar.gz", "custodian-windows-x64.tar.gz", "custodian-linux-x64.tar.gz", "engine-runtime-windows-x64.tar.gz", "engine-runtime-linux-x64.tar.gz", "codeparley-installer.ps1", "codeparley-installer.sh"]);
      const again = runVerify("payload", pkg, digest);
      expect(again, again.out).toMatchObject({ code: 0 }); // repeated: unchanged

      const tagObject = git(repo, ["rev-parse", "refs/tags/v1.0.1"]).stdout.trim();
      const release = (o: Partial<Release> = {}): Release => ({ tag_name: "v1.0.1", draft: true, prerelease: false, id: 7, html_url: "https://example.invalid/r/7", assets: payload.files.map((f) => ({ name: f.name, size: f.size, digest: `sha256:${f.sha256}`, state: "uploaded" })), ...o });
      const calls: string[] = [];
      const github = (r: Release, ref = tagObject, id = 42) => (path: string) => {
        calls.push(path);
        // A step removes its old record before checking: no earlier PASS exists while this one runs.
        expect(existsSync(join(pkg, "verified-remote.json"))).toBe(false);
        if (path === "repos/example/CodeParley") return { id, private: false };
        if (path === "repos/example/CodeParley/git/ref/tags/v1.0.1") return { object: { type: "tag", sha: ref } };
        if (path === "repos/example/CodeParley/releases?per_page=100") return [r];
        throw new Error(`unexpected ${path}`);
      };
      const draft = runVerify("remote", pkg, digest, { github: github(release()) });
      expect(draft).toMatchObject({ code: 0 });
      expect(draft.out).toContain("GitHub's REPORTED sizes and digests (nothing downloaded)");
      expect(JSON.parse(readFileSync(join(pkg, "verified-remote.json"), "utf8"))).toMatchObject({ details: { remote: { source: expect.stringMatching(/^github-reported: .*nothing was downloaded/) as unknown } } });
      expect(report(pkg, digest)).toContain("VERIFIED THROUGH remote, draft only: the release is not published"); // a draft is not a published release

      const bad: [string, (p: string) => unknown, RegExp, boolean?][] = [
        ["published too early", github(release({ draft: false })), /not a draft/],
        ["still a draft", github(release()), /still a draft/, true],
        ["size", github(release({ assets: release().assets.map((a, i) => (i === 4 ? { ...a, size: a.size + 1 } : a)) })), /GitHub reports .* as \d+ bytes/],
        ["digest", github(release({ assets: release().assets.map((a, i) => (i === 1 ? { ...a, digest: `sha256:${"0".repeat(64)}` } : a)) })), /GitHub reports release-manifest\.json\.asc with digest/],
        ["extra file", github(release({ assets: [...release().assets, { name: "extra.zip", size: 1, digest: "sha256:00", state: "uploaded" }] })), /the release has/],
        ["missing file", github(release({ assets: release().assets.slice(1) })), /the release has/],
        ["tag object", github(release(), "c".repeat(40)), /not the verified tag object/],
        ["repository", github(release(), tagObject, 43), /has ID 43, not 42/],
      ];
      for (const [label, gh, want, published] of bad) {
        const r = runVerify("remote", pkg, digest, { github: gh, published });
        expect(r.code, label).toBe(1);
        expect(r.out, label).toMatch(want);
      }
      // A payload list that no longer names exactly the verified files is refused before GitHub is asked.
      const list = readFileSync(join(pkg, "release-payload.json"), "utf8");
      writeFileSync(join(pkg, "release-payload.json"), list.replace('"codeparley-installer.sh"', '"codeparley-installer.bat"'));
      expect(runVerify("remote", pkg, digest, { github: github(release()) }).out).toContain("release-payload.json does not list exactly the verified files");
      writeFileSync(join(pkg, "release-payload.json"), list);
      expect(runVerify("remote", pkg, digest, { github: github(release({ draft: false })), published: true })).toMatchObject({ code: 0 });
      expect(new Set(calls)).toEqual(new Set(["repos/example/CodeParley", "repos/example/CodeParley/git/ref/tags/v1.0.1", "repos/example/CodeParley/releases?per_page=100"]));
      const md = report(pkg, digest);
      expect(md).toContain("VERIFIED THROUGH remote, published");
      expect(md).toContain("GitHub-reported");
      expect(md).toContain(tagObject);
      remove("v1.0.1");
    });

    it("a rehearsal package is marked so and never verifies as a release (nor a release as a rehearsal)", () => {
      const { pkg, digest } = prepared({ rehearsal: true });
      expect(readFileSync(join(pkg, "SIGNING-REQUEST.md"), "utf8")).toContain("REHEARSAL: sign this package only with a disposable test key");
      expect(runVerify("package", pkg, digest, { version: REHEARSAL, rehearsal: true })).toMatchObject({ code: 0 });
      expect(runVerify("package", pkg, digest, { version: REHEARSAL }).out).toContain("is not a release candidate");
      expect(row(report(pkg, digest, { version: REHEARSAL, rehearsal: true }), "package")).toContain("recorded with other values");
      const real = prepared();
      expect(runVerify("package", real.pkg, real.digest, { rehearsal: true }).out).toContain("a rehearsal needs a --test-version build");
    });
  });

  // C-3: a record counts only for its own values and while the package keeps the state it checked.
  describe("verification records and the report", () => {
    it("follows the stages: nothing verified, then package, signature and tag, each in turn", () => {
      const { pkg, digest } = prepared();
      remove("v1.0.1");
      let md = report(pkg, digest);
      expect(md).toContain("NOT VERIFIED: the package itself has no current PASS");
      expect(row(md, "signature")).toContain("no record (the manifest is not signed yet)");
      expect(row(md, "tag")).toContain("no record (there is no tag yet)");
      runVerify("package", pkg, digest);
      expect(report(pkg, digest)).toContain("VERIFIED THROUGH package only: signature not verified");
      signManifest(pkg);
      md = report(pkg, digest);
      expect(md).toContain("VERIFIED THROUGH package only"); // signing changes nothing the package step checked
      expect(row(md, "package")).toContain("| PASS |");
      runVerify("signature", pkg, digest);
      expect(report(pkg, digest)).toContain("VERIFIED THROUGH signature only");
      tag("v1.0.1", c.commit, lib.tagMessage(VERSION, digest));
      runVerify("tag", pkg, digest);
      expect(report(pkg, digest)).toContain("VERIFIED THROUGH tag only");
      remove("v1.0.1");
      md = report(pkg, digest);
      expect(row(md, "tag")).toContain("stale: tagObject changed since (there is no tag yet)");
      expect(md).toContain("VERIFIED THROUGH signature only");
      // A later PASS covers an earlier step without a record of its own, but never an earlier step's own FAIL.
      rmSync(join(pkg, "verified-package.json"));
      expect(row(report(pkg, digest), "package")).toContain("covered by the signature check");
      runVerify("package", pkg, digest, { gpg: process.execPath });
      md = report(pkg, digest);
      expect(row(md, "package")).toContain("| FAIL |");
      expect(md).toContain("NOT VERIFIED");
    });

    it("never counts a changed package, a missing or unreadable record, or a record of other values", () => {
      const { pkg, digest } = prepared();
      runVerify("package", pkg, digest);
      signManifest(pkg);
      runVerify("signature", pkg, digest);
      appendFileSync(join(pkg, "plugin-linux.tar.gz"), "x");
      let md = report(pkg, digest);
      expect(row(md, "package")).toContain("stale: content changed since");
      expect(row(md, "signature")).toContain("stale: content changed since");
      expect(md).toContain("NOT VERIFIED");
      const fresh = prepared();
      runVerify("package", fresh.pkg, fresh.digest);
      rmSync(join(fresh.pkg, "verified-package.json"));
      expect(row(report(fresh.pkg, fresh.digest), "package")).toContain("no record");
      writeFileSync(join(fresh.pkg, "verified-package.json"), "{ not json");
      expect(row(report(fresh.pkg, fresh.digest), "package")).toContain("unreadable");
      runVerify("package", fresh.pkg, fresh.digest);
      expect(row(report(fresh.pkg, fresh.digest, { version: "1.0.9" }), "package")).toContain("recorded with other values");
      // A replaced signature makes the signature record stale; a stale record covers no earlier step either.
      const resigned = prepared();
      signManifest(resigned.pkg);
      expect(runVerify("signature", resigned.pkg, resigned.digest)).toMatchObject({ code: 0 });
      expect(report(resigned.pkg, resigned.digest)).toContain("VERIFIED THROUGH signature only");
      signManifest(resigned.pkg, keys.strangerSub);
      md = report(resigned.pkg, resigned.digest);
      expect(row(md, "signature")).toContain("stale: signature changed since");
      expect(row(md, "package")).toContain("no record");
      expect(md).toContain("NOT VERIFIED");
    });

    it("an error is recorded as a FAIL and replaces an earlier PASS", () => {
      const { pkg, digest } = prepared();
      expect(runVerify("package", pkg, digest)).toMatchObject({ code: 0 });
      // Node.js in place of GnuPG: every gpg call fails, and the verifier stops with an error.
      const r = runVerify("package", pkg, digest, { gpg: process.execPath });
      expect(r.code).toBe(1);
      expect(r.out).toContain("the verification stopped with an error");
      expect(JSON.parse(readFileSync(join(pkg, "verified-package.json"), "utf8"))).toMatchObject({ result: "FAIL" });
      expect(row(report(pkg, digest), "package")).toContain("| FAIL |");
    });
  });

  // C-5: approved-subkey history, expiry, rotation, revocation.
  // C-1 (D-107, workflow §9): the release source is the owner-signed head of the merged pull request, never GitHub's
  // merge commit, and it must be integrated into the fetched main by that merge. Every main below is built in this
  // disposable fixture's object store; no real history is touched.
  describe("C-1: the release source and its integration into main", () => {
    const x = { unmerged: "", unsigned: "", strangerSigned: "", foreignKey: "" };
    const src = (commit: string, o: { version?: string; mainRef?: string; commitPin?: string } = {}) =>
      lib.releaseSourceProblems({ repo, commit, version: o.version ?? VERSION, gpg, pins: P1(), commitPin: o.commitPin ?? keys.commit, ...(o.mainRef ? { mainRef: o.mainRef } : {}) });
    const integration = (commit: string, main?: string) => (main === undefined ? lib.integrationOf({ repo, commit }) : withMain(main, () => lib.integrationOf({ repo, commit })));
    const gate = (commit: string, o: { dirty?: boolean; signature?: string; testBuild?: boolean; version?: string } = {}) =>
      lib.stagingSourceGate({ repo, commit, version: o.version ?? ROTATED, gpg, pins: P1(), commitPin: keys.commit, dirty: o.dirty ?? false, signature: o.signature ?? "verified", testBuild: o.testBuild ?? false });
    const MAIN = "refs/remotes/origin/main";

    beforeAll(() => {
      if (support.skip || support.broken) return;
      const commit = (msg: string, key: string | null, files: Record<string, string> = {}) => {
        for (const [p, t] of Object.entries(files)) writeFileSync(join(repo, ...p.split("/")), t);
        git(repo, ["add", "-A"]);
        git(repo, [...(key ? ["-c", `gpg.program=${gpgProgram()}`, "-c", `user.signingkey=${key}`] : []), "commit", "-q", ...(key ? ["-S"] : []), "--allow-empty", "-m", msg], { env: gitEnv() });
        return git(repo, ["rev-parse", "HEAD"]).stdout.trim();
      };
      x.unmerged = commit("an owner-signed head that no pull request merged yet", keys.commit);
      x.unsigned = commit("an unsigned commit", null);
      x.strangerSigned = commit("signed by a stranger, the owner's key file kept", `${keys.strangerSub}!`);
      x.foreignKey = commit("signed by a stranger, who also replaced the key file", `${keys.strangerSub}!`, { ".github/ci/commit-signing-key.asc": g(["--armor", "--export", keys.stranger]) });
    });

    it("accepts the owner-signed head its GitHub merge integrated, at main's tip and after main moved on through later merges", () => {
      expect(lib.MAIN_REF).toBe(MAIN);
      expect(lib.COMMIT_KEY.primary).toBe("261E3060E70B4904615F17BD026A2C3E92B42B25");
      // main moved on: c.merge2 (c.rotated's merge) is on top of c.merge1, which integrated c.commit.
      expect(integration(c.commit)).toEqual({ problems: [], main: c.merge2, merge: c.merge1, tree: treeOf(c.commit) });
      expect(integration(c.rotated)).toEqual({ problems: [], main: c.merge2, merge: c.merge2, tree: treeOf(c.rotated) });
      expect(integration(c.commit, c.merge1)).toMatchObject({ problems: [], main: c.merge1, merge: c.merge1 }); // the merge is main's tip
      expect(src(c.commit)).toMatchObject({ problems: [], integration: { merge: c.merge1 } });
      const { pkg, digest } = prepared();
      const r = runVerify("package", pkg, digest);
      expect(r.code, r.out).toBe(0);
      expect(r.out).toContain(`integrated into ${MAIN} (${c.merge2}) by the GitHub merge ${c.merge1}: second parent the source, the same tree ${treeOf(c.commit)}`);
      expect(JSON.parse(readFileSync(join(pkg, "verified-package.json"), "utf8"))).toMatchObject({ schema: "codeparley.release-verification.v3", details: { releaseSource: { required: true, mainRef: MAIN, main: c.merge2, merge: c.merge1, tree: treeOf(c.commit) } } });
      expect(report(pkg, digest)).toContain(`| Integrated into main by | the GitHub merge \`${c.merge1}\` (its second parent is the source; the same tree) |`);
    });

    it("refuses GitHub's merge commit as the release source", () => {
      const r = src(c.merge1);
      expect(r.problems).toContain(`commit ${c.merge1} is not signed by the owner's pinned commit key ${keys.commit} (signature N by no key)`);
      expect(r.problems).toContain(`the release source ${c.merge1} is on ${MAIN}'s first-parent line itself: it reached main without a merge (pushed or fast-forwarded), so no pull-request merge integrated it`);
      // Its manifest and request would name the merge; preparing it fails on the same checks.
      const dir = join(base, `case-${++n}`);
      const digest = stage(join(dir, "staged"), { commit: c.merge1 });
      const p = runPrepare(join(dir, "staged"), join(dir, "pkg"), digest, { commit: c.merge1 });
      expect(p.code).toBe(1);
      expect(p.out).toContain(`commit ${c.merge1} is not signed by the owner's pinned commit key`);
      expect(p.out).toContain("is on refs/remotes/origin/main's first-parent line itself");
      expect(existsSync(join(dir, "pkg"))).toBe(false);
    });

    it("refuses a source that the fetched main does not reach", () => {
      expect(integration(x.unmerged).problems).toEqual([`the release source ${x.unmerged} is not reachable from ${MAIN} (${c.merge2}): it is not integrated into main, or the clone's main is stale (fetch origin)`]);
      expect(src(x.unmerged, { version: ROTATED }).problems).toHaveLength(1); // the signature is the owner's; only the integration is missing
    });

    it("refuses a merge that merged another commit, or merged the source in another position or shape", () => {
      // The milestone moved on after the accepted head: the merge's second parent is a later commit (c.other).
      expect(integration(c.commit, githubMerge(c.main0, c.other)).problems).toEqual([`no merge on ${MAIN}'s first-parent line merged the release source ${c.commit} itself: it is reachable from main only inside another merged commit (the merged pull request's head is a different commit)`]);
      // The source as the FIRST parent: it is on main's first-parent line (the T7 shape).
      expect(integration(c.commit, githubMerge(c.commit, c.main0, treeOf(c.commit))).problems[0]).toContain("is on refs/remotes/origin/main's first-parent line itself");
      // An octopus merge carrying the source as its third parent.
      const octopus = rawCommit(treeOf(c.commit), [c.main0, c.other, c.commit]);
      expect(integration(c.commit, octopus).problems).toEqual([`${octopus} merges the release source, but not as the second of exactly two parents (parents ${c.main0}, ${c.other}, ${c.commit})`]);
      // The right parents and tree, but not made by GitHub: a merge pushed by someone.
      const pushed = rawCommit(treeOf(c.commit), [c.main0, c.commit], "Andries <owner@example.invalid>");
      expect(integration(c.commit, pushed).problems).toEqual([`${pushed} merges the release source, but is committed by Andries (owner@example.invalid), not GitHub (noreply@github.com): not a pull-request merge made by GitHub`]);
    });

    it("refuses an integrating merge whose tree is not the source's", () => {
      const conflict = githubMerge(c.main0, c.commit, treeOf(c.rotated));
      expect(integration(c.commit, conflict)).toMatchObject({ merge: null, problems: [`the integrating merge ${conflict} has the tree ${treeOf(c.rotated)}, not the release source's tree ${treeOf(c.commit)}: main did not receive exactly the source`] });
    });

    it("refuses a main whose tip is not a merge, or that moved on through anything but GitHub merges", () => {
      // The source pushed or fast-forwarded to main: main's tip is the source itself (T8).
      expect(integration(c.commit, c.commit).problems[0]).toContain(`the release source ${c.commit} is on ${MAIN}'s first-parent line itself`);
      // A non-merge commit on top of the integrating merge.
      const direct = rawCommit(treeOf(c.commit), [c.merge1], "Andries <owner@example.invalid>", "a direct push");
      expect(integration(c.commit, direct)).toMatchObject({ merge: null, problems: [`main moved on after the integrating merge ${c.merge1} through ${direct}, which is not a GitHub merge (1 parent(s), committer Andries (owner@example.invalid)): main's history since the integration is not verifiable`] });
      // A later merge that GitHub did not make.
      const pushed = rawCommit(treeOf(c.rotated), [c.merge1, c.rotated], "Andries <owner@example.invalid>");
      expect(integration(c.commit, pushed).problems[0]).toContain(`through ${pushed}, which is not a GitHub merge (2 parent(s)`);
      // A later GitHub merge is the legitimate way main moves on.
      expect(integration(c.commit, githubMerge(c.merge2, x.unmerged)).merge).toBe(c.merge1);
    });

    it("refuses an ambiguous integration: the source merged twice on main's first-parent line", () => {
      const again = githubMerge(c.merge1, c.commit);
      expect(integration(c.commit, again).problems).toEqual([`the release source ${c.commit} is merged by 2 commits on ${MAIN}'s first-parent line (${again}, ${c.merge1}): the integration is ambiguous`]);
    });

    it("refuses an integrated source whose signature is missing, a stranger's, or by a key its own key file substitutes", () => {
      const ref = "refs/remotes/test/main";
      const integrated = (commit: string) => { setMain(githubMerge(c.merge2, commit), ref); return src(commit, { version: ROTATED, mainRef: ref }); };
      try {
        expect(integrated(x.unmerged).problems).toEqual([]);
        expect(integrated(x.unsigned).problems).toEqual([`commit ${x.unsigned} is not signed by the owner's pinned commit key ${keys.commit} (signature N by no key)`]);
        const stranger = integrated(x.strangerSigned).problems;
        expect(stranger).toHaveLength(1);
        expect(stranger[0]).toMatch(new RegExp(`^commit ${x.strangerSigned} is not signed by the owner's pinned commit key ${keys.commit} \\(signature [^G] by `));
        // The stranger's key file, signed by the stranger: a signature that verifies against the commit's own key file,
        // so only the pin catches it.
        expect(integrated(x.foreignKey).problems).toEqual([`.github/ci/commit-signing-key.asc at ${x.foreignKey} does not hold the pinned commit-signing key ${keys.commit} (it holds ${keys.stranger})`]);
        expect(src(c.commit, { commitPin: keys.stranger }).problems).toEqual([`.github/ci/commit-signing-key.asc at ${c.commit} does not hold the pinned commit-signing key ${keys.stranger} (it holds ${keys.commit})`]);
        expect(src(c.commit, { commitPin: "" }).problems).toEqual(["no commit-signing key is pinned (40 upper-case hex digits)"]);
      } finally {
        setMain(null, ref);
      }
    });

    it("fails closed on missing integration evidence: no fetched main, a shallow clone, replacement refs", () => {
      expect(withMain(null, () => lib.integrationOf({ repo, commit: c.commit })).problems).toEqual([`${MAIN} is not in ${repo}: fetch origin first (the integration is checked against the fetched main)`]);
      const { pkg, digest } = prepared();
      expect(withMain(null, () => runVerify("package", pkg, digest)).out).toContain(`${MAIN} is not in ${repo}: fetch origin first`);
      const shallow = join(base, `shallow-${++n}`);
      git(base, ["clone", "-q", "--depth", "1", pathToFileURL(repo).href, shallow]);
      expect(lib.integrationOf({ repo: shallow, commit: git(shallow, ["rev-parse", "HEAD"]).stdout.trim() }).problems).toEqual([`${shallow} is a shallow clone: main's history cannot be followed`]);
      // A replacement ref that makes a non-merge main look like the integrating merge is never followed.
      const plain = rawCommit(treeOf(c.main0), [c.main0], "Fixture <fixture@example.invalid>", "not a merge");
      git(repo, ["replace", plain, c.merge1]);
      try {
        expect(integration(c.commit, plain).problems).toEqual([`the release source ${c.commit} is not reachable from ${MAIN} (${plain}): it is not integrated into main, or the clone's main is stale (fetch origin)`]);
      } finally {
        git(repo, ["replace", "-d", plain]);
      }
    });

    it("never counts a record once the fetched main no longer integrates the source; main moving on keeps it", () => {
      const { pkg, digest } = prepared();
      expect(runVerify("package", pkg, digest).code).toBe(0);
      signManifest(pkg);
      expect(runVerify("signature", pkg, digest).code).toBe(0);
      expect(report(pkg, digest)).toContain("VERIFIED THROUGH signature only");
      // Main moves on through a later GitHub merge: the integrating merge is the same, so the records still count.
      expect(withMain(githubMerge(c.merge2, x.unmerged), () => report(pkg, digest))).toContain("VERIFIED THROUGH signature only");
      // A fetched main from before the merge (stale evidence): every record is stale, and the check now fails.
      const md = withMain(c.main0, () => report(pkg, digest));
      expect(row(md, "package")).toContain("stale: integration changed since");
      expect(row(md, "signature")).toContain("stale: integration changed since");
      expect(md).toContain("NOT VERIFIED: the package itself has no current PASS");
      expect(withMain(c.main0, () => runVerify("package", pkg, digest)).out).toContain(`the release source ${c.commit} is not reachable from ${MAIN} (${c.main0})`);
      expect(report(pkg, digest)).toContain("NOT VERIFIED"); // the FAIL replaced the PASS, also with main restored
    });

    it("stages a test build before integration, marked so, and never accepts it as a release candidate", () => {
      // Staging: a would-be candidate needs the integration; a test build or a dry run does not, and is never a candidate.
      expect(gate(x.unmerged, { testBuild: true })).toEqual({ required: false, problems: [], integration: null, why: "a test build (--test-version), never a release candidate" });
      expect(gate(x.unmerged, { dirty: true })).toMatchObject({ required: false, problems: [] });
      expect(gate(x.unmerged, { signature: "unverified" })).toMatchObject({ required: false, problems: [] });
      expect(gate(x.unmerged)).toMatchObject({ required: true, problems: [`the release source ${x.unmerged} is not reachable from ${MAIN} (${c.merge2}): it is not integrated into main, or the clone's main is stale (fetch origin)`] });
      expect(gate(c.commit, { version: VERSION })).toMatchObject({ required: true, problems: [], integration: { merge: c.merge1 } });
      const id = manifestLib.buildId({ artifact: "npm-tarball", version: "1.0.2-vm.1", commit: x.unmerged, signature: "verified", dirty: false, testBuild: true, toolchain: { dotnetSdk: "10.0.403", node: "v24.11.0", npm: "11.6.1" }, builtAt: "2026-11-03T12:00:00.000Z" });
      expect(id).toMatchObject({ testBuild: true, releaseCandidate: false });
      // The test build is prepared and rehearsed without the integration, marked as a rehearsal throughout ...
      const version = "1.0.2-rehearsal.1";
      const dir = join(base, `case-${++n}`);
      const digest = stage(join(dir, "staged"), { version, commit: x.unmerged, testBuild: true });
      const p = runPrepare(join(dir, "staged"), join(dir, "pkg"), digest, { version, commit: x.unmerged, rehearsal: true, pins: P2() });
      expect(p.code, p.out).toBe(0);
      expect(p.out).toContain("a rehearsal: no integration into main required");
      const pkg = join(dir, "pkg");
      const r = runVerify("package", pkg, digest, { version, commit: x.unmerged, rehearsal: true, pins: P2() });
      expect(r.code, r.out).toBe(0);
      expect(r.out).toContain("PASS (REHEARSAL)");
      expect(r.out).toContain("integration into main: not required (rehearsal: never a release)");
      expect(report(pkg, digest, { version, commit: x.unmerged, rehearsal: true, pins: P2() })).toContain("| Integrated into main by | not required (rehearsal: never a release) |");
      // ... and never verifies as a release: it is no candidate, and its source is not integrated.
      const real = runVerify("package", pkg, digest, { version, commit: x.unmerged, pins: P2() });
      expect(real.code).toBe(1);
      expect(real.out).toContain("the manifest is not a release candidate");
      expect(real.out).toContain(`the release source ${x.unmerged} is not reachable from ${MAIN}`);
    });
  });

  describe("signing keys over time", () => {
    it("rotation: a new release needs the current subkey; an earlier release still verifies under the rotated pins", () => {
      const old = prepared();
      signManifest(old.pkg);
      expect(runVerify("signature", old.pkg, old.digest)).toMatchObject({ code: 0 });
      // After the rotation (P2), the release signed by the earlier subkey still verifies.
      expect(runVerify("signature", old.pkg, old.digest, { pins: P2() })).toMatchObject({ code: 0 });
      // A rotated-era release must be signed by the subkey its request names: the new current one.
      const neu = prepared({ version: ROTATED, commit: c.rotated, pins: P2() });
      signManifest(neu.pkg, keys.releaseSub);
      expect(runVerify("signature", neu.pkg, neu.digest, { version: ROTATED, commit: c.rotated, pins: P2() }).out).toContain(`not ${keys.releaseSub2}, the subkey this signing request names`);
      signManifest(neu.pkg, keys.releaseSub2);
      expect(runVerify("signature", neu.pkg, neu.digest, { version: ROTATED, commit: c.rotated, pins: P2() })).toMatchObject({ code: 0 });
      // Under the old pins the rotated key file carries an unapproved signing subkey.
      expect(runVerify("package", neu.pkg, neu.digest, { version: ROTATED, commit: c.rotated }).out).toContain(`signing subkey ${keys.releaseSub2} that is not approved`);
    });

    it("expiry: a signature made before the subkey expired verifies after it; signing after expiry is impossible", () => {
      const pins: Pins = { primary: keys.expiring, subkeys: [{ fpr: keys.expiringSub, current: true }] };
      const dir = join(base, `exp-${++n}`);
      mkdirSync(dir);
      writeFileSync(join(dir, "data"), "manifest stand-in\n");
      sign(keys.expiringSub, join(dir, "data"), join(dir, "data.asc"));
      const listed = lib.withKeyring(gpg, [pub.expiring!], (kr) => lib.listKeys(kr));
      const statusAt = (when: string | null) => lib.withKeyring(gpg, [pub.expiring!], (kr) => spawnSync(gpg, [...kr.base, ...(when ? ["--faked-system-time", when] : []), "--status-fd", "1", "--verify", join(dir, "data.asc"), join(dir, "data")], { encoding: "utf8", windowsHide: true }));
      const today = statusAt(null);
      expect(today.stdout).toMatch(/GOODSIG/);
      expect(lib.signatureStatusProblems(today.stdout, today.status, pins, listed)).toEqual([]);
      const later = statusAt(LATER);
      expect(later.stdout).toMatch(/EXPKEYSIG/);
      expect(later.stdout).not.toMatch(/GOODSIG/);
      expect(lib.signatureStatusProblems(later.stdout, later.status, pins, listed)).toEqual([]);
      // The same expired-key signature by an unapproved subkey, or under another primary, still fails.
      expect(lib.signatureStatusProblems(later.stdout, later.status, { primary: keys.expiring, subkeys: [{ fpr: keys.strangerSub, current: true }] }, listed).join()).toContain("not an approved release signing subkey");
      expect(lib.signatureStatusProblems(later.stdout, later.status, { primary: keys.stranger, subkeys: [{ fpr: keys.expiringSub, current: true }] }, listed).join()).toContain("not the release key");
      // GnuPG refuses to sign with the expired subkey.
      expect(() => g(["--faked-system-time", LATER, "--yes", "--armor", "--detach-sign", "--local-user", `${keys.expiringSub}!`, "--output", join(dir, "late.asc"), join(dir, "data")])).toThrow();
    });

    it("revocation: a revoked release key fails, also for a signature made before the revocation", () => {
      const h = newHome("gnupg-revoked");
      gpgIn(h, ["--quick-gen-key", "Disposable Revoked <revoked@example.invalid>", "ed25519", "cert", "2y"]);
      const primary = fprsOf(h, "Disposable Revoked").primary;
      gpgIn(h, ["--quick-add-key", primary, "ed25519", "sign", "1d"]);
      const subkey = fprsOf(h, primary).subs[0]!;
      const dir = join(base, `rev-${++n}`);
      mkdirSync(dir);
      writeFileSync(join(dir, "data"), "manifest stand-in\n");
      gpgIn(h, ["--yes", "--armor", "--detach-sign", "--local-user", `${subkey}!`, "--output", join(dir, "data.asc"), join(dir, "data")]);
      const pins: Pins = { primary, subkeys: [{ fpr: subkey, current: true }] };
      expect(lib.verifyDetached({ gpg, keyArmored: gpgIn(h, ["--armor", "--export", primary]), pins, signatureFile: join(dir, "data.asc"), dataFile: join(dir, "data") }).problems).toEqual([]);
      // GnuPG wrote a revocation certificate for the new key; importing it revokes the key.
      const cert = readFileSync(join(h, "openpgp-revocs.d", `${primary}.rev`), "utf8").replace(/^:-----BEGIN/m, "-----BEGIN");
      writeFileSync(join(dir, "revoke.asc"), cert);
      gpgIn(h, ["--import", join(dir, "revoke.asc")]);
      const revoked = lib.verifyDetached({ gpg, keyArmored: gpgIn(h, ["--armor", "--export", primary]), pins, signatureFile: join(dir, "data.asc"), dataFile: join(dir, "data") });
      expect(revoked.problems.join("\n")).toMatch(/REVKEYSIG|is revoked/);
      expect(revoked.problems.length).toBeGreaterThan(0);
    });
  });
});

describe("Step 4: approved subkeys and the signature status rules", () => {
  const A = "A".repeat(40);
  const B = "B".repeat(40);
  const P: Pins = { primary: A, subkeys: [{ fpr: B, current: true }] };
  const K = (o: Partial<Sub> = {}): Key[] => [{ primary: A, validity: "u", created: 1000, expires: 0, capabilities: "cSC", subkeys: [{ fpr: B, validity: "u", created: 1000, expires: 0, capabilities: "s", ...o }] }];
  const status = (o: { valid?: string; good?: string; extra?: string[]; at?: number } = {}) =>
    ["NEWSIG", o.good ?? `GOODSIG ${B.slice(24)} Owner`, o.valid ?? `VALIDSIG ${B} 2026-11-03 ${o.at ?? 2000} 0 4 0 22 10 00 ${A}`, ...(o.extra ?? [])].map((l) => `[GNUPG:] ${l}`).join("\n");
  const f = lib.signatureStatusProblems;

  it("accepts exactly one good, valid signature by an approved subkey of the pinned primary, over a document", () => {
    expect(f(status(), 0, P, K())).toEqual([]);
    expect(lib.pinProblems(lib.RELEASE_KEY)).toEqual([]);
  });

  it("refuses each deviation on its own", () => {
    expect(f(status(), 1, P, K())).toEqual(["gpg --verify exited with 1"]);
    expect(f(status({ valid: `VALIDSIG ${B} 2026-11-03 2000 0 4 0 22 10 00 ${"C".repeat(40)}` }), 0, P, K())).toEqual([`the signing key's primary key is ${"C".repeat(40)}, not the release key ${A}`]);
    expect(f(status({ valid: `VALIDSIG ${"D".repeat(40)} 2026-11-03 2000 0 4 0 22 10 00 ${A}` }), 0, P, K())).toEqual([`the signature was made by ${"D".repeat(40)}, not an approved release signing subkey (${B})`, `the signing subkey ${"D".repeat(40)} is not in the release key file`]);
    expect(f(status({ valid: `VALIDSIG ${B} 2026-11-03 2000 0 4 0 22 10 01 ${A}` }), 0, P, K())).toEqual(["the signature class is 01, not a signature over a document (00)"]);
    expect(f(status(), 0, P, K(), { expectSubkey: "E".repeat(40) })).toEqual([`the signature was made by ${B}, not ${"E".repeat(40)}, the subkey this signing request names`]);
    for (const bad of ["REVKEYSIG X Owner", "EXPSIG X Owner", "BADSIG X Owner", "ERRSIG X", "NO_PUBKEY X"]) expect(f(status({ extra: [bad] }), 0, P, K())).toEqual([`gpg reports ${bad.split(" ")[0]}`]);
    expect(f(status({ extra: [`GOODSIG ${B.slice(24)} Owner`] }), 0, P, K())).toEqual(["gpg reports no good signature"]); // two good lines
  });

  it("checks the signing time against the subkey's validity (a consistency check, not a proof of time)", () => {
    const expired = (at: number) => status({ good: `EXPKEYSIG ${B.slice(24)} Owner`, at });
    expect(f(expired(4999), 0, P, K({ expires: 5000 }))).toEqual([]); // the last second inside the validity
    expect(f(expired(5000), 0, P, K({ expires: 5000 }))).toEqual(["the signature claims a time (5000) at or after its subkey expired (5000)"]);
    expect(f(status({ at: 1000 }), 0, P, K())).toEqual([]); // the creation second itself
    expect(f(status({ at: 999 }), 0, P, K())).toEqual(["the signature claims a time (999) before its subkey was created (1000)"]);
    expect(f(status({ at: 0 }), 0, P, K())).toEqual(["the signature carries no signing time"]);
    expect(f(expired(2000), 0, P, K())).toEqual(["gpg reports an expired key, but the subkey has no expiry"]);
    expect(f(status({ good: `EXPKEYSIG ${B.slice(24)} Owner`, extra: ["REVKEYSIG X Owner"] }), 0, P, K({ expires: 5000 }))).toEqual(["gpg reports REVKEYSIG"]); // revoked: never, also historically
  });

  it("refuses pin sets without exactly one current, well-formed, distinct subkey", () => {
    expect(lib.pinProblems({ primary: A, subkeys: [{ fpr: B, current: false }] })).toContain("0 pinned signing subkeys are current, not exactly one");
    expect(lib.pinProblems({ primary: A, subkeys: [{ fpr: B, current: true }, { fpr: "C".repeat(40), current: true }] })).toContain("2 pinned signing subkeys are current, not exactly one");
    expect(lib.pinProblems({ primary: A, subkeys: [{ fpr: B, current: true }, { fpr: B, current: false }] })).toContain("a signing subkey is pinned twice");
    expect(lib.pinProblems({ primary: "a".repeat(40), subkeys: [{ fpr: B, current: true }] })).toContain("the pinned primary fingerprint is not 40 upper-case hex digits");
    expect(lib.pinProblems({ primary: A, subkeys: [{ fpr: A, current: true }] })).toContain("the primary key is pinned as a signing subkey");
    expect(f(status(), 0, { primary: A, subkeys: [] }, K()).join()).toContain("no signing subkey is pinned");
  });

  it("checks the release key file for a new request: the current subkey present, signing, unexpired, unrevoked", () => {
    const r = (o: Partial<Sub>, now = 3000) => lib.releaseKeyProblems(K(o), P, { forSigning: true, now });
    expect(r({})).toEqual([]);
    expect(r({ expires: 3000 })).toEqual([`the current subkey ${B} has expired: a new signing request needs a current, unexpired subkey`]);
    expect(r({ validity: "r" })).toEqual([`the current subkey ${B} is revoked`]);
    expect(lib.releaseKeyProblems(K({ expires: 3000 }), P, { now: 9000 })).toEqual([]); // verification (not a new request) allows an expired subkey
    expect(lib.releaseKeyProblems([{ ...K()[0]!, validity: "r" }], P)).toEqual([`the release primary key ${A} is revoked`]);
  });
});

// The workflow's code never signs, pushes or changes a GitHub release, and runs GnuPG only in a temporary home.
// Template literals (text) and comments are removed before the checks.
describe("Step 4: the release tooling has no signing or publication side effects", () => {
  const files = ["scripts/package/prepare-signing.mjs", "scripts/package/verify-release.mjs", "scripts/package/lib/release-verify.mjs"];
  const code = (f: string) => readFileSync(join(root, f), "utf8").replace(/`(?:\\[\s\S]|\$\{(?:[^{}]|\{[^{}]*\})*\}|\$(?!\{)|[^`\\$])*`/g, "``").replace(/^\s*\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");

  it("contains no signing, push or release-changing invocation", () => {
    for (const f of files) {
      expect(code(f), f).not.toMatch(/detach-sign|clearsign|"--sign"|"-s"|"push"|"tag",\s*"-s"|release",\s*"(create|edit|upload|delete)"|--method|"-X"|--passphrase|--pinentry|export-secret|card-edit|"(?:ykman|gpg-connect-agent)"/);
      expect(code(f), f).not.toMatch(/spawnSync\("gh",\s*\[(?!"api", path\])/);
    }
  });

  it("C-2: runs every GnuPG command with a temporary home", () => {
    const lib = code("scripts/package/lib/release-verify.mjs");
    const calls = [...lib.matchAll(/sh\((gpg|kr\.gpg|gpgconf),\s*\[([^\]]*)/g)];
    expect(calls.length).toBeGreaterThanOrEqual(6);
    for (const m of calls) expect(m[2]!.trimStart(), m[0]).toMatch(/^(\.\.\.kr\.base|"--homedir", home)/);
    // The temporary home's agent never starts a smart-card daemon, so no YubiKey is reachable from it.
    expect(lib).toContain('writeFileSync(join(home, "gpg-agent.conf"), "disable-scdaemon\\n")');
    for (const f of files.slice(0, 2)) expect(code(f), f).not.toMatch(/spawnSync\((ctx\.)?gpg|sh\(gpg/);
  });

  it("C-1: the owner's instructions take the three values from the TD's record, typed, never pre-filled", () => {
    const doc = readFileSync(join(root, "docs", "releasing.md"), "utf8");
    for (const what of ["Version, from the TD acceptance record", "Source commit (40 hex), from the TD acceptance record", "Manifest SHA-256 (64 hex), from the TD acceptance record"]) expect(doc).toContain(`Read-Host '${what}'`);
    expect(doc).not.toMatch(/\b[0-9a-f]{64}\b/);
    expect(doc).toContain("$gpg = 'C:\\Program Files\\GnuPG\\bin\\gpg.exe'");
    expect(doc).toMatch(/server-reported values, not an independent download-and-hash check/);
    expect(doc).toContain("eleven-file procedure");
  });

  it("D-107 C-1: the owner verifies the accepted source commit and its integration, never main's head", () => {
    const doc = readFileSync(join(root, "docs", "releasing.md"), "utf8");
    expect(doc).not.toContain("checkout --detach origin/main");
    expect(doc).not.toContain("verify-commit HEAD");
    const sign = doc.slice(doc.indexOf("### 4. Sign (owner)"), doc.indexOf("### 5. Publish"));
    const at = (s: string) => {
      const i = sign.indexOf(s);
      expect(i, s).toBeGreaterThan(-1);
      return i;
    };
    // The typed values, the fetch, the owner's own GnuPG check of the commit, its checkout, then the verifier from it.
    const order = ["Read-Host 'Source commit", "fetch origin", "verify-commit --raw $commit", "checkout --detach $commit", "merge-base --is-ancestor $commit origin/main", 'verify-release.mjs" package'];
    for (let i = 1; i < order.length; i++) expect(at(order[i - 1]!), `${order[i - 1]} before ${order[i]}`).toBeLessThan(at(order[i]!));
  });

  it("TD C-1 correction: every step of the owner's source check stops on failure, before any code from the clone runs", () => {
    const doc = readFileSync(join(root, "docs", "releasing.md"), "utf8");
    const sign = doc.slice(doc.indexOf("### 4. Sign (owner)"), doc.indexOf("### 5. Publish"));
    const block = sign.slice(sign.indexOf("```powershell"), sign.indexOf("```", sign.indexOf("```powershell") + 3));
    const line = (s: string) => block.split("\n").find((l) => l.includes(s)) ?? "";
    // Each git step and the verifier carry their own stop on the same line.
    for (const step of ["fetch origin", "checkout --detach $commit", "merge-base --is-ancestor", 'verify-release.mjs" package']) expect(line(step), step).toMatch(/; if \(\$LASTEXITCODE -ne 0\) \{ throw 'STOP: [^']+' \}$/);
    expect(line("-cnotmatch '^[0-9a-f]{40}$'")).toContain("throw 'STOP:");
    // The signature: the owner's own Git and Gpg4win, one GOODSIG, one VALIDSIG whose primary is the pinned commit key.
    expect(block).toContain('verify-commit --raw $commit 2>&1');
    expect(block).toContain("'^\\[GNUPG:\\] GOODSIG '");
    expect(block).toContain("$valid.Count -ne 1 -or $valid[0] -cnotmatch ' 261E3060E70B4904615F17BD026A2C3E92B42B25$'");
    expect(block).toContain("throw 'STOP: the source commit is not signed by the commit key 261E3060E70B4904615F17BD026A2C3E92B42B25'");
    expect(block).toMatch(/\(git -C \$clone rev-parse HEAD\) -cne \$commit -or \(git -C \$clone status --porcelain --untracked-files=all\)\) \{ throw 'STOP: /);
    // The verifier, code from the clone, comes last.
    expect(block.indexOf("verify-release.mjs")).toBeGreaterThan(block.indexOf("rev-parse HEAD"));
    expect(block.match(/\$clone\\scripts/g)).toHaveLength(1);
  });

  it("D-107 C-1: staging checks the source's integration before it builds anything, and refuses on any problem", () => {
    const s = code("scripts/package/stage-release.mjs");
    const gate = s.indexOf("stagingSourceGate(");
    expect(gate).toBeGreaterThan(-1);
    for (const later of ["nodeVersion(o.nodeWin", "mkdtempSync(", "runOk("]) expect(s.indexOf(later), later).toBeGreaterThan(gate);
    expect(s).toMatch(/if \(gate\.problems\.length\) \{\s*process\.stderr\.write\(``\);\s*return 1;\s*\}/);
  });
});
