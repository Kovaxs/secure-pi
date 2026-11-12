// securepi behaviour tests. Run through test/run.sh, which builds securepi.ts and
// sets the environment this file needs:
//   HOME       temporary home directory (the real ~/.pi/agent is never touched)
//   TEST_ROOT  temporary root; this file creates the fixture tree under it
//   DEFS       directory holding the shipped default lists
//   MOD        path of the built extension to load
import * as fsm from "node:fs";
import { join } from "node:path";

const ROOT = process.env.TEST_ROOT;
const H = join(ROOT, "home");
const P = join(ROOT, "proj");
const DEFS = process.env.DEFS;

// ---------- fixtures ----------
fsm.rmSync(ROOT, { recursive: true, force: true });
for (const d of [
	"work/sub", "secrets/a", ".gnupg", ".pi/agent", ".ssh",
]) fsm.mkdirSync(join(H, d), { recursive: true });
fsm.mkdirSync(join(P, "sub"), { recursive: true });
for (const f of [
	"work/a.json", "work/sub/x.json", "secrets/a/b.txt", ".gnupg/x",
	".pi/agent/settings.json", ".pi/agent/models.json",
]) fsm.writeFileSync(join(H, f), "x\n");
for (const f of ["README.md", "auth.json", ".env", ".env.local", ".envrc", "notes.txt"]) {
	fsm.writeFileSync(join(P, f), "x\n");
}

// ---------- harness ----------
const mod = await import(process.env.MOD);
const handlers = [];
const commands = {};
mod.default({ on: (n, h) => handlers.push([n, h]), registerCommand: (n, o) => (commands[n] = o) });
const toolCall = handlers.find(([n]) => n === "tool_call")[1];

let confirmAnswer = true;
let selectAnswer = "Yes";
let hasUI = true;
let notes = [];
let selects = [];
const ctx = {
	cwd: P,
	get hasUI() {
		return hasUI;
	},
	ui: {
		notify: (m, t) => notes.push(`[${t}] ${m}`),
		confirm: async () => confirmAnswer,
		select: async (_t, opts) => {
			selects.push(opts);
			return selectAnswer;
		},
	},
};

let pass = 0;
let fail = 0;
const ok = (name, cond, extra = "") => {
	if (cond) pass++;
	else fail++;
	console.log(`${cond ? "PASS" : "FAIL"} ${name}${cond ? "" : `  ${extra}`}`);
};
// true = the call was blocked (needs approval and the answer was No)
const gate = async (toolName, input) => {
	selectAnswer = "No";
	const r = await toolCall({ toolName, input }, ctx);
	return !!r;
};
const bash = (command) => gate("bash", { command });
const cmd = async (args) => {
	notes = [];
	await commands.securepi.handler(args, ctx);
	return notes.join("\n");
};
const listFile = join(H, ".pi/agent/securepi-blacklist.json");
const cliFile = join(H, ".pi/agent/securepi-cli.json");
const readJ = (f) => JSON.parse(fsm.readFileSync(f, "utf8"));
const shippedFiles = readJ(join(DEFS, "securepi-files.json"));
const shippedCli = readJ(join(DEFS, "securepi-cli.json"));

// ---------- seeding from shipped defaults ----------
console.log("== seeding from shipped defaults ==");
ok("no list file before first use", !fsm.existsSync(listFile) && !fsm.existsSync(cliFile));
ok("read README allowed", !(await gate("read", { path: "README.md" })));
ok("list file seeded from shipped defaults",
	fsm.existsSync(listFile) && JSON.stringify(readJ(listFile)) === JSON.stringify(shippedFiles));
ok("read auth.json gated", await gate("read", { path: "auth.json" }));
ok("read models.json gated", await gate("read", { path: join(H, ".pi/agent/models.json") }));
ok("read .pi/agent/settings.json allowed", !(await gate("read", { path: join(H, ".pi/agent/settings.json") })));
ok("read securepi-blacklist.json gated", await gate("read", { path: listFile }));
ok("bash write to securepi-cli.json gated", await bash(`echo [] > ${cliFile}`));
ok("write securepi-cli.json: No only",
	(await gate("write", { path: cliFile })) && selects.at(-1).join() === "No");
ok("read .env.local gated", await gate("read", { path: ".env.local" }));
ok("read .envrc allowed", !(await gate("read", { path: ".envrc" })));
ok("read .gnupg gated", await gate("read", { path: join(H, ".gnupg/x") }));
hasUI = false;
const noUi = await gate("read", { path: "auth.json" });
hasUI = true;
ok("no UI: blocked", noUi);

// ---------- cli defaults and bash controls ----------
console.log("== cli defaults and bash controls ==");
ok("bash gpg gated", await bash("gpg --list-keys"));
ok("cli file seeded", fsm.existsSync(cliFile) && JSON.stringify(readJ(cliFile)) === JSON.stringify(shippedCli));
ok("bash echo gpg allowed", !(await bash("echo gpg")));
ok('bash echo "pass" allowed', !(await bash('echo "pass"')));
ok("bash env-prefixed pass gated", await bash("FOO=1 pass show x"));
ok("bash sudo pass gated", await bash("ls && sudo pass show"));
ok("bash cat ./auth.json gated", await bash("cat ./auth.json"));
ok("bash ls allowed", !(await bash("ls -la")));
ok("bash git status allowed", !(await bash("git status")));
ok("bash cat README.md allowed", !(await bash("cat README.md")));
ok("bash grep in notes allowed", !(await bash("grep hello notes.txt")));
ok("bash npm test allowed", !(await bash("npm test")));
ok("bash echo HOME allowed", !(await bash("echo $HOME")));

// ---------- files add, wildcards, directories ----------
console.log("== files add, wildcards, directories ==");
confirmAnswer = true;
await cmd("files add ~/work/*.json");
ok("entry appended to seeded list",
	readJ(listFile).length === shippedFiles.length + 1 && readJ(listFile).at(-1) === `${H}/work/*.json`);
ok("bash cat ~/work/*.json gated (expanded)", await bash("cat ~/work/*.json"));
ok("read work/a.json gated", await gate("read", { path: join(H, "work/a.json") }));
ok("read work/sub/x.json allowed (* is one level)", !(await gate("read", { path: join(H, "work/sub/x.json") })));
await cmd("files add ~/secrets");
ok("dir entry covers children", await gate("read", { path: join(H, "secrets/a/b.txt") }));
ok("sibling dir allowed", !(await bash(`ls ${H}/secretsX`)));
await cmd('files add "~/My Docs/**/*.key"');
ok("quoted ** entry added", readJ(listFile).includes(`${H}/My Docs/**/*.key`));
ok("duplicate reported", (await cmd("files add ~/secrets")).includes("already listed"));
await cmd("files add **");
ok("'**' refused", !readJ(listFile).includes("**"));
await cmd("files add /");
ok("'/' refused", !readJ(listFile).includes("/"));
confirmAnswer = false;
await cmd("files add ~/denied");
ok("denied add not saved", !readJ(listFile).includes(`${H}/denied`));
confirmAnswer = true;
await cmd("files remove ~/secrets nosuch");
ok("remove by ~ path", !readJ(listFile).includes(`${H}/secrets`));
ok("removed children allowed", !(await gate("read", { path: join(H, "secrets/a/b.txt") })));
ok("remove keeps shipped entries", readJ(listFile).includes("**/auth.json"));

// ---------- cli list commands ----------
console.log("== cli list commands ==");
await cmd("cli add mytool");
ok("cli list has defaults + mytool", readJ(cliFile).includes("pass") && readJ(cliFile).includes("mytool"));
ok("custom cli gated", await bash("mytool --x"));
await cmd("cli remove mytool");
ok("cli removed", !readJ(cliFile).includes("mytool"));
await cmd("cli clear");
ok("cli clear -> []", readJ(cliFile).length === 0);
ok("cleared cli: gpg allowed", !(await bash("gpg --list-keys")));
await cmd("files clear");
ok("files clear -> []", readJ(listFile).length === 0);
ok("cleared: auth.json allowed", !(await gate("read", { path: "auth.json" })));

// ---------- corrupt list and missing shipped defaults ----------
console.log("== corrupt list and missing shipped defaults ==");
fsm.writeFileSync(listFile, "{bad json");
ok("corrupt file -> shipped defaults still gate", await gate("read", { path: "auth.json" }));
ok("corrupt file not overwritten by a read", fsm.readFileSync(listFile, "utf8") === "{bad json");
ok("list view notes unreadable file", (await cmd("files list")).includes("unreadable"));
fsm.rmSync(listFile, { force: true });
fsm.rmSync(cliFile, { force: true });
fsm.renameSync(DEFS, `${DEFS}.moved`);
let threw = false;
try {
	await gate("read", { path: "README.md" });
} catch {
	threw = true;
}
fsm.renameSync(`${DEFS}.moved`, DEFS);
ok("missing shipped defaults -> tool call fails closed", threw);
ok("no list file written when defaults are missing", !fsm.existsSync(listFile));
fsm.rmSync(listFile, { force: true });
fsm.rmSync(cliFile, { force: true });

// ---------- command errors ----------
console.log("== command errors ==");
ok("usage on bogus", (await cmd("bogus")).includes("Usage"));
hasUI = false;
await cmd("files add x");
hasUI = true;
ok("add without UI refused", !fsm.existsSync(listFile));

// ---------- bypasses that must be caught ----------
console.log("== bypasses: must be caught ==");
ok("cd then relative into gnupg", await bash("cd ~/.gnupg && cat x"));
ok("cd home then .gnupg/x", await bash("cd ~ && cat .gnupg/x"));
ok("$HOME/.gnupg/x", await bash("cat $HOME/.gnupg/x"));
ok("quote-split name ~/.g''nupg/x", await bash("cat ~/.g''nupg/x"));
ok("backslash name ~/.gn\\upg/x", await bash("cat ~/.gn\\upg/x"));
ok("brace expansion ~/.{gnupg,ssh}/x", await bash("cat ~/.{gnupg,ssh}/x"));
ok("timeout 5 gpg", await bash("timeout 5 gpg --list-keys"));
ok("timeout -s KILL 5 gpg", await bash("timeout -s KILL 5 gpg --list-keys"));
ok('sh -c "gpg ..."', await bash('sh -c "gpg --list-keys"'));
ok("bash -lc 'pass show x'", await bash("bash -lc 'pass show x'"));
ok("timeout 5 bash -c 'gpg x'", await bash("timeout 5 bash -c 'gpg x'"));
ok("python3 -c inline code",
	await bash(`python3 -c "import subprocess;subprocess.run(['gpg','--list-keys'])"`));
ok("eval with variable (unresolved)", await bash('c=gp; eval "${c}g --list-keys"'));
ok("cp $(which gpg) copy", await bash("cp $(which gpg) ./tool && ./tool --list-keys"));
ok("cp /usr/bin/gpg copy", await bash("cp /usr/bin/gpg ./tool"));
ok("find -exec gpg", await bash("find . -name x -exec gpg {} \\;"));
ok("find -exec cat ~/.gnupg/x", await bash("find . -exec cat ~/.gnupg/x \\;"));
ok("unresolved variable in arg", await bash("cat $SOMEFILE"));
ok("/usr/local/bin/gpg (control)", await bash("/usr/local/bin/gpg --list-keys"));
await cmd(`files add ${H}/secrets`);
ok("cd home then secrets/a/b.txt (absolute entry)", await bash("cd ~ && cat secrets/a/b.txt"));
ok("pushd home then secrets/a", await bash("pushd ~ >/dev/null && cat secrets/a/b.txt"));
fsm.rmSync(listFile, { force: true });

// ---------- normal commands that must not be blocked ----------
console.log("== no false positives ==");
ok("subshell cd then ls", !(await bash("(cd proj && ls)")));
ok("grep pattern with pass word", !(await bash("grep -r 'password' src")));
ok("git commit -m with gpg word", !(await bash('git commit -m "fix gpg docs"')));
ok("loop with $i asks (unresolved, documented cost)", await bash("for i in 1 2 3; do echo $i; done"));

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
