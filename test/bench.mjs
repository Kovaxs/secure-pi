// Timing: median µs per tool_call for a baseline build and the current build.
// Usage: node test/bench.mjs <baseline.mjs> <current.mjs>   (N=2000 by default)
// Needs a built extension and its defaults/ folder beside each build; test/run.sh
// creates that layout. The temporary HOME is created here and removed on exit.
import * as fsm from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [baseline, current] = process.argv.slice(2);
if (!baseline || !current) {
	console.error("usage: node test/bench.mjs <baseline.mjs> <current.mjs>");
	process.exit(2);
}
const ROOT = fsm.mkdtempSync(join(tmpdir(), "securepi-bench-"));
process.on("exit", () => fsm.rmSync(ROOT, { recursive: true, force: true }));
process.env.HOME = join(ROOT, "home");
const P = join(ROOT, "proj");
fsm.mkdirSync(join(process.env.HOME, ".pi/agent"), { recursive: true });
fsm.mkdirSync(join(P, "src"), { recursive: true });

const load = async (m) => {
	const h = {};
	(await import(m)).default({ on: (n, f) => (h[n] = f), registerCommand: () => {} });
	return h.tool_call;
};
const oldCall = await load(baseline);
const newCall = await load(current);
const ctx = { cwd: P, hasUI: true, ui: { select: async () => "No" } };
const cases = [
	["ls -la", "bash"],
	["git status", "bash"],
	["grep -r foo src", "bash"],
	['find . -name "*.ts" -exec wc -l {} \\;', "bash"],
	["cd proj && ls", "bash"],
	["timeout 5 gpg --list-keys", "bash"],
	["read README.md", "read"],
	["read auth.json", "read"],
];
const N = Number(process.env.N || 2000);
const time = async (fn, c, t) => {
	const input = t === "bash" ? { command: c } : { path: c };
	const t0 = process.hrtime.bigint();
	for (let i = 0; i < N; i++) await fn({ toolName: t, input }, ctx);
	return Number(process.hrtime.bigint() - t0) / N / 1000;
};
const median = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];

console.log(`N=${N}, median of 5 alternating rounds, µs per call`);
console.log("command".padEnd(36) + "baseline".padStart(11) + "current".padStart(10) + "delta".padStart(10));
for (const [c, t] of cases) {
	await time(oldCall, c, t);
	await time(newCall, c, t);
	const o = [];
	const n = [];
	for (let r = 0; r < 5; r++) {
		o.push(await time(oldCall, c, t));
		n.push(await time(newCall, c, t));
	}
	const mo = median(o);
	const mn = median(n);
	const d = (mn - mo >= 0 ? "+" : "") + (mn - mo).toFixed(1);
	console.log(c.slice(0, 33).padEnd(36) + mo.toFixed(1).padStart(11) + mn.toFixed(1).padStart(10) + d.padStart(10));
}
