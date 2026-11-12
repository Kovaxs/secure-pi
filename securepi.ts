/**
 * securepi: a Pi extension that gates access to restricted files and CLI tools.
 *
 * Two user-managed lists control what needs approval:
 *   - files: glob patterns for files and directories (absolute, or "**" for any depth)
 *   - cli:   program names that need approval when a bash command runs them
 *
 * The lists are the only source of restrictions. Their contents are seeded with
 * defaults until the list file is first written. Manage them with /securepi.
 * Every change to a list asks for approval.
 *
 * This is a speed bump, not a sandbox: commands can be obfuscated, and any
 * extension or process running as your user can bypass it.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import * as fs from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve, sep } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

// Seed values, used only until the list file is first written.
const DEFAULT_FILES = [
	"**/auth.json",
	"**/mcp-auth.json",
	"**/trust.json",
	"**/.password-store",
	"**/.gnupg",
	"**/models.json",
	"**/.env",
	"**/.env.*",
	"**/securepi-blacklist.json",
	"**/securepi-cli.json",
];
const DEFAULT_CLI = ["pass", "gpg", "gpg2", "gpgconf", "pinentry*"];

const AGENT_DIR = join(homedir(), ".pi", "agent");

interface Store {
	title: string;
	file: string;
	defaults: string[];
	normalize: (raw: string, cwd: string) => string; // throws if invalid
}

interface LoadResult {
	entries: string[];
	source: "file" | "default" | "default-corrupt";
}

interface Reason {
	kind: "file" | "cli";
	subject: string;
	entry: string;
	command?: string;
}

const FILES: Store = {
	title: "Files and directories",
	file: join(AGENT_DIR, "securepi-blacklist.json"),
	defaults: DEFAULT_FILES,
	normalize: normalizeFile,
};

const CLI: Store = {
	title: "CLI tools",
	file: join(AGENT_DIR, "securepi-cli.json"),
	defaults: DEFAULT_CLI,
	normalize: (raw) => normalizeCli(raw),
};

// Tools that modify files: a restricted path is never auto-allowed for these.
const WRITE_TOOLS = new Set(["write", "edit"]);
const PATH_TOOLS = new Set(["read", "write", "edit", "grep", "find", "ls"]);

// Command separators used to split a bash command into segments.
const SEGMENT_SPLIT = /&&|\|\||[;|&\n(){}`]/;
// Prefixes that run another program; the program name follows them.
const WRAPPERS = new Set(["sudo", "doas", "env", "command", "exec", "nohup", "time", "nice", "xargs"]);

type GlobSync = (pattern: string, opts: { cwd: string }) => string[];
const globSync = (fs as unknown as { globSync?: GlobSync }).globSync;

function expandHome(p: string): string {
	if (p === "~") return homedir();
	if (p.startsWith("~/")) return join(homedir(), p.slice(2));
	return p;
}

// ---------- glob matching ----------

// "*" stays in one path segment, "**/" matches any number of directories,
// "**" matches anything, "?" matches one character, "[...]" is a character class.
function globToRegExp(glob: string): RegExp {
	let re = "";
	for (let i = 0; i < glob.length; i++) {
		const c = glob[i];
		if (c === "*") {
			if (glob[i + 1] === "*") {
				i++;
				if (glob[i + 1] === "/") {
					i++;
					re += "(?:.*/)?";
				} else {
					re += ".*";
				}
			} else {
				re += "[^/]*";
			}
		} else if (c === "?") {
			re += "[^/]";
		} else if (c === "[" && glob.indexOf("]", i + 1) > i) {
			const end = glob.indexOf("]", i + 1);
			const body = glob.slice(i + 1, end).replace(/\\/g, "\\\\").replace(/^!/, "^");
			re += `[${body}]`;
			i = end;
		} else {
			re += c.replace(/[.+^${}()|\\\/]/g, "\\$&");
		}
	}
	return new RegExp(`^${re}$`);
}

// A path matches an entry if the path or any of its parent directories matches.
function matchesFileEntry(entry: string, abs: string): boolean {
	const re = globToRegExp(entry);
	let p = abs;
	for (;;) {
		if (re.test(p)) return true;
		const parent = dirname(p);
		if (parent === p) return false;
		p = parent;
	}
}

function matchFile(abs: string, entries: string[]): string | undefined {
	return entries.find((e) => matchesFileEntry(e, abs));
}

// ---------- list storage ----------

function loadList(store: Store): LoadResult {
	if (!existsSync(store.file)) return { entries: [...store.defaults], source: "default" };
	try {
		const data = JSON.parse(readFileSync(store.file, "utf8"));
		if (Array.isArray(data) && data.every((x) => typeof x === "string")) {
			return { entries: data, source: "file" };
		}
	} catch {
		// fall through to defaults
	}
	return { entries: [...store.defaults], source: "default-corrupt" };
}

function saveList(store: Store, entries: string[]): void {
	mkdirSync(dirname(store.file), { recursive: true });
	writeFileSync(store.file, `${JSON.stringify(entries, null, 2)}\n`);
}

// ---------- validation ----------

function normalizeFile(raw: string, cwd: string): string {
	if (!raw.trim()) throw new Error("empty path");
	// "**" patterns are kept as written; everything else becomes an absolute path.
	const entry = raw.startsWith("**") ? raw.replace(/\/+$/, "") : resolve(cwd, expandHome(raw));
	if (!entry || entry === "**") throw new Error("pattern is too broad");
	const re = globToRegExp(entry);
	if (re.test("/") || re.test("/x")) throw new Error("pattern is too broad");
	return entry;
}

function normalizeCli(raw: string): string {
	const name = raw.trim();
	if (!name || /\s/.test(name)) throw new Error("name must not be empty or contain spaces");
	if (/^[*?]+$/.test(name)) throw new Error("pattern is too broad");
	return name;
}

// ---------- bash parsing ----------

function tokenize(text: string): string[] {
	const out: string[] = [];
	const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
	for (let m = re.exec(text); m; m = re.exec(text)) {
		out.push(m[1] ?? m[2] ?? m[3]);
	}
	return out;
}

// Program names that a command runs, one per segment.
function programs(command: string): string[] {
	const names: string[] = [];
	for (const segment of command.split(SEGMENT_SPLIT)) {
		const tokens = tokenize(segment);
		let i = 0;
		while (
			i < tokens.length &&
			(/^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i]) || WRAPPERS.has(basename(tokens[i])) || tokens[i].startsWith("-"))
		) {
			i++;
		}
		if (i < tokens.length) names.push(tokens[i]);
	}
	return names;
}

function matchCli(prog: string, entries: string[], cwd: string): string | undefined {
	const name = basename(prog);
	const full = resolve(cwd, expandHome(prog));
	return entries.find((e) => {
		const re = globToRegExp(e);
		return e.includes("/") ? re.test(prog) || re.test(full) : re.test(name);
	});
}

// Absolute paths a bash command may touch. Wildcard tokens are expanded
// against the filesystem when the runtime supports fs.globSync.
function bashPathCandidates(command: string, cwd: string): string[] {
	const found = new Set<string>();
	for (const segment of command.split(SEGMENT_SPLIT)) {
		for (const token of tokenize(segment)) {
			const parts = [token];
			const eq = token.indexOf("=");
			if (eq >= 0) parts.push(token.slice(eq + 1));
			for (const raw of parts) {
				if (!raw) continue;
				const pattern = expandHome(raw);
				if (/[*?[]/.test(pattern) && globSync) {
					try {
						for (const hit of globSync(pattern, { cwd })) found.add(resolve(cwd, hit));
					} catch {
						// unreadable directory: fall back to the literal pattern
					}
				}
				found.add(resolve(cwd, pattern));
			}
		}
	}
	return [...found];
}

// ---------- decision ----------

function findReason(toolName: string, input: Record<string, unknown>, cwd: string): Reason | undefined {
	const files = loadList(FILES).entries;

	if (toolName === "bash") {
		const command = String(input.command ?? "");
		const cli = loadList(CLI).entries;
		for (const prog of programs(command)) {
			const entry = matchCli(prog, cli, cwd);
			if (entry) return { kind: "cli", subject: prog, entry, command };
		}
		for (const candidate of bashPathCandidates(command, cwd)) {
			const entry = matchFile(candidate, files);
			if (entry) return { kind: "file", subject: candidate, entry, command };
		}
		return undefined;
	}

	if (!PATH_TOOLS.has(toolName)) return undefined;
	const path = typeof input.path === "string" ? input.path : "";
	if (!path) return undefined;
	const abs = resolve(cwd, expandHome(path));
	const entry = matchFile(abs, files);
	return entry ? { kind: "file", subject: abs, entry } : undefined;
}

// ---------- commands ----------

function formatList(store: Store, result: LoadResult): string {
	const note =
		result.source === "default"
			? " (defaults, no file yet)"
			: result.source === "default-corrupt"
				? " (file unreadable, showing defaults)"
				: "";
	const body = result.entries.length ? result.entries.map((e) => `  ${e}`).join("\n") : "  (empty)";
	return `${store.title}${note}:\n${body}`;
}

function corruptNote(result: LoadResult): string {
	return result.source === "default-corrupt"
		? "\n\nNote: the existing list file is unreadable. Saving will replace it."
		: "";
}

function fail(ctx: ExtensionContext, message: string): void {
	ctx.ui.notify(message, "error");
}

function info(ctx: ExtensionContext, message: string): void {
	ctx.ui.notify(message, "info");
}

const USAGE =
	"Usage:\n" +
	"  /securepi list\n" +
	"  /securepi files list | add <path...> | remove <entry...> | clear\n" +
	"  /securepi cli list | add <name...> | remove <name...> | clear";

async function addItems(store: Store, items: string[], ctx: ExtensionContext): Promise<void> {
	if (items.length === 0) return fail(ctx, USAGE);
	const current = loadList(store);
	const fresh: string[] = [];
	const skipped: string[] = [];
	const problems: string[] = [];

	for (const raw of items) {
		try {
			const entry = store.normalize(raw, ctx.cwd);
			if (current.entries.includes(entry) || fresh.includes(entry)) skipped.push(entry);
			else fresh.push(entry);
		} catch (err) {
			problems.push(`${raw}: ${(err as Error).message}`);
		}
	}

	if (problems.length) return fail(ctx, `securepi: nothing added. Invalid entries:\n${problems.join("\n")}`);
	if (skipped.length) info(ctx, `securepi: already listed: ${skipped.join(", ")}`);
	if (fresh.length === 0) return;

	const approved = await ctx.ui.confirm(
		`Add to securepi ${store.title} list?`,
		`${fresh.map((e) => `  + ${e}`).join("\n")}${corruptNote(current)}\n\nUse of these will require your approval.`,
	);
	if (!approved) return info(ctx, "securepi: not added");

	saveList(store, [...current.entries, ...fresh]);
	info(ctx, `securepi: added ${fresh.length} to ${store.title}`);
}

async function removeItems(store: Store, items: string[], ctx: ExtensionContext): Promise<void> {
	if (items.length === 0) return fail(ctx, USAGE);
	const current = loadList(store);
	const toRemove: string[] = [];
	const missing: string[] = [];

	for (const raw of items) {
		let entry: string | undefined;
		if (current.entries.includes(raw)) entry = raw;
		else {
			try {
				const normalized = store.normalize(raw, ctx.cwd);
				if (current.entries.includes(normalized)) entry = normalized;
			} catch {
				// not a valid entry, so it cannot be in the list
			}
		}
		if (entry) {
			if (!toRemove.includes(entry)) toRemove.push(entry);
		} else {
			missing.push(raw);
		}
	}

	if (missing.length) info(ctx, `securepi: not in the ${store.title} list: ${missing.join(", ")}`);
	if (toRemove.length === 0) return;

	const approved = await ctx.ui.confirm(
		`Remove from securepi ${store.title} list?`,
		`${toRemove.map((e) => `  - ${e}`).join("\n")}${corruptNote(current)}\n\nThese will no longer require approval.`,
	);
	if (!approved) return info(ctx, "securepi: not removed");

	saveList(store, current.entries.filter((e) => !toRemove.includes(e)));
	info(ctx, `securepi: removed ${toRemove.length} from ${store.title}`);
}

async function clearItems(store: Store, ctx: ExtensionContext): Promise<void> {
	const current = loadList(store);
	if (current.entries.length === 0 && current.source === "file") {
		return info(ctx, `securepi: ${store.title} list is already empty`);
	}

	const approved = await ctx.ui.confirm(
		`Clear the securepi ${store.title} list?`,
		`This removes all ${current.entries.length} entries:\n${current.entries.map((e) => `  ${e}`).join("\n") || "  (none)"}${corruptNote(current)}`,
	);
	if (!approved) return info(ctx, "securepi: list not cleared");

	saveList(store, []);
	info(ctx, `securepi: cleared ${store.title} list`);
}

export default function (pi: ExtensionAPI) {
	pi.on("tool_call", async (event, ctx) => {
		const reason = findReason(event.toolName, event.input as Record<string, unknown>, ctx.cwd);
		if (!reason) return undefined;

		const what =
			reason.kind === "cli"
				? `CLI tool ${reason.subject}`
				: event.toolName === "bash"
					? "file path in command"
					: `${event.toolName} path`;

		if (!ctx.hasUI) {
			return { block: true, reason: `securepi: blocked ${what} (no UI to confirm)` };
		}

		const details = reason.command ? `\n  command: ${reason.command}` : "";
		const choice = await ctx.ui.select(
			`🔐 securepi: restricted ${what}\n\n  ${reason.subject}${details}\n  matches list entry: ${reason.entry}\n\nAllow?`,
			WRITE_TOOLS.has(event.toolName) ? ["No"] : ["Yes", "No"],
		);

		if (choice !== "Yes") {
			return { block: true, reason: "securepi: blocked by user" };
		}
		return undefined;
	});

	pi.registerCommand("securepi", {
		description: "Manage securepi lists: /securepi list | files ... | cli ...",
		getArgumentCompletions: (prefix: string) => {
			const words = prefix.split(" ");
			let options: string[] | undefined;
			if (words.length === 1) options = ["list", "files", "cli"];
			else if (words.length === 2 && (words[0] === "files" || words[0] === "cli")) {
				options = ["list", "add", "remove", "clear"];
			}
			if (!options) return null;
			const items = options
				.filter((o) => o.startsWith(words[words.length - 1]))
				.map((o) => ({ value: [...words.slice(0, -1), o].join(" "), label: o }));
			return items.length > 0 ? items : null;
		},
		handler: async (args, ctx) => {
			const [group = "", action = "", ...rest] = tokenize(args);

			if (group === "" || group === "list") {
				info(ctx, `${formatList(FILES, loadList(FILES))}\n\n${formatList(CLI, loadList(CLI))}`);
				return;
			}

			const store = group === "files" ? FILES : group === "cli" ? CLI : undefined;
			if (!store) return fail(ctx, USAGE);

			if (action === "list") {
				info(ctx, formatList(store, loadList(store)));
				return;
			}

			if (!["add", "remove", "clear"].includes(action)) return fail(ctx, USAGE);
			if (!ctx.hasUI) return fail(ctx, "securepi: changing a list requires interactive approval");

			if (action === "add") return addItems(store, rest, ctx);
			if (action === "remove") return removeItems(store, rest, ctx);
			return clearItems(store, ctx);
		},
	});
}
