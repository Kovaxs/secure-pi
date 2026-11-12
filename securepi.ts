/**
 * securepi: a Pi extension that gates access to credential stores.
 *
 * Intercepts tool calls (bash, read, write, edit, grep, find, ls) and asks for
 * confirmation before anything touches password stores, GPG, Pi credential
 * files, or user-blacklisted paths. Without an interactive UI, such calls are
 * blocked.
 *
 * Users manage the blacklist with `/securepi add <path>` (requires approval)
 * and `/securepi list`. The model cannot change it: writes to the blacklist
 * file are gated like any other ~/.pi/agent file.
 *
 * This is a speed bump, not a sandbox: commands can be obfuscated, and any
 * extension or process running as your user can bypass it.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

// Shell commands that reach password stores or GPG.
const SENSITIVE_COMMANDS: RegExp[] = [
	/(^|[\s;&|(`'"\/])(pass|gpg|gpg2|gpgconf|pinentry[\w-]*)(\s|$)/,
	/\.password-store\b/,
	/\.gnupg\b/,
];

// Files and directories holding credentials, in bash commands or tool paths.
const SENSITIVE_PATHS: RegExp[] = [
	/(^|\/)auth\.json\b/,
	/(^|\/)mcp-auth\.json\b/,
	/(^|\/)trust\.json\b/,
	/(^|\/)\.password-store(\/|$)/,
	/(^|\/)\.gnupg(\/|$)/,
	/(^|\/)\.pi\/agent(\/|$)/,
	/(^|\/)\.env(\.|$)/,
];

// User-managed blacklist of absolute paths (JSON array of strings).
const BLACKLIST_FILE = join(homedir(), ".pi", "agent", "securepi-blacklist.json");

// Tools that modify files: a sensitive path is never auto-allowed for these.
const WRITE_TOOLS = new Set(["write", "edit"]);

function matchesAny(patterns: RegExp[], text: string): boolean {
	return patterns.some((p) => p.test(text));
}

function expandHome(p: string): string {
	if (p === "~") return homedir();
	if (p.startsWith("~/")) return join(homedir(), p.slice(2));
	return p;
}

function loadBlacklist(): string[] {
	if (!existsSync(BLACKLIST_FILE)) return [];
	try {
		const data = JSON.parse(readFileSync(BLACKLIST_FILE, "utf8"));
		return Array.isArray(data) ? data.filter((x): x is string => typeof x === "string") : [];
	} catch {
		return [];
	}
}

function saveBlacklist(entries: string[]): void {
	mkdirSync(dirname(BLACKLIST_FILE), { recursive: true });
	writeFileSync(BLACKLIST_FILE, `${JSON.stringify(entries, null, 2)}\n`);
}

// A tool path matches an entry if it is the entry or lies inside it.
function pathMatchesBlacklist(target: string, cwd: string, entries: string[]): boolean {
	const abs = resolve(cwd, expandHome(target));
	return entries.some((entry) => {
		const prefix = entry.endsWith(sep) ? entry : entry + sep;
		return abs === entry || abs.startsWith(prefix);
	});
}

// True if `needle` occurs in `text` not followed by a path-name character,
// so "/a/client" does not match "/a/clientele".
function containsPath(text: string, needle: string): boolean {
	for (let i = text.indexOf(needle); i !== -1; i = text.indexOf(needle, i + 1)) {
		const next = text[i + needle.length];
		if (next === undefined || !/[\w.-]/.test(next)) return true;
	}
	return false;
}

// A bash command matches if it mentions an entry, absolute or as "~/...".
function commandMatchesBlacklist(command: string, entries: string[]): boolean {
	const home = homedir();
	return entries.some((entry) => {
		const tilde = entry === home ? "~" : entry.startsWith(home + sep) ? "~" + entry.slice(home.length) : entry;
		return containsPath(command, entry) || containsPath(command, tilde);
	});
}

export default function (pi: ExtensionAPI) {
	pi.on("tool_call", async (event, ctx) => {
		let target: string | undefined;
		let isBash = false;
		let patterns: RegExp[];

		if (event.toolName === "bash") {
			target = event.input.command as string;
			isBash = true;
			patterns = [...SENSITIVE_COMMANDS, ...SENSITIVE_PATHS];
		} else if (["read", "write", "edit", "grep", "find", "ls"].includes(event.toolName)) {
			const path = (event.input.path as string | undefined) ?? "";
			target = path;
			patterns = SENSITIVE_PATHS;
		} else {
			return undefined;
		}

		if (!target) return undefined;

		const blacklist = loadBlacklist();
		const listed = isBash
			? commandMatchesBlacklist(target, blacklist)
			: pathMatchesBlacklist(target, ctx.cwd, blacklist);

		if (!listed && !matchesAny(patterns, target)) return undefined;

		const label = event.toolName === "bash" ? "command" : `${event.toolName} path`;
		const note = listed && !matchesAny(patterns, target) ? "\n\n(user blacklist)" : "";
		const isWrite = WRITE_TOOLS.has(event.toolName);

		if (!ctx.hasUI) {
			return { block: true, reason: `securepi: blocked ${label} touching credentials (no UI to confirm)` };
		}

		const choice = await ctx.ui.select(
			`🔐 securepi: model wants to access credentials via ${label}:\n\n  ${target}${note}\n\nAllow?`,
			isWrite ? ["No"] : ["Yes", "No"],
		);

		if (choice !== "Yes") {
			return { block: true, reason: "securepi: blocked by user" };
		}
		return undefined;
	});

	pi.registerCommand("securepi", {
		description: "Manage the securepi path blacklist: /securepi add <path> | /securepi list",
		getArgumentCompletions: (prefix: string) => {
			if (prefix.includes(" ")) return null;
			const items = ["add", "list"].filter((s) => s.startsWith(prefix)).map((s) => ({ value: s, label: s }));
			return items.length > 0 ? items : null;
		},
		handler: async (args, ctx) => {
			const [sub = "", ...rest] = args.trim().split(/\s+/);
			const arg = rest.join(" ").trim();

			if (sub === "list" || sub === "") {
				const entries = loadBlacklist();
				ctx.ui.notify(
					entries.length > 0
						? `securepi blacklist:\n${entries.map((e) => `  ${e}`).join("\n")}`
						: "securepi blacklist is empty",
					"info",
				);
				return;
			}

			if (sub !== "add" || !arg) {
				ctx.ui.notify("Usage: /securepi add <path> | /securepi list", "error");
				return;
			}

			if (!ctx.hasUI) {
				ctx.ui.notify("securepi: adding a path requires interactive approval", "error");
				return;
			}

			const abs = resolve(ctx.cwd, expandHome(arg));
			if (abs === sep) {
				ctx.ui.notify("securepi: refusing to blacklist the filesystem root", "error");
				return;
			}

			const entries = loadBlacklist();
			if (entries.includes(abs)) {
				ctx.ui.notify(`securepi: already blacklisted: ${abs}`, "info");
				return;
			}

			const approved = await ctx.ui.confirm(
				"Add path to securepi blacklist?",
				`${abs}\n\nAny tool access to this path will require your approval.`,
			);
			if (!approved) {
				ctx.ui.notify("securepi: not added", "info");
				return;
			}

			entries.push(abs);
			saveBlacklist(entries);
			ctx.ui.notify(`securepi: blacklisted ${abs}`, "info");
		},
	});
}
