/**
 * securepi: a Pi extension that gates access to credential stores.
 *
 * Intercepts tool calls (bash, read, write, edit, grep, find, ls) and asks for
 * confirmation before anything touches password stores, GPG, or Pi credential
 * files. Without an interactive UI, such calls are blocked.
 *
 * This is a speed bump, not a sandbox: commands can be obfuscated, and any
 * extension or process running as your user can bypass it.
 */

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

// Tools that modify files: a sensitive path is never auto-allowed for these.
const WRITE_TOOLS = new Set(["write", "edit"]);

function matchesAny(patterns: RegExp[], text: string): boolean {
	return patterns.some((p) => p.test(text));
}

export default function (pi: ExtensionAPI) {
	pi.on("tool_call", async (event, ctx) => {
		let target: string | undefined;
		let patterns: RegExp[];

		if (event.toolName === "bash") {
			target = event.input.command as string;
			patterns = [...SENSITIVE_COMMANDS, ...SENSITIVE_PATHS];
		} else if (["read", "write", "edit", "grep", "find", "ls"].includes(event.toolName)) {
			const path = (event.input.path as string | undefined) ?? "";
			target = path;
			patterns = SENSITIVE_PATHS;
		} else {
			return undefined;
		}

		if (!target || !matchesAny(patterns, target)) return undefined;

		const label = event.toolName === "bash" ? "command" : `${event.toolName} path`;
		const isWrite = WRITE_TOOLS.has(event.toolName);

		if (!ctx.hasUI) {
			return { block: true, reason: `securepi: blocked ${label} touching credentials (no UI to confirm)` };
		}

		const choice = await ctx.ui.select(
			`🔐 securepi: model wants to access credentials via ${label}:\n\n  ${target}\n\nAllow?`,
			isWrite ? ["No"] : ["Yes", "No"],
		);

		if (choice !== "Yes") {
			return { block: true, reason: "securepi: blocked by user" };
		}
		return undefined;
	});
}
