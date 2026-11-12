# securepi

A [Pi](https://pi.dev) extension that asks for confirmation before the agent touches restricted files or runs restricted CLI tools.

Restrictions come from two user-managed lists:

- **Files and directories:** paths or glob patterns. Any tool call that touches a match needs approval.
- **CLI tools:** program names. A bash command that runs one needs approval.

Nothing is hardcoded in the extension. The lists are seeded with defaults until you change them, and from then on only the list contents apply.

## Install and update

```bash
pi install git:github.com/kovaxs/secure-pi
pi update --extensions     # pull new versions
```

Then run `/reload` in Pi, or restart it.

## Default lists

Until the list files exist, these defaults apply:

| Files and directories | CLI tools |
|---|---|
| `**/auth.json` | `pass` |
| `**/mcp-auth.json` | `gpg` |
| `**/trust.json` | `gpg2` |
| `**/.password-store` | `gpgconf` |
| `**/.gnupg` | `pinentry*` |
| `**/models.json` | |
| `**/.env` | |
| `**/.env.*` | |
| `**/securepi-blacklist.json` | |
| `**/securepi-cli.json` | |

The defaults are only seed values. The first `add`, `remove`, or `clear` writes the list to disk, and the file is then the only source. Once `clear` empties a list, nothing in that list is restricted.

## Commands

```
/securepi                                  show both lists
/securepi list                             show both lists
/securepi files list
/securepi files add <path or pattern...>
/securepi files remove <entry...>
/securepi files clear
/securepi cli list
/securepi cli add <name...>
/securepi cli remove <name...>
/securepi cli clear
```

- Every `add`, `remove`, and `clear` asks for approval first. Changes are only saved if you confirm.
- `add` takes several arguments and shows one approval dialog for all of them. If any argument is invalid, nothing is added.
- Quote paths that contain spaces: `/securepi files add "~/My Docs/*.key"`.
- Entries that are already listed are skipped. Removing an entry that isn't listed does nothing.
- Commands are for you, not the model. The model can't change the lists, because the two list files are in the default files list. Reading them also asks for approval, since the gate can't reliably tell reads from writes in bash.

Examples:

```
/securepi files add ~/.ssh ~/.aws ~/.kube
/securepi files add ~/clients/*.json
/securepi files add "**/*.pem"
/securepi cli add mytool
/securepi files remove ~/.kube
/securepi files clear
```

## Matching rules

### Files and directories

- Entries are absolute paths, or patterns starting with `**`. Relative paths are resolved against the current directory when you add them, and `~` is expanded.
- `*` matches within one directory level. `**/` matches any number of directories, `**` matches anything, `?` matches one character, and `[abc]` matches a character class.
- A matching directory covers everything beneath it. `~/.ssh` covers `~/.ssh/id_ed25519`.
- `**/auth.json` matches `auth.json` in any directory.
- Overly broad patterns are refused: `/`, `**`, `**/*`, and similar.

### CLI tools

- Each command in a pipeline or chain is checked, including commands after `&&`, `||`, `;`, `|`, and inside `$( )`.
- The program is matched by name, so `pass` matches `/usr/bin/pass` as well as `pass`. Leading `VAR=value` assignments and wrappers (`sudo`, `env`, `nohup`, `timeout`, `nice`, `xargs`, and others) are skipped, so `timeout 5 gpg` is checked as `gpg`.
- `sh -c`, `bash -c`, and `eval` run their text as commands, and that text is checked the same way. `find -exec` checks the program it runs.
- Interpreters with inline code (`python3 -c`, `node -e`, `perl -e`) always ask, because their code can't be checked here.
- Copying or locating a restricted binary (`cp`, `mv`, `ln`, `which`, or any `$(...)`) asks when a restricted name appears in the command.
- An entry with a `/` is matched against the full path instead of the name.
- Names are glob patterns too: `pinentry*` matches `pinentry-mac`.
- Text that is only an argument does not count. `echo pass` is not a `pass` call.

### Bash paths

- Each argument is resolved against the current directory and checked against the file list. `--file=path` is checked too.
- Arguments are unquoted the way a shell does it: `'...'`, `"..."`, and backslashes are removed before matching, so `~/.g''nupg` is checked as `~/.gnupg`.
- `$HOME` and `~` are expanded, and brace alternatives such as `~/.{gnupg,ssh}` are each checked.
- `cd` and `pushd` change the base for later relative paths, so `cd ~ && cat .gnupg/x` is checked against the real location.
- Arguments with `*`, `?`, or `[` are expanded against the filesystem before checking, so `cat ~/work/*.json` is checked against the real matching files.
- A command with any other shell variable (`$FOO`, `$1`, `$?`) always asks, because its paths can't be known. This includes common loops such as `for f in *; do echo "$f"; done`.

## Approval behavior

- A match shows a dialog with the file or program, the full command for bash, and the list entry that matched. Choose **Yes** or **No**.
- Writes and edits to a matching file only offer **No**.
- Without an interactive UI (print or RPC mode), matches are blocked.

## Storage

| File | Contents |
|---|---|
| `~/.pi/agent/securepi-blacklist.json` | Files and directories list (JSON array of strings) |
| `~/.pi/agent/securepi-cli.json` | CLI tools list (JSON array of strings) |

If a list file exists but can't be parsed, the defaults apply until the next `add`, `remove`, or `clear`, and the dialog warns that saving will replace the file.

## Limits

This is a **speed bump, not a security boundary**:

- Scripts run from files (`./run.sh`, `python3 script.py`) are not read, and shell aliases and functions are not known.
- Encoded payloads piped into a shell (`base64 -d | sh`) are not decoded.
- Content searches (`grep -r`, `find . -exec cat`) can read a restricted file without naming it, so they are not detected. Use the tool-level protections in a sandbox for that.
- Symlinks are not resolved: a link in an allowed folder that points into a restricted one is not detected.
- Tools other than the built-in `bash`, `read`, `write`, `edit`, `grep`, `find`, and `ls` are not checked, including MCP and other extensions' tools.
- Wildcard expansion uses Node's `fs.globSync`. On runtimes without it, wildcard tokens are only matched as literal text.
- Any extension or process running as your user can read these files directly.
- For real isolation, run Pi in a sandbox that does not contain the credentials (see Pi's `docs/containerization.md`).

## Development

Test the logic with a temporary `HOME`, so your real `~/.pi/agent` is untouched. Bundle `securepi.ts` with esbuild and drive it through a fake `ExtensionAPI` that records the `tool_call` handler and the `securepi` command.
