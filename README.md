# securepi

A [Pi](https://pi.dev) extension that asks for confirmation before the agent touches credentials.

It gates:

- **Bash commands** that run `pass`, `gpg`, `gpg2`, `gpgconf`, `pinentry*`, or reference `~/.password-store`, `~/.gnupg`, `auth.json`, `mcp-auth.json`, `trust.json`, `~/.pi/agent`, or `.env` files.
- **Tool paths** for `read`, `write`, `edit`, `grep`, `find`, and `ls` matching the same credential paths.

Writes and edits to these paths are always refused. Other matches show a Yes/No prompt. Without interactive UI (print/RPC mode), matches are blocked.

## Custom blacklist

Add your own paths with the `/securepi` command:

```
/securepi add ~/clients/acme      # asks for approval before adding
/securepi list                    # show the blacklist
```

Entries are stored as absolute paths in `~/.pi/agent/securepi-blacklist.json`. Any tool access to a listed path (or anything under it) prompts for confirmation, and writes or edits are refused, just like the built-in credential paths. The model cannot change the list: the file lives under `~/.pi/agent`, which is itself gated.

## Limits

This is a **speed bump, not a security boundary**:

- Obfuscated commands (`python -c`, `base64`, variable indirection) can bypass pattern matching.
- Extensions and processes running as your user can read these files directly.
- For real isolation, run Pi in a sandbox that does not contain the credentials (see Pi's `docs/containerization.md`).

## Install

Symlink into Pi's global extensions directory:

```bash
pi install git:github.com/kovaxs/secure-pi
```

Then run `/reload` in Pi, or restart it.

## Customize

For built-in patterns, edit the `SENSITIVE_COMMANDS` and `SENSITIVE_PATHS` arrays in `securepi.ts`. For per-machine paths, use `/securepi add` instead.
