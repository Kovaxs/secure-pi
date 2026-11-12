# securepi

A [Pi](https://pi.dev) extension that asks for confirmation before the agent touches credentials.

It gates:

- **Bash commands** that run `pass`, `gpg`, `gpg2`, `gpgconf`, `pinentry*`, or reference `~/.password-store`, `~/.gnupg`, `auth.json`, `mcp-auth.json`, `trust.json`, `~/.pi/agent`, or `.env` files.
- **Tool paths** for `read`, `write`, `edit`, `grep`, `find`, and `ls` matching the same credential paths.

Writes and edits to these paths are always refused. Other matches show a Yes/No prompt. Without interactive UI (print/RPC mode), matches are blocked.

## Limits

This is a **speed bump, not a security boundary**:

- Obfuscated commands (`python -c`, `base64`, variable indirection) can bypass pattern matching.
- Extensions and processes running as your user can read these files directly.
- For real isolation, run Pi in a sandbox that does not contain the credentials (see Pi's `docs/containerization.md`).

## Install

Symlink into Pi's global extensions directory:

```bash
ln -s ~/workspace/securepi/securepi.ts ~/.pi/agent/extensions/securepi.ts
```

Then run `/reload` in Pi, or restart it.

## Customize

Edit the `SENSITIVE_COMMANDS` and `SENSITIVE_PATHS` arrays in `securepi.ts`.
