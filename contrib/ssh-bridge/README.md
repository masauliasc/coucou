# SSH bridge — Claude Code on a server, Coucou on your PC

Run Claude Code on a Linux server you reach over SSH, and still get it in the Coucou
island on your PC: live steps, diffs, **Allow / Deny** and answers to Claude's questions,
exactly like a local session.

> This is a community add-on in `contrib/`, not an official part of Coucou. It changes nothing
> in the app: it only talks to the `coucou-hook` relay the app already installs.

```
 SERVER (Ubuntu, Claude Code)                            YOUR PC (Windows, Coucou)

 Claude Code ──hook──▶ coucou-remote ──┐
   ▲                                   │ Unix socket        ┌─ coucou-bridge.py ─▶ coucou-hook.exe ─▶ Coucou island
   │                                   ▼ ~/.coucou-remote/   │   127.0.0.1:47900     (the real relay)
   │                          sshd ═══ SSH tunnel (-R) ══════╝
   └────── allow / deny ◀──────────── (the answer travels back the same way)
```

The server never decides anything and never learns your PC's internals. It sends the hook
event; the PC runs the real `coucou-hook` on it, so approvals, questions and diffs go through
the code the app already ships and tests. What `coucou-hook` prints is what comes back.

## Setup

You need Python 3.8+ on both machines (standard library only), Coucou installed **and
launched at least once** on the PC (it copies `coucou-hook` next to itself at every launch),
and an SSH login to the server. Key-based login is strongly recommended: the tunnel
reconnects by itself, and a password prompt would block that.

**1. On the server** — put this folder there (`git clone` your fork, or `scp`), then:

```
python3 contrib/ssh-bridge/coucou-remote install
```

It shows the exact diff of `~/.claude/settings.json`, takes a dated backup and asks before
writing; your own hooks are never touched. It also keeps a copy of itself in
`~/.coucou-remote/`, and prints the command for the next step.

**2. On the PC** — from a terminal:

```
python coucou-bridge.py --ssh me@myserver --remote-socket /home/me/.coucou-remote/bridge.sock
```

`--ssh` takes anything `ssh` takes, so an alias from your `~/.ssh/config` works too. The
`--remote-socket` value is printed by the server's `install` and `status` (it is an absolute
path; `ssh` does not expand `~`). Extra ssh settings: `--ssh-option IdentityFile=C:/keys/home`
(repeatable).

On its first run it creates a shared secret and prints one line to run on the server:

**3. On the server**, once:

```
echo <the secret> | ~/.coucou-remote/coucou-remote set-token
```

**4.** Restart your Claude Code sessions on the server (they read `settings.json` at start).
`~/.coucou-remote/coucou-remote status` tells you what is in place and whether the tunnel is up.

### Keeping it running

Leave the `coucou-bridge.py` terminal open, or start it at login: a Task Scheduler entry or a
Startup shortcut running `pythonw coucou-bridge.py …` (no window). For a hidden run add
`--ssh-option BatchMode=yes` so a prompt can never hang it. The tunnel reopens by itself after
a dropped connection, and clears a stale socket file on the server when needed (no
`sshd_config` change required).

## When something is down

Claude Code is never held up. If the tunnel is down, the PC is asleep, or Coucou is closed,
the hook prints nothing and Claude Code asks for permission in the terminal as usual:

- no tunnel / agent not running → the hook returns at once;
- a tunnel that accepts but does not answer (a PC that just went to sleep) → one wait of at most
  1.5 s, then the server stays quiet for 20 s instead of paying that on every event;
- a permission request is only held for a human once the PC has said "got it".

## Security

- The agent listens on `127.0.0.1` only, and refuses any request without the shared secret
  (constant-time comparison). The secret lives in a file only you can read on each side.
- On the server, the socket sits in `~/.coucou-remote/` (mode 0700), is created by sshd for
  your own account, and `coucou-remote` checks with `SO_PEERCRED` that the process serving it
  is you before sending anything. Another account on the server gets nothing.
- The tunnel is ordinary SSH. Hook events (commands, paths, prompts) go only to your own PC.
- A decision is only ever what `coucou-hook` printed after you clicked. This code adds none.
- Keep in mind what the card is: the server tells the island what to show. A compromised
  server can make the island show anything, so treat the card as Claude Code's description
  of the request, not as proof of what will run. The same is true for a local session.

## What is not covered

- **Claude Code only.** Other agents' hooks on the server (Codex, Gemini CLI…) are not wired
  up: the request would need to carry an agent tag, and the server would need each agent's
  "no decision" reply for when the PC is unreachable (some, like Copilot CLI, fail closed
  without one).
- **No plan-usage gauge** (that is `coucou-hook --statusline` and stays local).
- **Linux servers.** The server half relies on `SO_PEERCRED`.
- **"Open terminal"** from the island will find the window running `coucou-bridge.py`, not
  your SSH session: the app only sees the process that called the relay.
- **One server per `coucou-bridge.py`.** For a second server, run a second instance with
  another `--port` and its own `--remote-socket`.

## Status

Tested on Linux with OpenSSH 9.6 (the Ubuntu 24.04 build): a real `sshd`, `ssh -R` to a Unix
socket, the real `coucou-hook` built from `windows/hook`, and a stand-in for the app's relay.
That covers Allow / Deny / questions / diffs, a dropped tunnel, a stale socket file,
another account on the server, and large events.

**Not tested on Windows yet**: the PC half is plain Python, but running the real
`coucou-hook.exe` through the Windows named pipe, and the Windows OpenSSH client as the tunnel,
have only been checked by reading the code. If something fails there, the agent's log
(stderr) says which step.

## Uninstall

```
~/.coucou-remote/coucou-remote uninstall      # removes only our hooks, with a backup
rm -r ~/.coucou-remote
```

## Tests

```
python3 -m unittest discover -s contrib/ssh-bridge/tests -v
```

Add the real relay to the full-chain tests by building it (`cd windows/hook && cargo build --release`)
and pointing `COUCOU_HOOK_BIN` at the resulting `coucou-hook` binary; without it those tests are skipped.
