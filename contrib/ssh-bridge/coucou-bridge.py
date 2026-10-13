#!/usr/bin/env python3
"""coucou-bridge — the PC half of the SSH bridge.

Claude Code runs on a server you reach over SSH; Coucou runs on this PC. The
server half (coucou-remote) sends every hook event through an SSH tunnel to this
program, which feeds it to the real `coucou-hook` that Coucou installed here —
so the island, the Allow / Deny buttons and the answers to Claude's questions
behave exactly as for a local session. See README.md.

    python coucou-bridge.py                        listen only (you run ssh yourself)
    python coucou-bridge.py --ssh me@server \\
        --remote-socket /home/me/.coucou-remote/bridge.sock
                                                   listen AND keep the tunnel up

Nothing here decides anything: whatever coucou-hook prints (an Allow the human
clicked, or nothing) is what goes back. Requests need the shared secret, and the
listener only ever binds 127.0.0.1.

Python 3.8+, standard library only. Windows 10/11 and Linux.
"""

import argparse
import hmac
import json
import os
import re
import secrets
import shlex
import socket
import socketserver
import subprocess
import sys
import threading
import time

PROTOCOL = 1
DEFAULT_PORT = 47900
EVENT_RE = re.compile(r"^[A-Za-z]{1,40}$")
MAX_REQUEST = 8 * 1024 * 1024
READ_TIMEOUT = 5.0          # to receive the request line
QUICK_HOOK_TIMEOUT = 10.0   # coucou-hook for an event nobody waits on
DECISION_HOOK_TIMEOUT = 113.0  # coucou-hook itself gives up on a human after 110 s
MAX_CONNECTIONS = 32


# ── Where Coucou keeps things ─────────────────────────────────────────────────

def default_hook_exe():
    """The relay the Coucou app copies next to itself at every launch."""
    if os.name == "nt":
        return os.path.join(os.environ.get("LOCALAPPDATA", ""), "Coucou", "bin", "coucou-hook.exe")
    return os.path.join(os.path.expanduser("~"), ".local", "share", "coucou", "bin", "coucou-hook")


def default_token_file():
    if os.name == "nt":
        return os.path.join(os.environ.get("LOCALAPPDATA", ""), "Coucou", "bridge-token")
    return os.path.join(os.path.expanduser("~"), ".local", "share", "coucou", "bridge-token")


def log(message):
    # Event names and hosts only — never a command, a path or a prompt.
    print("{} {}".format(time.strftime("%H:%M:%S"), message), file=sys.stderr, flush=True)


# ── Token ─────────────────────────────────────────────────────────────────────

def load_or_create_token(path):
    """(token, created). The secret is created on first run, readable by us only."""
    try:
        with open(path) as f:
            token = f.read().strip()
        if token:
            return token, False
    except FileNotFoundError:
        pass
    token = secrets.token_urlsafe(24)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token + "\n")
    return token, True


# ── The listener ──────────────────────────────────────────────────────────────

def read_request_line(conn):
    buf = bytearray()
    while True:
        i = buf.find(b"\n")
        if i >= 0:
            return bytes(buf[:i])
        try:
            chunk = conn.recv(65536)
        except OSError:
            return None
        if not chunk:
            return bytes(buf) if buf else None
        buf.extend(chunk)
        if len(buf) > MAX_REQUEST:
            return None


def send_line(conn, obj):
    conn.sendall(json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\n")


class Bridge:
    def __init__(self, hook_exe, token):
        self.hook_exe = hook_exe
        self.token = token  # "" means no authentication (--no-auth)
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def run_hook(self, event, payload, waits_for_human):
        """What coucou-hook prints for this event ("" when it prints nothing)."""
        cmd = [self.hook_exe] + ([event] if event else [])
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            proc = subprocess.Popen(
                cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=flags
            )
        except OSError as err:
            log("cannot run {}: {}".format(self.hook_exe, err))
            return ""
        timeout = DECISION_HOOK_TIMEOUT if waits_for_human else QUICK_HOOK_TIMEOUT
        try:
            out, _ = proc.communicate(json.dumps(payload).encode("utf-8"), timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            return ""
        return out.decode("utf-8", "replace").strip()

    def handle(self, conn):
        conn.settimeout(READ_TIMEOUT)
        line = read_request_line(conn)
        if line is None:
            return
        try:
            req = json.loads(line)
        except ValueError:
            return
        if not isinstance(req, dict) or req.get("v") != PROTOCOL:
            return
        if self.token:
            given = req.get("token")
            if not isinstance(given, str) or not hmac.compare_digest(given.encode("utf-8"), self.token.encode("utf-8")):
                log("refused a request with the wrong secret")
                return
        payload = req.get("payload")
        if not isinstance(payload, dict):
            return
        event = req.get("event", "")
        if not isinstance(event, str) or not EVENT_RE.match(event):
            event = ""
        name = payload.get("hook_event_name") or event
        host = req.get("host") if isinstance(req.get("host"), str) else "?"

        # "Got it", at once: the server only starts a long permission wait on a
        # connection somebody is actually reading.
        conn.settimeout(None)
        send_line(conn, {"ack": 1})
        waits = name == "PermissionRequest"
        stdout = self.run_hook(event, payload, waits)
        log("{} from {}{}".format(name or "event", host[:40], " → answered" if stdout else ""))
        send_line(conn, {"stdout": stdout})


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        bridge = self.server.bridge
        if not bridge.slots.acquire(blocking=False):
            return
        try:
            bridge.handle(self.request)
        except OSError:
            pass  # the server hook went away (Claude Code was answered in the terminal)
        finally:
            bridge.slots.release()


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(bridge, port, host="127.0.0.1"):
    server = _Server((host, port), _Handler)
    server.bridge = bridge
    return server


# ── The tunnel ────────────────────────────────────────────────────────────────

def ssh_command(args):
    cmd = [
        args.ssh_bin, "-N", "-T",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
    ]
    for opt in args.ssh_option:
        cmd += ["-o", opt]
    cmd += ["-R", "{}:127.0.0.1:{}".format(args.remote_socket, args.port), args.ssh]
    return cmd


def clear_stale_socket(args):
    """An ssh that died without a goodbye leaves its socket file behind, and the
    next `-R` then fails to bind. Removing it is safe: nothing can be using it."""
    cmd = [args.ssh_bin]
    for opt in args.ssh_option:
        cmd += ["-o", opt]
    cmd += [args.ssh, "rm -f -- " + shlex.quote(args.remote_socket)]
    try:
        subprocess.run(cmd, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        pass


def keep_tunnel_up(args, stop):
    backoff = 2
    while not stop.is_set():
        started = time.monotonic()
        log("opening the tunnel to {}".format(args.ssh))
        try:
            proc = subprocess.Popen(ssh_command(args))
        except OSError as err:
            log("cannot run {}: {}".format(args.ssh_bin, err))
            return 1
        while proc.poll() is None and not stop.is_set():
            time.sleep(0.5)
        if stop.is_set():
            proc.terminate()
            return 0
        ran = time.monotonic() - started
        log("the tunnel closed after {:.0f} s".format(ran))
        if ran < 10:
            # Failed straight away: most likely a stale socket file on the server.
            clear_stale_socket(args)
        backoff = 2 if ran > 60 else min(backoff * 2, 60)
        stop.wait(backoff)
    return 0


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args(argv=None):
    ap = argparse.ArgumentParser(prog="coucou-bridge", description=__doc__.split("\n\n")[0])
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help="local port to listen on (default %(default)s)")
    ap.add_argument("--hook-exe", help="path of coucou-hook (default: where the Coucou app puts it)")
    ap.add_argument("--token-file", help="where the shared secret lives (default: next to Coucou's data)")
    ap.add_argument("--no-auth", action="store_true", help="accept requests without the shared secret (not recommended)")
    ap.add_argument("--ssh", metavar="USER@HOST", help="also open and keep up the tunnel to this server")
    ap.add_argument("--remote-socket", help="with --ssh: the server's ~/.coucou-remote/bridge.sock, as an absolute path")
    ap.add_argument("--ssh-bin", default="ssh", help="the ssh client (default: ssh)")
    ap.add_argument("--ssh-option", action="append", default=[], metavar="OPT",
                    help="extra ssh -o option, repeatable (e.g. --ssh-option IdentityFile=C:/keys/home)")
    args = ap.parse_args(argv)
    if args.ssh and not args.remote_socket:
        ap.error("--ssh needs --remote-socket (run `coucou-remote status` on the server for the path)")
    if args.remote_socket and not args.remote_socket.startswith("/"):
        ap.error("--remote-socket must be an absolute path on the server")
    return args


def main(argv=None):
    args = parse_args(argv)
    hook_exe = args.hook_exe or default_hook_exe()
    if not os.path.isfile(hook_exe):
        print(
            "coucou-hook not found at {}.\n"
            "Install and launch Coucou once (it copies the relay there at every launch), "
            "or point --hook-exe at it.".format(hook_exe),
            file=sys.stderr,
        )
        return 2

    token = ""
    if not args.no_auth:
        token_file = args.token_file or default_token_file()
        token, created = load_or_create_token(token_file)
        if created:
            log("created a shared secret in {}".format(token_file))
            print("\nOn the server, run this once:\n  echo {} | ~/.coucou-remote/coucou-remote set-token\n".format(token))
    else:
        log("WARNING: --no-auth — any program on this PC can drive the island")

    try:
        server = make_server(Bridge(hook_exe, token), args.port)
    except OSError as err:
        print("cannot listen on 127.0.0.1:{}: {}".format(args.port, err), file=sys.stderr)
        return 2
    log("listening on 127.0.0.1:{} — relaying to {}".format(server.server_address[1], hook_exe))

    stop = threading.Event()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        if args.ssh:
            return keep_tunnel_up(args, stop)
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        stop.set()
        return 0
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())
