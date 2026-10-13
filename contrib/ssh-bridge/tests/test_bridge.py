"""Tests for the SSH bridge (coucou-remote + coucou-bridge.py).

    python3 -m unittest discover -s contrib/ssh-bridge/tests -v

Three layers:
  * pure logic: settings.json merging, request building, validation;
  * the PC agent against a stand-in for coucou-hook;
  * the whole chain (remote hook → "tunnel" → agent → coucou-hook → "Coucou app"),
    with the REAL coucou-hook when COUCOU_HOOK_BIN points at a Linux build of
    windows/hook (`cargo build --release` there), and a stand-in app that speaks
    the relay protocol of windows/src-tauri/src/pipe.rs.

The tunnel is simulated by a Unix-socket → TCP relay, which is all that
`ssh -R /path/bridge.sock:127.0.0.1:PORT` is from the programs' point of view.
Unix only (the whole chain needs Unix sockets).
"""

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import pathlib
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
REMOTE_SCRIPT = ROOT / "coucou-remote"
BRIDGE_SCRIPT = ROOT / "coucou-bridge.py"
REAL_HOOK = os.environ.get("COUCOU_HOOK_BIN", "")
TOKEN = "test-secret-0123456789abcdef"


sys.dont_write_bytecode = True  # loading the two scripts must not leave __pycache__ files in the checkout


def load(path, name):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


remote = load(REMOTE_SCRIPT, "coucou_remote")
bridge = load(BRIDGE_SCRIPT, "coucou_bridge")
bridge.log = lambda message: None  # the agent's log lines would only clutter the test output

ALLOW_JSON = '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}'
DENY_JSON = '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"Denied from Coucou"}}}'


def short_tmpdir():
    """Unix socket paths are limited to ~100 bytes: keep the directory short."""
    d = tempfile.mkdtemp(prefix="cb-")
    if len(d) > 40:
        shutil.rmtree(d, ignore_errors=True)
        d = tempfile.mkdtemp(prefix="cb-", dir="/tmp")
    return d


def permission(command, cwd="/srv/app", tool="Bash"):
    return {
        "hook_event_name": "PermissionRequest",
        "session_id": "s-1",
        "cwd": cwd,
        "tool_name": tool,
        "tool_input": {"command": command},
    }


# ── Pure logic ────────────────────────────────────────────────────────────────

class SettingsTests(unittest.TestCase):
    SCRIPT = "/home/me/.coucou-remote/coucou-remote"

    def test_every_event_gets_one_entry_with_its_timeout(self):
        out = remote.merged({}, self.SCRIPT)
        self.assertEqual(set(out["hooks"]), {e for e, _ in remote.HOOK_EVENTS})
        for event, timeout in remote.HOOK_EVENTS:
            (entry,) = out["hooks"][event]
            (hook,) = entry["hooks"]
            self.assertEqual(hook["type"], "command")
            self.assertEqual(hook["timeout"], timeout)
            self.assertEqual(hook["command"], "{} hook {}".format(self.SCRIPT, event))
        self.assertEqual(dict(remote.HOOK_EVENTS)["PermissionRequest"], 120)

    def test_same_events_as_the_app(self):
        """The list must not drift from what the Coucou app installs."""
        source = (ROOT.parent.parent / "windows" / "src-tauri" / "src" / "hooks.rs").read_text()
        block = source.split("pub const HOOK_EVENTS", 1)[1].split("];", 1)[0]
        import re
        app = re.findall(r'\("(\w+)", (\d+)\)', block)
        self.assertEqual([(e, int(t)) for e, t in app], remote.HOOK_EVENTS)

    def test_other_settings_and_other_hooks_are_untouched(self):
        mine = {"hooks": [{"type": "command", "command": "/usr/bin/audit"}]}
        existing = {
            "model": "opus",
            "permissions": {"allow": ["Bash(ls)"]},
            "hooks": {"PreToolUse": [mine], "Custom": [{"x": 1}]},
        }
        out = remote.merged(existing, self.SCRIPT)
        self.assertEqual(out["model"], "opus")
        self.assertEqual(out["permissions"], {"allow": ["Bash(ls)"]})
        self.assertEqual(out["hooks"]["Custom"], [{"x": 1}])
        self.assertEqual(out["hooks"]["PreToolUse"][0], mine)
        self.assertEqual(len(out["hooks"]["PreToolUse"]), 2)
        self.assertEqual(existing["hooks"]["PreToolUse"], [mine], "the input is not modified")

    def test_installing_twice_changes_nothing(self):
        once = remote.merged({"a": 1}, self.SCRIPT)
        self.assertEqual(remote.merged(once, self.SCRIPT), once)

    def test_the_local_coucou_apps_own_hooks_are_not_ours(self):
        app_entry = {"hooks": [{"type": "command", "command": "'/home/me/.local/share/coucou/bin/coucou-hook' Stop"}]}
        self.assertFalse(remote.entry_is_ours(app_entry))
        out = remote.merged({"hooks": {"Stop": [app_entry]}}, self.SCRIPT)
        self.assertIn(app_entry, out["hooks"]["Stop"])
        back = remote.without_ours(out)
        self.assertEqual(back["hooks"], {"Stop": [app_entry]})

    def test_uninstall_removes_ours_and_nothing_else(self):
        mine = {"hooks": [{"type": "command", "command": "/usr/bin/audit"}]}
        existing = {"model": "opus", "hooks": {"PreToolUse": [mine]}}
        self.assertEqual(remote.without_ours(remote.merged(existing, self.SCRIPT)), existing)
        # Nothing but our hooks: the key goes away entirely.
        self.assertEqual(remote.without_ours(remote.merged({"model": "x"}, self.SCRIPT)), {"model": "x"})
        self.assertEqual(remote.without_ours({}), {})

    def test_unexpected_shapes_are_refused_not_replaced(self):
        for bad in ({"hooks": []}, {"hooks": "x"}, {"hooks": {"Stop": {"a": 1}}}):
            with self.assertRaises(remote.SettingsError):
                remote.merged(bad, self.SCRIPT)
        with self.assertRaises(remote.SettingsError):
            remote.without_ours({"hooks": 3})

    def test_a_path_with_spaces_is_one_shell_word(self):
        command = remote.hook_command("/home/a b/it's/coucou-remote", "Stop")
        import shlex
        self.assertEqual(shlex.split(command), ["/home/a b/it's/coucou-remote", "hook", "Stop"])


class RequestTests(unittest.TestCase):
    def test_pointless_fields_are_dropped_and_the_event_comes_from_the_payload(self):
        payload = {"hook_event_name": "PostToolUse", "tool_response": "x" * 10, "tool_output": "y",
                   "transcript_path": "/t", "tool_name": "Read", "cwd": "/p"}
        data, event = remote.build_request(payload, "Stop", TOKEN, "box")
        self.assertEqual(event, "PostToolUse")
        self.assertTrue(data.endswith(b"\n") and data.count(b"\n") == 1, "exactly one line")
        req = json.loads(data)
        self.assertEqual(req["v"], 1)
        self.assertEqual(req["host"], "box")
        self.assertEqual(req["token"], TOKEN)
        self.assertEqual(sorted(req["payload"]), ["cwd", "hook_event_name", "tool_name"])
        self.assertIn("tool_response", payload, "the caller's dict is not modified")

    def test_the_event_argument_is_the_fallback_and_must_look_like_an_event(self):
        _data, event = remote.build_request({"tool_name": "x"}, "Stop", "", "h")
        self.assertEqual(event, "Stop")
        for bad in ("Stop; rm -rf /", "", "A" * 41, "../x", "St op"):
            _data, event = remote.build_request({}, bad, "", "h")
            self.assertEqual(event, "", bad)

    def test_an_enormous_event_is_not_sent(self):
        self.assertIsNone(remote.build_request({"hook_event_name": "Stop", "x": "z" * (5 * 1024 * 1024)}, "", "", "h"))

    def test_token_shape(self):
        self.assertTrue(remote.TOKEN_RE.match(TOKEN))
        for bad in ("short", "has space 0123456789abc", "x" * 200, ""):
            self.assertFalse(remote.TOKEN_RE.match(bad), bad)


# ── The PC agent ──────────────────────────────────────────────────────────────

FAKE_HOOK = """#!{python}
import json, os, sys, time
payload = json.loads(sys.stdin.read())
log = os.environ.get("FAKE_HOOK_LOG")
if log:
    with open(log, "a") as f:
        f.write(json.dumps({{"argv": sys.argv[1:], "keys": sorted(payload)}}) + "\\n")
command = str(payload.get("tool_input", {{}}).get("command", ""))
if payload.get("hook_event_name") == "PermissionRequest":
    if "SLOW" in command:
        time.sleep(1.0)
    if "ALLOW" in command:
        print('{{"decision":"allow"}}')
    elif "DENY" in command:
        print('{{"decision":"deny"}}')
"""


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.tmp = short_tmpdir()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def fake_hook(self):
        path = os.path.join(self.tmp, "fake-hook")
        with open(path, "w") as f:
            f.write(FAKE_HOOK.format(python=sys.executable))
        os.chmod(path, 0o755)
        return path

    def start_agent(self, hook_exe, token=TOKEN):
        server = bridge.make_server(bridge.Bridge(hook_exe, token), 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop():
            server.shutdown()
            server.server_close()

        self.addCleanup(stop)
        return server.server_address[1]


def exchange(port, request, timeout=10):
    """Send one request line; the lines that come back, with the time each took."""
    sock = socket.create_connection(("127.0.0.1", port), timeout)
    started = time.monotonic()
    sock.sendall((request if isinstance(request, bytes) else json.dumps(request).encode()) + b"\n")
    lines, times = [], []
    with sock.makefile("rb") as f:
        for line in f:
            lines.append(json.loads(line))
            times.append(time.monotonic() - started)
    sock.close()
    return lines, times


def request(payload, event="", token=TOKEN):
    return {"v": 1, "token": token, "host": "box", "event": event, "payload": payload}


class AgentTests(TempDirCase):
    def setUp(self):
        super().setUp()
        self.log = os.path.join(self.tmp, "hook.log")
        os.environ["FAKE_HOOK_LOG"] = self.log
        self.addCleanup(os.environ.pop, "FAKE_HOOK_LOG", None)
        self.port = self.start_agent(self.fake_hook())

    def hook_calls(self):
        try:
            with open(self.log) as f:
                return [json.loads(line) for line in f]
        except FileNotFoundError:
            return []

    def test_the_answer_is_what_coucou_hook_printed(self):
        lines, _ = exchange(self.port, request(permission("ALLOW"), "PermissionRequest"))
        self.assertEqual(lines, [{"ack": 1}, {"stdout": '{"decision":"allow"}'}])
        lines, _ = exchange(self.port, request(permission("DENY"), "PermissionRequest"))
        self.assertEqual(lines[1], {"stdout": '{"decision":"deny"}'})

    def test_no_decision_is_an_empty_answer_never_an_invented_one(self):
        lines, _ = exchange(self.port, request(permission("neither"), "PermissionRequest"))
        self.assertEqual(lines, [{"ack": 1}, {"stdout": ""}])

    def test_ack_comes_before_the_long_wait(self):
        lines, times = exchange(self.port, request(permission("SLOW ALLOW"), "PermissionRequest"))
        self.assertEqual(lines[0], {"ack": 1})
        self.assertLess(times[0], 0.5, "ack must not wait for coucou-hook")
        self.assertGreaterEqual(times[1], 0.9)
        self.assertEqual(lines[1]["stdout"], '{"decision":"allow"}')

    def test_a_wrong_or_missing_secret_gets_nothing_and_runs_nothing(self):
        for token in ("nope", "", None, 123):
            lines, _ = exchange(self.port, request(permission("ALLOW"), "PermissionRequest", token=token))
            self.assertEqual(lines, [], repr(token))
        body = request(permission("ALLOW"))
        del body["token"]
        self.assertEqual(exchange(self.port, body)[0], [])
        self.assertEqual(self.hook_calls(), [], "coucou-hook was never started")

    def test_garbage_is_ignored(self):
        for junk in (b"not json", b"[1,2]", b'{"v":2}', b'{"v":1,"token":"%s","payload":[]}' % TOKEN.encode(), b""):
            self.assertEqual(exchange(self.port, junk)[0], [], junk)
        self.assertEqual(self.hook_calls(), [])

    def test_the_event_is_passed_as_an_argument_only_if_it_looks_like_one(self):
        exchange(self.port, request(permission("x"), "PermissionRequest"))
        exchange(self.port, request(permission("x"), "Stop; calc.exe"))
        exchange(self.port, request(permission("x"), "$(reboot)"))
        argvs = [c["argv"] for c in self.hook_calls()]
        self.assertEqual(argvs, [["PermissionRequest"], [], []])

    def test_the_payload_reaches_coucou_hook_whole(self):
        payload = permission("x")
        payload["extra"] = {"nested": [1, 2]}
        exchange(self.port, request(payload, "Stop"))
        (call,) = self.hook_calls()
        self.assertEqual(call["keys"], sorted(payload))

    def test_a_missing_coucou_hook_is_an_empty_answer(self):
        port = self.start_agent(os.path.join(self.tmp, "does-not-exist"))
        lines, _ = exchange(port, request(permission("ALLOW"), "PermissionRequest"))
        self.assertEqual(lines, [{"ack": 1}, {"stdout": ""}])

    def test_no_auth_mode_accepts_requests_without_a_secret(self):
        port = self.start_agent(self.fake_hook(), token="")
        body = request(permission("ALLOW"), "PermissionRequest")
        del body["token"]
        self.assertEqual(exchange(port, body)[0][1], {"stdout": '{"decision":"allow"}'})

    def test_the_listener_is_loopback_only(self):
        server = bridge.make_server(bridge.Bridge(self.fake_hook(), TOKEN), 0)
        self.addCleanup(server.server_close)
        self.assertEqual(server.server_address[0], "127.0.0.1")

    def test_the_token_file_is_created_once_and_private(self):
        path = os.path.join(self.tmp, "sub", "bridge-token")
        token, created = bridge.load_or_create_token(path)
        self.assertTrue(created)
        self.assertGreaterEqual(len(token), 24)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        again, created = bridge.load_or_create_token(path)
        self.assertEqual((again, created), (token, False))

    def test_ssh_command_and_arguments(self):
        args = bridge.parse_args(["--ssh", "me@box", "--remote-socket", "/home/me/.coucou-remote/bridge.sock",
                                  "--port", "47901", "--ssh-option", "IdentityFile=/k"])
        cmd = bridge.ssh_command(args)
        self.assertEqual(cmd[0], "ssh")
        self.assertIn("ExitOnForwardFailure=yes", cmd)
        self.assertIn("IdentityFile=/k", cmd)
        self.assertEqual(cmd[cmd.index("-R") + 1], "/home/me/.coucou-remote/bridge.sock:127.0.0.1:47901")
        self.assertEqual(cmd[-1], "me@box")
        with contextlib.redirect_stderr(io.StringIO()):  # argparse prints its usage on error
            with self.assertRaises(SystemExit):
                bridge.parse_args(["--ssh", "me@box"])
            with self.assertRaises(SystemExit):
                bridge.parse_args(["--ssh", "me@box", "--remote-socket", "relative/path"])


# ── The whole chain ───────────────────────────────────────────────────────────

class Tunnel(threading.Thread):
    """What `ssh -R <unix socket>:127.0.0.1:<port>` amounts to: a Unix socket on
    the server whose connections come out at a TCP port on the PC.

    mode "forward": a faithful relay (half-close included).
    mode "blackhole": accepts, then neither reads nor answers: a PC that went to
    sleep behind a tunnel that has not noticed yet.
    """

    def __init__(self, path, port, mode="forward"):
        super().__init__(daemon=True)
        self.port, self.mode, self.connections = port, mode, 0
        self.held = []
        self.stopping = False
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(path)
        self.listener.listen(16)
        self.listener.settimeout(0.1)

    def run(self):
        while not self.stopping:
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.connections += 1
            if self.mode == "blackhole":
                self.held.append(conn)
                continue
            try:
                up = socket.create_connection(("127.0.0.1", self.port), 1)
            except OSError:
                conn.close()  # the agent is not there: sshd closes the connection
                continue
            open_directions = [2, threading.Lock()]
            threading.Thread(target=self.pump, args=(conn, up, open_directions), daemon=True).start()
            threading.Thread(target=self.pump, args=(up, conn, open_directions), daemon=True).start()

    @staticmethod
    def pump(src, dst, open_directions):
        """One direction. A finished direction half-closes (as an ssh channel does);
        when both are finished, both sockets are closed."""
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                dst.sendall(chunk)
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        with open_directions[1]:
            open_directions[0] -= 1
            last = open_directions[0] == 0
        if last:
            src.close()
            dst.close()

    def stop(self):
        self.stopping = True
        self.listener.close()
        for conn in self.held:
            conn.close()


class FakeApp(threading.Thread):
    """Stands in for the Coucou app's relay server (windows/src-tauri/src/pipe.rs):
    one JSON line in; for a PermissionRequest, an answer line — or silence."""

    def __init__(self, path, answer=None):
        super().__init__(daemon=True)
        self.answer = answer or (lambda payload: None)
        self.received = []
        self.stopping = False
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(path)
        self.listener.listen(16)
        self.listener.settimeout(0.1)

    def run(self):
        while not self.stopping:
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def serve(self, conn):
        buf = b""
        try:
            while b"\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            payload = json.loads(buf.split(b"\n", 1)[0])
            self.received.append(payload)
            if payload.get("hook_event_name") == "PermissionRequest":
                reply = self.answer(payload)
                if reply:
                    conn.sendall(reply.encode() + b"\n")
        except (OSError, ValueError):
            pass
        finally:
            conn.close()

    def stop(self):
        self.stopping = True
        self.listener.close()


@unittest.skipUnless(os.name == "posix" and sys.platform.startswith("linux"), "needs Linux (SO_PEERCRED, Unix sockets)")
class ChainCase(TempDirCase):
    def setUp(self):
        super().setUp()
        self.home = os.path.join(self.tmp, "h")
        self.state = os.path.join(self.home, ".coucou-remote")
        os.makedirs(self.state, mode=0o700)
        os.chmod(self.state, 0o700)
        self.sock = os.path.join(self.state, "bridge.sock")

    def tunnel(self, port, mode="forward"):
        t = Tunnel(self.sock, port, mode)
        t.start()
        self.addCleanup(t.stop)
        return t

    def remote_hook(self, payload, event="", token=TOKEN, raw=None, timeout=30):
        env = dict(os.environ, HOME=self.home, COUCOU_REMOTE_DIR=self.state)
        env.pop("COUCOU_REMOTE_TOKEN", None)
        if token:
            env["COUCOU_REMOTE_TOKEN"] = token
        data = raw if raw is not None else json.dumps(payload).encode()
        started = time.monotonic()
        done = subprocess.run([sys.executable, str(REMOTE_SCRIPT), "hook", event], input=data,
                              capture_output=True, env=env, timeout=timeout)
        return done.returncode, done.stdout.decode().strip(), time.monotonic() - started


class RemoteHookWithFakeHookTests(ChainCase):
    def setUp(self):
        super().setUp()
        self.port = self.start_agent(self.fake_hook())
        self.tun = self.tunnel(self.port)

    def test_a_permission_request_round_trips(self):
        code, out, _ = self.remote_hook(permission("ALLOW"), "PermissionRequest")
        self.assertEqual((code, out), (0, '{"decision":"allow"}'))
        code, out, _ = self.remote_hook(permission("DENY"), "PermissionRequest")
        self.assertEqual((code, out), (0, '{"decision":"deny"}'))

    def test_without_a_decision_nothing_is_printed(self):
        code, out, _ = self.remote_hook(permission("nothing"), "PermissionRequest")
        self.assertEqual((code, out), (0, ""))

    def test_an_ordinary_event_is_quick_and_silent(self):
        code, out, took = self.remote_hook({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": "/p"}, "PreToolUse")
        self.assertEqual((code, out), (0, ""))
        self.assertLess(took, 1.5)

    def test_a_wrong_secret_on_the_server_is_silence(self):
        code, out, _ = self.remote_hook(permission("ALLOW"), "PermissionRequest", token="wrong-secret-0123456789")
        self.assertEqual((code, out), (0, ""))

    def test_no_secret_on_the_server_is_silence(self):
        code, out, _ = self.remote_hook(permission("ALLOW"), "PermissionRequest", token="")
        self.assertEqual((code, out), (0, ""))

    def test_whatever_arrives_the_exit_code_is_zero(self):
        for raw in (b"", b"not json", b"[1]", b"\xff\xfe", b"\xef\xbb\xbf" + json.dumps(permission("ALLOW")).encode()):
            code, out, _ = self.remote_hook(None, "Stop", raw=raw)
            self.assertEqual(code, 0, raw)
        # A BOM in front is not a reason to drop the event.
        self.assertEqual(self.remote_hook(None, "PermissionRequest", raw=b"\xef\xbb\xbf" + json.dumps(permission("ALLOW")).encode())[1],
                         '{"decision":"allow"}')

    def test_odd_command_lines_never_fail_a_hook(self):
        env = dict(os.environ, HOME=self.home, COUCOU_REMOTE_DIR=self.state)
        for argv in (["hook"], ["hook", "A" * 500, "--bogus", "extra"], ["hook", "--help"]):
            done = subprocess.run([sys.executable, str(REMOTE_SCRIPT)] + argv, input=b"{}", capture_output=True, env=env, timeout=20)
            self.assertEqual(done.returncode, 0, argv)

    def test_a_state_directory_open_to_others_is_not_used(self):
        os.chmod(self.state, 0o755)
        code, out, _ = self.remote_hook(permission("ALLOW"), "PermissionRequest")
        self.assertEqual((code, out), (0, ""))
        self.assertEqual(self.tun.connections, 0, "nothing was even sent")


class RemoteHookFailureTests(ChainCase):
    def test_no_tunnel_at_all_is_instant_silence(self):
        code, out, took = self.remote_hook(permission("ALLOW"), "PermissionRequest")
        self.assertEqual((code, out), (0, ""))
        self.assertLess(took, 1.0)

    def test_tunnel_up_but_agent_not_running_is_quick_silence(self):
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        self.tunnel(port)
        code, out, took = self.remote_hook(permission("ALLOW"), "PermissionRequest")
        self.assertEqual((code, out), (0, ""))
        self.assertLess(took, 1.5)
        self.assertFalse(os.path.exists(os.path.join(self.state, "down")), "a closed door is not a silent PC")

    def test_a_sleeping_pc_costs_one_short_wait_then_nothing(self):
        tun = self.tunnel(0, mode="blackhole")
        code, out, took = self.remote_hook(permission("ALLOW"), "PermissionRequest")
        self.assertEqual((code, out), (0, ""))
        self.assertLess(took, 4.0, "the permission wait (110 s) must never start on a dead connection")
        self.assertGreaterEqual(took, remote.ACK_TIMEOUT - 0.2)
        self.assertEqual(tun.connections, 1)
        self.assertTrue(os.path.exists(os.path.join(self.state, "down")))

        # Next events skip the tunnel altogether while the breaker is open.
        for event in ("PreToolUse", "PermissionRequest"):
            code, out, took = self.remote_hook(permission("ALLOW"), event)
            self.assertEqual((code, out), (0, ""))
            self.assertLess(took, 0.6)
        self.assertEqual(tun.connections, 1)

    def test_the_breaker_closes_again_by_itself(self):
        self.tunnel(0, mode="blackhole")
        self.remote_hook(permission("ALLOW"), "PermissionRequest")
        down = os.path.join(self.state, "down")
        old = time.time() - remote.BREAKER_SECONDS - 5
        os.utime(down, (old, old))
        t0 = time.monotonic()
        self.remote_hook(permission("ALLOW"), "PermissionRequest")
        self.assertGreaterEqual(time.monotonic() - t0, remote.ACK_TIMEOUT - 0.2, "it tried again")

    def test_a_working_connection_clears_the_breaker(self):
        down = os.path.join(self.state, "down")
        with open(down, "w") as f:
            f.write("1")
        old = time.time() - remote.BREAKER_SECONDS - 5
        os.utime(down, (old, old))
        self.tunnel(self.start_agent(self.fake_hook()))
        self.remote_hook(permission("ALLOW"), "PermissionRequest")
        self.assertFalse(os.path.exists(down))


@unittest.skipUnless(REAL_HOOK and os.access(REAL_HOOK, os.X_OK), "set COUCOU_HOOK_BIN to a Linux build of windows/hook to run this")
class RealCoucouHookChain(ChainCase):
    """The real coucou-hook, in front of a stand-in Coucou app."""

    def setUp(self):
        super().setUp()
        run = os.path.join(self.tmp, "run")
        os.makedirs(run, mode=0o700)
        os.chmod(run, 0o700)
        old = os.environ.get("XDG_RUNTIME_DIR")
        os.environ["XDG_RUNTIME_DIR"] = run  # coucou-hook looks for the app here
        self.addCleanup(lambda: os.environ.__setitem__("XDG_RUNTIME_DIR", old) if old is not None else os.environ.pop("XDG_RUNTIME_DIR", None))
        self.app_sock = os.path.join(run, "coucou.sock")

    def chain(self, answer=None):
        app = FakeApp(self.app_sock, answer)
        app.start()
        self.addCleanup(app.stop)
        self.tunnel(self.start_agent(REAL_HOOK))
        return app

    def test_allow_comes_back_in_the_documented_shape(self):
        app = self.chain(lambda p: "allow")
        code, out, _ = self.remote_hook(permission("ls -la"), "PermissionRequest")
        self.assertEqual((code, out), (0, ALLOW_JSON))
        (seen,) = app.received
        self.assertEqual(seen["tool_name"], "Bash")
        self.assertEqual(seen["cwd"], "/srv/app", "the SERVER's directory, as Claude Code reported it")

    def test_always_is_a_plain_allow_and_deny_is_a_deny(self):
        self.chain(lambda p: "always" if "again" in p["tool_input"]["command"] else "deny")
        self.assertEqual(self.remote_hook(permission("do it again"), "PermissionRequest")[1], ALLOW_JSON)
        self.assertEqual(self.remote_hook(permission("rm x"), "PermissionRequest")[1], DENY_JSON)

    def test_an_island_that_says_nothing_leaves_the_decision_to_the_terminal(self):
        self.chain(lambda p: None)
        code, out, _ = self.remote_hook(permission("ls"), "PermissionRequest")
        self.assertEqual((code, out), (0, ""))

    def test_a_closed_coucou_app_is_silence_too(self):
        self.tunnel(self.start_agent(REAL_HOOK))  # no app listening
        code, out, took = self.remote_hook(permission("ls"), "PermissionRequest")
        self.assertEqual((code, out), (0, ""))
        self.assertLess(took, 3.0)

    def test_an_answered_question_goes_back_as_the_same_input_plus_answers(self):
        question = {"questions": [{"question": "Which one?", "options": [{"label": "A"}, {"label": "B"}]}]}
        app = self.chain(lambda p: json.dumps({"answers": {"Which one?": "B"}}))
        payload = {"hook_event_name": "PermissionRequest", "session_id": "s", "cwd": "/srv/app",
                   "tool_name": "AskUserQuestion", "tool_input": question}
        code, out, _ = self.remote_hook(payload, "PermissionRequest")
        self.assertEqual(code, 0)
        decision = json.loads(out)["hookSpecificOutput"]["decision"]
        self.assertEqual(decision["behavior"], "allow")
        self.assertEqual(decision["updatedInput"]["answers"], {"Which one?": "B"})
        self.assertEqual(decision["updatedInput"]["questions"], question["questions"])

    def test_an_answer_that_does_not_fit_the_question_is_refused(self):
        question = {"questions": [{"question": "Which one?", "options": [{"label": "A"}]}]}
        self.chain(lambda p: json.dumps({"answers": {"Which one?": "Z"}}))
        payload = {"hook_event_name": "PermissionRequest", "session_id": "s", "tool_name": "AskUserQuestion", "tool_input": question}
        self.assertEqual(self.remote_hook(payload, "PermissionRequest")[1], "")

    def test_ordinary_events_reach_the_app_without_the_heavy_fields(self):
        app = self.chain()
        payload = {"hook_event_name": "PostToolUse", "session_id": "s-2", "cwd": "/srv/app", "tool_name": "Read",
                   "tool_response": "x" * 100_000, "transcript_path": "/home/me/.claude/t.jsonl"}
        code, out, took = self.remote_hook(payload, "PostToolUse")
        self.assertEqual((code, out), (0, ""))
        self.assertLess(took, 2.0)
        deadline = time.monotonic() + 3
        while not app.received and time.monotonic() < deadline:
            time.sleep(0.05)
        (seen,) = app.received
        self.assertEqual(seen["hook_event_name"], "PostToolUse")
        self.assertEqual(seen["session_id"], "s-2")
        self.assertNotIn("tool_response", seen)
        self.assertNotIn("transcript_path", seen)

    def test_a_finished_edit_keeps_its_text_whole_for_the_live_diff(self):
        app = self.chain()
        text = "line\n" * 4000
        payload = {"hook_event_name": "PostToolUse", "session_id": "s-3", "tool_name": "Edit",
                   "tool_input": {"file_path": "/srv/app/a.ts", "old_string": text, "new_string": text + "x"}}
        self.remote_hook(payload, "PostToolUse")
        deadline = time.monotonic() + 3
        while not app.received and time.monotonic() < deadline:
            time.sleep(0.05)
        (seen,) = app.received
        self.assertEqual(len(seen["tool_input"]["old_string"]), len(text), "coucou-hook's diff rule survives the bridge")

    def test_decisions_are_never_invented_when_the_pc_is_silent(self):
        self.tunnel(0, mode="blackhole")
        self.assertEqual(self.remote_hook(permission("rm -rf /"), "PermissionRequest")[1], "")


# ── Installing the hooks ──────────────────────────────────────────────────────

class InstallTests(TempDirCase):
    def setUp(self):
        super().setUp()
        self.home = os.path.join(self.tmp, "h")
        self.state = os.path.join(self.home, ".coucou-remote")
        self.claude = os.path.join(self.home, ".claude")
        os.makedirs(self.claude)
        self.settings = os.path.join(self.claude, "settings.json")
        self.env = dict(os.environ, HOME=self.home, COUCOU_REMOTE_DIR=self.state, CLAUDE_CONFIG_DIR=self.claude)
        self.env.pop("COUCOU_REMOTE_TOKEN", None)

    def run_cli(self, *args, stdin=b""):
        return subprocess.run([sys.executable, str(REMOTE_SCRIPT)] + list(args), input=stdin, capture_output=True,
                              env=self.env, timeout=30)

    def write_settings(self, text):
        with open(self.settings, "w") as f:
            f.write(text)

    def read_settings(self):
        with open(self.settings) as f:
            return json.load(f)

    def backups(self):
        return sorted(n for n in os.listdir(self.claude) if ".bak-coucou-remote-" in n)

    ORIGINAL = {"model": "opus", "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "/usr/bin/audit"}]}]}}

    def test_install_backs_up_merges_and_uninstall_restores(self):
        self.write_settings(json.dumps(self.ORIGINAL, indent=4))
        done = self.run_cli("install", "--yes")
        self.assertEqual(done.returncode, 0, done.stderr)
        merged = self.read_settings()
        self.assertEqual(merged["model"], "opus")
        self.assertEqual(len(merged["hooks"]), 12)
        script = os.path.join(self.state, "coucou-remote")
        self.assertEqual(merged["hooks"]["PermissionRequest"][0]["hooks"][0]["command"],
                         remote.hook_command(script, "PermissionRequest"))
        # The copy is a real, executable script in a private directory.
        self.assertTrue(os.access(script, os.X_OK))
        self.assertEqual(stat.S_IMODE(os.stat(self.state).st_mode), 0o700)
        # One dated backup holding the file exactly as it was.
        (backup,) = self.backups()
        with open(os.path.join(self.claude, backup)) as f:
            self.assertEqual(json.load(f), self.ORIGINAL)

        # Installing again changes nothing and takes no new backup.
        before = self.read_settings()
        self.assertEqual(self.run_cli("install", "--yes").returncode, 0)
        self.assertEqual(self.read_settings(), before)
        self.assertEqual(len(self.backups()), 1)

        # Uninstall: back to the original settings, with its own backup.
        time.sleep(1.1)  # backups are named by the second
        self.assertEqual(self.run_cli("uninstall", "--yes").returncode, 0)
        self.assertEqual(self.read_settings(), self.ORIGINAL)
        self.assertEqual(len(self.backups()), 2)

    def test_the_installed_hook_command_actually_runs(self):
        self.write_settings("{}")
        self.run_cli("install", "--yes")
        command = self.read_settings()["hooks"]["Stop"][0]["hooks"][0]["command"]
        done = subprocess.run(command, shell=True, input=b'{"hook_event_name":"Stop"}', capture_output=True, env=self.env, timeout=20)
        self.assertEqual((done.returncode, done.stdout), (0, b""))

    def test_without_a_yes_and_without_a_terminal_nothing_is_written(self):
        self.write_settings(json.dumps(self.ORIGINAL))
        done = self.run_cli("install")
        self.assertEqual(done.returncode, 1)
        self.assertEqual(self.read_settings(), self.ORIGINAL)
        self.assertEqual(self.backups(), [])
        self.assertFalse(os.path.exists(self.state), "not even the state directory is created before the yes")

    def test_the_diff_is_shown_before_anything_is_written(self):
        self.write_settings(json.dumps(self.ORIGINAL))
        done = self.run_cli("install")
        self.assertIn(b"PermissionRequest", done.stdout)
        self.assertIn(b"+++", done.stdout)

    def test_a_settings_file_that_is_not_valid_json_is_left_alone(self):
        self.write_settings("{ not json")
        done = self.run_cli("install", "--yes")
        self.assertEqual(done.returncode, 1)
        with open(self.settings) as f:
            self.assertEqual(f.read(), "{ not json")
        self.assertEqual(self.backups(), [])

    def test_a_missing_settings_file_is_created(self):
        done = self.run_cli("install", "--yes")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(len(self.read_settings()["hooks"]), 12)
        self.assertEqual(self.backups(), [], "nothing to back up")

    def test_set_token_validates_and_keeps_the_file_private(self):
        self.assertEqual(self.run_cli("set-token", stdin=b"short\n").returncode, 1)
        self.assertEqual(self.run_cli("set-token", stdin=(TOKEN + "\n").encode()).returncode, 0)
        path = os.path.join(self.state, "token")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path) as f:
            self.assertEqual(f.read().strip(), TOKEN)

    def test_status_runs(self):
        done = self.run_cli("status")
        self.assertEqual(done.returncode, 0)
        self.assertIn(b"--remote-socket", done.stdout)


if __name__ == "__main__":
    unittest.main()
