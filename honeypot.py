#!/usr/bin/env python3
# Simple SSH honeypot with an interactive fake shell.
# It accepts any username/password or public key and logs what the client does.
# It never executes commands on the host.

import argparse
import json
import logging
import os
import posixpath
import re
import socket
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import paramiko

LOG = logging.getLogger("ssh-honeypot")

FAKE_HOSTNAME = "ubuntu"
FAKE_KERNEL = "Linux ubuntu 5.15.0-91-generic #101-Ubuntu SMP Tue Oct 10 12:34:56 UTC 2023 x86_64"

# Very small fake filesystem layout used by ls/cd/cat.
BASE_FS = {
    "/": [
        "bin", "boot", "dev", "etc", "home", "lib", "media", "mnt",
        "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp",
        "usr", "var",
    ],
    "/bin": ["bash", "cat", "ls", "ps", "uname", "whoami"],
    "/boot": [],
    "/dev": [],
    "/etc": ["passwd", "shadow", "hosts", "resolv.conf"],
    "/home": [],
    "/lib": [],
    "/media": [],
    "/mnt": [],
    "/opt": [],
    "/proc": [],
    "/root": [],
    "/run": [],
    "/sbin": [],
    "/srv": [],
    "/sys": [],
    "/tmp": [],
    "/usr": ["bin", "lib", "local", "sbin", "share"],
    "/usr/bin": ["bash", "cat", "ls", "ps"],
    "/usr/lib": [],
    "/usr/local": ["bin", "etc", "share"],
    "/usr/local/bin": [],
    "/usr/sbin": [],
    "/usr/share": [],
    "/var": ["log", "tmp", "lib"],
    "/var/log": ["auth.log", "syslog"],
    "/var/lib": [],
    "/var/tmp": [],
}

# Split simple command lines by ; && || |
# This is intentionally naive. It is enough for a honeypot demo.
COMMAND_SPLIT_RE = re.compile(r"\s*(?:;|&&|\|\||\|)\s*")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def to_text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def home_dir_for(user):
    return "/root" if user == "root" else f"/home/{user}"


def fake_passwd(user):
    lines = [
        "root:x:0:0:root:/root:/bin/bash",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
        "sync:x:4:65534:sync:/bin:/bin/sync",
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
        "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin",
    ]

    if user != "root":
        lines.append(
            f"{user}:x:1000:1000:{user}:{home_dir_for(user)}:/bin/bash"
        )

    return "\n".join(lines)


def get_fake_entries(path, user):
    """Return fake directory entries for a path, or None if it does not exist."""
    home = home_dir_for(user)

    if path == "/home":
        entries = ["visitor"]
        if user != "root" and user != "visitor":
            entries.insert(0, user)
        return entries

    if path == home:
        if user == "root":
            return [".bashrc", ".profile", "anaconda-ks.cfg"]
        return ["Desktop", "Documents", "Downloads", "Pictures", ".bashrc"]

    if path.startswith(home + "/"):
        return []

    if path == "/root":
        if user == "root":
            return [".bashrc", ".profile", "anaconda-ks.cfg"]
        return None

    if path in BASE_FS:
        return BASE_FS[path]

    return None


def resolve_path(target, state):
    """Resolve a user-supplied path inside the fake filesystem."""
    user = state["user"]
    cwd = state["cwd"]

    if not target:
        return cwd

    if target == "-":
        return state.get("oldpwd", cwd)

    if target.startswith("~"):
        if target == "~":
            return home_dir_for(user)

        if target.startswith("~/"):
            return posixpath.normpath(
                posixpath.join(home_dir_for(user), target[2:])
            )

        # Handle ~username or ~username/path
        rest = target[1:]
        parts = rest.split("/", 1)
        other_user = parts[0] or user
        other_home = home_dir_for(other_user)

        if len(parts) == 1:
            return posixpath.normpath(other_home)

        return posixpath.normpath(posixpath.join(other_home, parts[1]))

    if target.startswith("/"):
        return posixpath.normpath(target)

    return posixpath.normpath(posixpath.join(cwd, target))


def path_exists_for_cd(path, user):
    if path == "/root" and user != "root":
        return False

    if get_fake_entries(path, user) is not None:
        return True

    allowed_prefixes = (
        home_dir_for(user) + "/",
        "/tmp/",
        "/proc/",
        "/sys/",
        "/dev/",
        "/run/",
        "/var/",
        "/usr/",
        "/etc/",
        "/opt/",
        "/srv/",
        "/media/",
        "/mnt/",
        "/lib/",
        "/bin/",
        "/sbin/",
        "/boot/",
    )

    return path.startswith(allowed_prefixes)


def get_prompt(state):
    user = state["user"]
    cwd = state["cwd"]
    home = home_dir_for(user)

    if cwd == home:
        display = "~"
    elif cwd.startswith(home + "/"):
        display = "~" + cwd[len(home):]
    else:
        display = cwd

    prompt_char = "#" if user == "root" else "$"
    return f"{user}@{FAKE_HOSTNAME}:{display}{prompt_char} "


def send_output(channel, text, use_crlf=True):
    if not text:
        return

    if use_crlf:
        data = text.replace("\n", "\r\n")
        if not data.endswith("\r\n"):
            data += "\r\n"
    else:
        data = text
        if not data.endswith("\n"):
            data += "\n"

    channel.sendall(data.encode("utf-8", "replace"))


def process_command(line, state):
    """Process a full command line and return (output, close_shell)."""
    line = line.strip()
    if not line:
        return "", False

    outputs = []
    close_shell = False

    for part in COMMAND_SPLIT_RE.split(line):
        part = part.strip()
        if not part:
            continue

        output, should_close = process_single_command(part, state)
        if output:
            outputs.append(output)

        if should_close:
            close_shell = True
            break

    return "\n".join(outputs), close_shell


def process_single_command(command, state):
    """Process one command and return (output, close_shell)."""
    command = command.strip()
    if not command:
        return "", False

    tokens = command.split()
    if not tokens:
        return "", False

    name = tokens[0]
    args = tokens[1:]
    user = state["user"]
    home = home_dir_for(user)

    if name in ("exit", "logout"):
        return "logout", True

    if name == "help":
        return (
            "Available fake commands:\n"
            "  ls, pwd, whoami, id, uname, cat, ps, date, uptime,\n"
            "  echo, env, hostname, history, clear, cd, exit"
        ), False

    if name == "cd":
        target = args[0] if args else "~"

        if target == "-":
            new_path = state.get("oldpwd", state["cwd"])
        else:
            new_path = resolve_path(target, state)

        if new_path.startswith("/root") and user != "root":
            return f"bash: cd: {target}: Permission denied", False

        if not path_exists_for_cd(new_path, user):
            return f"bash: cd: {target}: No such file or directory", False

        state["oldpwd"] = state["cwd"]
        state["cwd"] = new_path
        return "", False

    if name == "pwd":
        return state["cwd"], False

    if name == "whoami":
        return user, False

    if name == "hostname":
        return FAKE_HOSTNAME, False

    if name == "id":
        if user == "root":
            return "uid=0(root) gid=0(root) groups=0(root)", False
        return f"uid=1000({user}) gid=1000({user}) groups=1000({user}),27(sudo)", False

    if name == "uname":
        if "-a" in args:
            return FAKE_KERNEL, False
        if "-r" in args:
            return "5.15.0-91-generic", False
        if "-n" in args:
            return FAKE_HOSTNAME, False
        return "Linux", False

    if name == "ls":
        paths = [a for a in args if not a.startswith("-")]
        target = paths[0] if paths else None
        path = resolve_path(target, state) if target else state["cwd"]

        if path.startswith("/root") and user != "root":
            return "ls: cannot open directory '/root': Permission denied", False

        entries = get_fake_entries(path, user)
        if entries is None:
            shown = target if target else path
            return f"ls: cannot access '{shown}': No such file or directory", False

        return "  ".join(entries), False

    if name in ("cat", "head", "tail", "less", "more"):
        files = [a for a in args if not a.startswith("-")]
        if not files:
            return f"{name}: missing file operand", False

        target = files[0]
        path = resolve_path(target, state)

        if path.startswith("/root") and user != "root":
            return f"{name}: {target}: Permission denied", False

        if path == "/etc/passwd":
            return fake_passwd(user), False

        if path == "/etc/shadow":
            return f"{name}: {target}: Permission denied", False

        if path == "/etc/hosts":
            return "127.0.0.1 localhost\n127.0.1.1 ubuntu", False

        if path == "/etc/resolv.conf":
            return "nameserver 1.1.1.1\nnameserver 8.8.8.8", False

        if path == f"{home}/.bashrc":
            return "# ~/.bashrc: executed by bash(1) for non-login shells.", False

        return f"{name}: {target}: No such file or directory", False

    if name == "ps":
        return (
            "    PID TTY          TIME CMD\n"
            "   1001 pts/0    00:00:00 bash\n"
            "   1002 pts/0    00:00:00 ps"
        ), False

    if name == "date":
        return time.strftime("%a %b %d %H:%M:%S UTC %Y", time.gmtime()), False

    if name == "uptime":
        return (
            " 12:34:56 up 3 days,  4:12,  1 user,  "
            "load average: 0.00, 0.01, 0.05"
        ), False

    if name == "echo":
        return " ".join(args), False

    if name == "env":
        return (
            f"HOME={home}\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            "LANG=C.UTF-8\n"
            f"USER={user}\n"
            f"LOGNAME={user}"
        ), False

    if name == "ifconfig":
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.0.0.5  netmask 255.255.255.0  ether 02:42:0a:00:00:05"
        ), False

    if name == "ip":
        return (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
            "    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0"
        ), False

    if name == "history":
        return (
            "    1  ls\n"
            "    2  whoami\n"
            "    3  history"
        ), False

    if name == "clear":
        return "\x1b[2J\x1b[H", False

    if name in ("wget", "curl", "ftp", "scp", "rsync"):
        return f"{name}: network is unreachable", False

    if name == "ssh":
        return "ssh: connect to host: Connection timed out", False

    if name == "sudo":
        return f"{user} is not in the sudoers file. This incident will be reported.", False

    if name == "su":
        return "Password: \nsu: Authentication failure", False

    if name in ("rm", "mv", "cp", "chmod", "chown", "touch", "mkdir", "rmdir"):
        target = args[-1] if args else ""
        return f"{name}: cannot access '{target}': Permission denied", False

    if name in ("service", "systemctl"):
        return "Failed to connect to bus: No such file or directory", False

    if name in ("crontab", "at"):
        return f"{name}: permission denied", False

    if name in ("iptables", "nft", "mount", "umount", "reboot", "shutdown", "poweroff"):
        return f"{name}: permission denied", False

    if name in ("python", "python3", "perl", "ruby", "nc", "ncat", "netcat", "bash", "sh"):
        # Do not provide a real interpreter.
        return f"-bash: {name}: command not found", False

    return f"-bash: {name}: command not found", False


class EventLogger:
    """Log structured events to stdout and optionally to a JSONL file."""

    def __init__(self, log_file=None, log_passwords=False):
        self.log_passwords = log_passwords
        self.lock = threading.Lock()
        self.log_file = None

        if log_file:
            path = Path(log_file)
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch(exist_ok=True)
                self.log_file = path
            except OSError as exc:
                LOG.warning(
                    "Cannot write JSONL log file %s: %s. Using stdout only.",
                    path,
                    exc,
                )

    def log(self, event, **fields):
        record = {
            "timestamp": utc_now(),
            "event": event,
        }
        record.update(fields)

        if "password" in record and not self.log_passwords:
            record["password"] = "[REDACTED]"

        # Never print passwords to stdout, even if file logging is enabled.
        console_record = {k: v for k, v in record.items() if k != "password"}

        LOG.info(
            "%s %s",
            event,
            json.dumps(console_record, ensure_ascii=False, sort_keys=True, default=str),
        )

        if self.log_file:
            line = json.dumps(record, ensure_ascii=False, default=str)
            try:
                with self.lock:
                    with self.log_file.open("a", encoding="utf-8") as f:
                        f.write(line + "\n")
            except OSError as exc:
                LOG.warning(
                    "Failed writing JSONL log file: %s. Disabling file logging.",
                    exc,
                )
                self.log_file = None


class HoneypotServer(paramiko.ServerInterface):
    """Paramiko server interface that accepts almost everything."""

    def __init__(self, event_logger, session_id, peer):
        self.event_logger = event_logger
        self.session_id = session_id
        self.peer = peer
        self.username = None

        self.pending = []
        self.pending_lock = threading.Lock()
        self.pending_event = threading.Event()
        self.channels = []

    def log(self, event, **fields):
        self.event_logger.log(
            event,
            session_id=self.session_id,
            peer=self.peer,
            **fields,
        )

    def check_auth_password(self, username, password):
        self.username = username
        self.log(
            "auth_password",
            username=username,
            password=password,
            success=True,
        )
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        self.username = username
        self.log(
            "auth_publickey",
            username=username,
            key_type=key.get_name(),
            key_fingerprint=key.get_fingerprint().hex(),
            success=True,
        )
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            self.log("channel_request", kind=kind, chanid=chanid)
            return paramiko.OPEN_SUCCEEDED

        self.log("channel_request_rejected", kind=kind, chanid=chanid)
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(
        self,
        channel,
        term,
        width,
        height,
        pixelwidth,
        pixelheight,
        modes,
    ):
        self.log(
            "pty_request",
            term=to_text(term),
            width=width,
            height=height,
        )
        return True

    def check_channel_shell_request(self, channel):
        self.log("shell_request")
        self._add_pending(("shell", channel))
        return True

    def check_channel_exec_request(self, channel, command):
        self.log("exec_request", command=to_text(command))
        self._add_pending(("exec", channel, command))
        return True

    def check_channel_env_request(self, channel, name, value):
        self.log("env_request", name=to_text(name), value=to_text(value))
        return True

    def check_channel_window_change_request(
        self,
        channel,
        width,
        height,
        pixelwidth,
        pixelheight,
    ):
        return True

    def check_channel_subsystem_request(self, channel, name):
        self.log("subsystem_request_rejected", name=to_text(name))
        return False

    def _add_pending(self, item):
        with self.pending_lock:
            self.pending.append(item)
            self.pending_event.set()

    def take_pending(self):
        with self.pending_lock:
            items = self.pending.copy()
            self.pending.clear()
            self.pending_event.clear()
            return items

    def has_pending(self):
        with self.pending_lock:
            return bool(self.pending)


def handle_shell(channel, server, event_logger):
    """Fake interactive shell handler."""
    user = server.username or "visitor"

    state = {
        "user": user,
        "hostname": FAKE_HOSTNAME,
        "cwd": home_dir_for(user),
        "oldpwd": home_dir_for(user),
    }

    event_logger.log(
        "shell_started",
        session_id=server.session_id,
        peer=server.peer,
        username=user,
    )

    try:
        channel.sendall(b"Linux ubuntu 5.15.0-91-generic\r\n")
        channel.sendall(
            b"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
        )
        channel.sendall(b" * Documentation:  https://help.ubuntu.com\r\n")
        channel.sendall(b" * Management:     https://landscape.canonical.com\r\n")
        channel.sendall(b" * Support:        https://ubuntu.com/advantage\r\n\r\n")

        last_login = time.strftime("%a %b %d %H:%M:%S %Y", time.gmtime())
        channel.sendall(f"Last login: {last_login} from 10.0.0.1\r\n".encode())

        channel.sendall(get_prompt(state).encode())

        input_buffer = b""
        in_escape = False
        skip_lf = False

        while True:
            try:
                data = channel.recv(1024)
            except (EOFError, OSError):
                break

            if not data:
                break

            for byte in data:
                if skip_lf:
                    skip_lf = False
                    if byte == 0x0A:
                        continue

                if in_escape:
                    # Ignore terminal escape sequences until final byte.
                    if 0x40 <= byte <= 0x7E:
                        in_escape = False
                    continue

                if byte == 0x1B:
                    in_escape = True
                    continue

                enter_pressed = False

                if byte == 0x03:
                    # Ctrl+C
                    channel.sendall(b"^C\r\n")
                    input_buffer = b""
                    channel.sendall(get_prompt(state).encode())

                elif byte == 0x04:
                    # Ctrl+D
                    if not input_buffer:
                        channel.sendall(b"logout\r\n")
                        event_logger.log(
                            "shell_closed",
                            session_id=server.session_id,
                            peer=server.peer,
                            username=user,
                            reason="ctrl-d",
                        )
                        channel.close()
                        return

                elif byte == 0x0D:
                    skip_lf = True
                    enter_pressed = True

                elif byte == 0x0A:
                    enter_pressed = True

                elif byte in (0x7F, 0x08):
                    # Backspace
                    if input_buffer:
                        input_buffer = input_buffer[:-1]
                        channel.sendall(b"\x08 \x08")

                elif byte == 0x15:
                    # Ctrl+U: clear current line.
                    if input_buffer:
                        channel.sendall(b"\r\x1b[K")
                        channel.sendall(get_prompt(state).encode())
                        input_buffer = b""

                elif byte == 0x09:
                    # Tab: fake completion as spaces.
                    channel.sendall(b"    ")
                    input_buffer += b"    "

                elif byte >= 0x20:
                    input_buffer += bytes([byte])
                    channel.sendall(bytes([byte]))

                if enter_pressed:
                    channel.sendall(b"\r\n")
                    line = input_buffer.decode("utf-8", "replace").strip()

                    if line:
                        event_logger.log(
                            "command",
                            session_id=server.session_id,
                            peer=server.peer,
                            username=user,
                            cwd=state["cwd"],
                            command=line,
                        )

                        output, close_shell = process_command(line, state)
                        if output:
                            send_output(channel, output, use_crlf=True)

                        if close_shell:
                            event_logger.log(
                                "shell_closed",
                                session_id=server.session_id,
                                peer=server.peer,
                                username=user,
                                reason="exit-command",
                            )
                            channel.close()
                            return

                    input_buffer = b""
                    channel.sendall(get_prompt(state).encode())

    except Exception as exc:
        event_logger.log(
            "shell_error",
            session_id=server.session_id,
            peer=server.peer,
            error=str(exc),
        )
    finally:
        try:
            channel.close()
        except Exception:
            pass


def handle_exec(channel, command_bytes, server, event_logger):
    """Handle one-shot commands like: ssh user@host 'ls -la'."""
    command = to_text(command_bytes)
    user = server.username or "visitor"

    state = {
        "user": user,
        "hostname": FAKE_HOSTNAME,
        "cwd": home_dir_for(user),
        "oldpwd": home_dir_for(user),
    }

    event_logger.log(
        "exec_command",
        session_id=server.session_id,
        peer=server.peer,
        username=user,
        cwd=state["cwd"],
        command=command,
    )

    try:
        output, _ = process_command(command, state)
        if output:
            send_output(channel, output, use_crlf=False)

        channel.send_exit_status(0)
        time.sleep(0.05)
    except Exception as exc:
        event_logger.log(
            "exec_error",
            session_id=server.session_id,
            peer=server.peer,
            error=str(exc),
        )
    finally:
        try:
            channel.close()
        except Exception:
            pass


def load_or_create_host_key(path):
    """Load RSA host key from disk or create a new one."""
    p = Path(path)

    try:
        if p.exists():
            LOG.info("Loading SSH host key from %s", p)
            return paramiko.RSAKey(filename=str(p))

        p.parent.mkdir(parents=True, exist_ok=True)
        LOG.info("Generating new 2048-bit RSA SSH host key at %s", p)

        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(str(p))
        os.chmod(p, 0o600)

        return key

    except OSError as exc:
        LOG.warning(
            "Cannot use host key file %s: %s. Using ephemeral in-memory host key.",
            p,
            exc,
        )
        return paramiko.RSAKey.generate(2048)


def handle_client(sock, addr, host_key, event_logger):
    session_id = uuid.uuid4().hex[:12]
    peer = f"{addr[0]}:{addr[1]}"

    event_logger.log(
        "connection_open",
        session_id=session_id,
        peer=peer,
        remote_ip=addr[0],
        remote_port=addr[1],
    )

    transport = None

    try:
        transport = paramiko.Transport(sock)
        transport.add_server_key(host_key)
        transport.set_keepalive(30)

        server = HoneypotServer(event_logger, session_id, peer)

        try:
            transport.start_server(server=server)
        except paramiko.SSHException as exc:
            event_logger.log(
                "ssh_handshake_failed",
                session_id=session_id,
                peer=peer,
                error=str(exc),
            )
            return

        event_logger.log("ssh_handshake_ok", session_id=session_id, peer=peer)

        while transport.is_active() or server.has_pending():
            try:
                channel = transport.accept(timeout=0.2)
            except Exception:
                channel = None

            if channel is not None:
                server.channels.append(channel)

            for item in server.take_pending():
                if item[0] == "shell":
                    threading.Thread(
                        target=handle_shell,
                        args=(item[1], server, event_logger),
                        daemon=True,
                    ).start()

                elif item[0] == "exec":
                    threading.Thread(
                        target=handle_exec,
                        args=(item[1], item[2], server, event_logger),
                        daemon=True,
                    ).start()

            time.sleep(0.05)

    except Exception as exc:
        event_logger.log(
            "connection_error",
            session_id=session_id,
            peer=peer,
            error=str(exc),
        )
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass

        event_logger.log(
            "connection_closed",
            session_id=session_id,
            peer=peer,
        )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Interactive SSH honeypot with a fake shell.",
    )

    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Bind address. Default: 0.0.0.0",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=2222,
        help="Listen port. Default: 2222",
    )

    parser.add_argument(
        "--host-key",
        default="data/ssh_host_rsa_key",
        help="Path to SSH host RSA key.",
    )

    parser.add_argument(
        "--log-file",
        default="data/honeypot.jsonl",
        help="Path to JSONL log file.",
    )

    parser.add_argument(
        "--log-passwords",
        action="store_true",
        help="Store submitted passwords in JSONL logs. Disabled by default.",
    )

    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Python logging level. Default: INFO",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
        stream=sys.stdout,
    )

    event_logger = EventLogger(
        log_file=args.log_file,
        log_passwords=args.log_passwords,
    )

    host_key = load_or_create_host_key(args.host_key)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        listener.bind((args.host, args.port))
    except PermissionError:
        LOG.error(
            "Cannot bind to %s:%s. Use a non-privileged port such as 2222 "
            "or run with appropriate capabilities.",
            args.host,
            args.port,
        )
        sys.exit(1)
    except OSError as exc:
        LOG.error("Cannot bind to %s:%s: %s", args.host, args.port, exc)
        sys.exit(1)

    listener.listen(100)

    LOG.info("SSH honeypot listening on %s:%s", args.host, args.port)
    LOG.info("JSONL log file: %s", args.log_file or "stdout only")
    LOG.info(
        "Password logging: %s",
        "enabled" if args.log_passwords else "disabled",
    )

    try:
        while True:
            client_sock, addr = listener.accept()

            threading.Thread(
                target=handle_client,
                args=(client_sock, addr, host_key, event_logger),
                daemon=True,
            ).start()

    except KeyboardInterrupt:
        LOG.info("Shutdown requested by user")
    finally:
        listener.close()


if __name__ == "__main__":
    main()
