# SSH Honeypot

A small, interactive SSH honeypot written in Python. It accepts almost any SSH authentication attempt and gives attackers a fake interactive shell. All commands are logged for analysis.

This project is intended for education, research, and defensive security use cases.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Docker](https://img.shields.io/badge/Docker-enabled-2496ED?logo=docker)
![Status](https://img.shields.io/badge/status-pet%20project-yellow)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Warning / Responsible Use](#warning--responsible-use)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Quick Start with Docker](#quick-start-with-docker)
- [Run Without Docker](#run-without-docker)
- [Testing the Honeypot](#testing-the-honeypot)
- [Example Session](#example-session)
- [One-Shot Command Execution](#one-shot-command-execution)
- [Logging](#logging)
- [JSONL Event Types](#jsonl-event-types)
- [Analyzing Logs](#analyzing-logs)
- [Configuration](#configuration)
- [Docker Notes](#docker-notes)
- [Deploying on a VPS](#deploying-on-a-vps)
- [Security Hardening Recommendations](#security-hardening-recommendations)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [Alternatives](#alternatives)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

This is a low-interaction SSH honeypot.

It pretends to be an SSH server running on an Ubuntu-like system. When a client connects, the honeypot:

1. Accepts SSH connections.
2. Accepts any username/password combination.
3. Accepts public key authentication.
4. Opens a fake interactive shell.
5. Logs commands entered by the client.
6. Returns fake command output.
7. Does **not** execute commands on the host system.

The goal is to observe what attackers try after gaining SSH access.

---

## Features

- Interactive fake SSH shell
- Accepts any password
- Accepts any public key
- Logs authentication attempts
- Logs executed commands
- Logs one-shot SSH commands, for example:

  ```bash
  ssh user@host "uname -a"
  ```

- Structured JSONL logging
- Docker support
- Docker Compose support
- Non-root container user
- Read-only container filesystem
- Persistent volume for logs and SSH host key
- Password logging disabled by default

---

## Warning / Responsible Use

Run this honeypot only on systems you own or have explicit permission to monitor.

Recommended safety rules:

- Do not run it on production infrastructure.
- Use an isolated VM or VPS.
- Do not expose real sensitive services on the same machine.
- Use a non-privileged port such as `2222`.
- Keep the honeypot updated.
- Treat logs as potentially malicious input.
- Be careful if you enable password logging.
- Check local laws and regulations before collecting attacker activity.

This honeypot is intentionally simple. It is not a full high-interaction honeypot.

---

## How It Works

The honeypot uses [Paramiko](https://github.com/paramiko/paramiko) to implement an SSH server.

When a client connects:

1. Paramiko performs the SSH handshake.
2. The honeypot presents an RSA host key.
3. The client tries to authenticate.
4. The honeypot accepts password or public key authentication.
5. The client requests a shell or executes a command.
6. The honeypot returns fake output.
7. All interesting events are written to JSONL logs.

No real system commands are executed.

For example, if an attacker types:

```bash
rm -rf /
```

the honeypot only logs the command and returns a fake permission error.

---

## Architecture

```text
Attacker
   |
   | SSH TCP connection
   v
Docker container
   |
   | Paramiko SSH server
   v
Fake shell / fake command processor
   |
   | Structured events
   v
JSONL log file + stdout logs
```

---

## Project Structure

```text
ssh-honeypot/
├── .dockerignore
├── .gitignore
├── Dockerfile
├── README.md
├── docker-compose.yml
├── honeypot.py
└── requirements.txt
```

---

## Requirements

### Docker

Recommended:

- Docker Engine 24+
- Docker Compose v2

### Local Python

If you want to run without Docker:

- Python 3.11 or newer
- pip

---

## Quick Start with Docker

Build and start the container:

```bash
docker compose up --build -d
```

Check logs:

```bash
docker compose logs -f ssh-honeypot
```

Connect to the honeypot:

```bash
ssh -p 2222 test@localhost
```

Use any password.

For testing, you can disable strict host key checking:

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 test@localhost
```

Stop the honeypot:

```bash
docker compose down
```

Stop and remove persistent data:

```bash
docker compose down -v
```

---

## Run Without Docker

Create a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the honeypot:

```bash
python honeypot.py --host 0.0.0.0 --port 2222
```

By default, it creates:

```text
data/ssh_host_rsa_key
data/honeypot.jsonl
```

---

## Testing the Honeypot

Connect:

```bash
ssh -p 2222 attacker@localhost
```

Enter any password.

Then try:

```bash
whoami
id
pwd
ls
uname -a
cat /etc/passwd
cat /etc/shadow
sudo su
wget http://example.com/payload.sh
exit
```

Expected behavior:

- The honeypot returns fake output.
- Commands are logged.
- Nothing is executed on the host.
- Network download commands are not performed.

---

## Example Session

```text
$ ssh -p 2222 attacker@localhost
attacker@localhost's password:

Linux ubuntu 5.15.0-91-generic
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Thu Jul 23 12:00:00 2026 from 10.0.0.1
attacker@ubuntu:~$ whoami
attacker
attacker@ubuntu:~$ id
uid=1000(attacker) gid=1000(attacker) groups=1000(attacker),27(sudo)
attacker@ubuntu:~$ ls
Desktop  Documents  Downloads  Pictures  .bashrc
attacker@ubuntu:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
attacker:x:1000:1000:attacker:/home/attacker:/bin/bash
attacker@ubuntu:~$ sudo su
attacker is not in the sudoers file. This incident will be reported.
attacker@ubuntu:~$ exit
logout
```

---

## One-Shot Command Execution

The honeypot also supports commands passed directly over SSH:

```bash
ssh -p 2222 attacker@localhost "uname -a"
```

Example output:

```text
Linux ubuntu 5.15.0-91-generic #101-Ubuntu SMP Tue Oct 10 12:34:56 UTC 2023 x86_64
```

Another example:

```bash
ssh -p 2222 attacker@localhost "cat /etc/passwd"
```

These commands are logged as `exec_command` events.

---

## Logging

The honeypot writes logs to two places:

1. stdout
2. JSONL file

Default JSONL location inside Docker:

```text
/app/data/honeypot.jsonl
```

Default JSONL location when running locally:

```text
data/honeypot.jsonl
```

stdout logs are useful for live monitoring:

```bash
docker compose logs -f ssh-honeypot
```

JSONL logs are useful for later analysis.

---

## JSONL Event Types

Each line in the JSONL file is one event.

Example:

```json
{
  "timestamp": "2026-07-23T12:00:00.000000+00:00",
  "event": "connection_open",
  "session_id": "a1b2c3d4e5f6",
  "peer": "203.0.113.10:54321",
  "remote_ip": "203.0.113.10",
  "remote_port": 54321
}
```

Common events:

| Event | Description |
|---|---|
| `connection_open` | A TCP connection was accepted. |
| `ssh_handshake_ok` | SSH handshake completed. |
| `ssh_handshake_failed` | SSH handshake failed. |
| `auth_password` | Password authentication attempt. |
| `auth_publickey` | Public key authentication attempt. |
| `channel_request` | SSH channel request. |
| `pty_request` | Client requested a pseudo-terminal. |
| `shell_request` | Client requested an interactive shell. |
| `exec_request` | Client requested command execution. |
| `exec_command` | One-shot command received. |
| `command` | Command entered in interactive shell. |
| `env_request` | Client sent environment variables. |
| `subsystem_request_rejected` | Subsystem request such as SFTP was rejected. |
| `shell_closed` | Interactive shell closed. |
| `connection_error` | Connection error occurred. |
| `connection_closed` | Connection closed. |

Example password authentication event:

```json
{
  "timestamp": "2026-07-23T12:00:01.000000+00:00",
  "event": "auth_password",
  "session_id": "a1b2c3d4e5f6",
  "peer": "203.0.113.10:54321",
  "username": "root",
  "password": "[REDACTED]",
  "success": true
}
```

Example command event:

```json
{
  "timestamp": "2026-07-23T12:00:05.000000+00:00",
  "event": "command",
  "session_id": "a1b2c3d4e5f6",
  "peer": "203.0.113.10:54321",
  "username": "root",
  "cwd": "/root",
  "command": "cat /etc/passwd"
}
```

---

## Analyzing Logs

Copy logs from the container:

```bash
docker compose cp ssh-honeypot:/app/data/honeypot.jsonl ./honeypot.jsonl
```

Count usernames:

```bash
jq -r 'select(.event == "auth_password") | .username' honeypot.jsonl \
  | sort \
  | uniq -c \
  | sort -nr
```

Count commands:

```bash
jq -r 'select(.event == "command") | .command' honeypot.jsonl \
  | sort \
  | uniq -c \
  | sort -nr
```

Show commands by IP:

```bash
jq -r 'select(.event == "command") | [.peer, .command] | @tsv' honeypot.jsonl
```

Show all events for one session:

```bash
jq 'select(.session_id == "a1b2c3d4e5f6")' honeypot.jsonl
```

---

## Configuration

The honeypot supports command-line options.

```bash
python honeypot.py --help
```

Options:

| Option | Default | Description |
|---|---:|---|
| `--host` | `0.0.0.0` | Bind address. |
| `--port` | `2222` | Listen port. |
| `--host-key` | `data/ssh_host_rsa_key` | SSH host key path. |
| `--log-file` | `data/honeypot.jsonl` | JSONL log file path. |
| `--log-passwords` | disabled | Store passwords in JSONL logs. |
| `--log-level` | `INFO` | Python log level. |

Example:

```bash
python honeypot.py \
  --host 0.0.0.0 \
  --port 2222 \
  --host-key data/ssh_host_rsa_key \
  --log-file data/honeypot.jsonl
```

### Password Logging

Password logging is disabled by default.

If disabled, passwords are replaced with:

```text
[REDACTED]
```

Enable password logging only if you understand the legal and security risks:

```bash
python honeypot.py --log-passwords
```

With Docker Compose, you can override the command:

```yaml
services:
  ssh-honeypot:
    build: .
    container_name: ssh-honeypot
    restart: unless-stopped
    ports:
      - "2222:2222"
    volumes:
      - ssh_honeypot_data:/app/data
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    command:
      - python
      - honeypot.py
      - --host
      - 0.0.0.0
      - --port
      - "2222"
      - --host-key
      - /app/data/ssh_host_rsa_key
      - --log-file
      - /app/data/honeypot.jsonl
      - --log-passwords

volumes:
  ssh_honeypot_data:
```

Again: enabling password logging may be risky and may be regulated in your jurisdiction.

---

## Docker Notes

### Persistent Data

The Docker container stores persistent data in a named volume:

```text
/app/data
```

This directory contains:

```text
ssh_host_rsa_key
honeypot.jsonl
```

### View Log File Inside Container

```bash
docker compose exec ssh-honeypot cat /app/data/honeypot.jsonl
```

### Copy Log File to Host

```bash
docker compose cp ssh-honeypot:/app/data/honeypot.jsonl ./honeypot.jsonl
```

### Remove All Persistent Data

```bash
docker compose down -v
```

If you remove the volume, the SSH host key will be regenerated on the next start. SSH clients may show a host key warning.

---

## Deploying on a VPS

Example deployment on Ubuntu/VPS.

### 1. Copy project to server

```bash
scp -r ssh-honeypot user@your-server:~/ssh-honeypot
```

### 2. Install Docker

Use the official Docker installation guide for your distribution.

For Ubuntu:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
```

Add your user to the `docker` group if needed:

```bash
sudo usermod -aG docker "$USER"
```

Log out and log back in.

### 3. Start honeypot

```bash
cd ssh-honeypot
docker compose up --build -d
```

### 4. Open firewall port

If using UFW:

```bash
sudo ufw allow 2222/tcp
sudo ufw reload
```

### 5. Monitor logs

```bash
docker compose logs -f ssh-honeypot
```

---

## Security Hardening Recommendations

This project already uses some basic hardening:

- non-root container user
- read-only root filesystem
- temporary `/tmp` filesystem
- `no-new-privileges`
- no real command execution

Additional recommendations:

1. Run the honeypot on an isolated VPS or VM.
2. Do not store secrets on the honeypot machine.
3. Do not expose port `22` directly unless you understand the risks.
4. Use firewall rules to limit access if needed.
5. Rotate or archive logs regularly.
6. Monitor log size.
7. Treat logs as untrusted input.
8. Do not analyze logs with vulnerable tools.
9. Consider sending logs to a separate centralized logging system.
10. Consider restricting outbound traffic from the honeypot host.

### About Port 22

For safety, this project uses port `2222` by default.

If you want to listen on port `22`, prefer one of these approaches:

- run a reverse proxy such as NGINX stream or `socat` on port `22`;
- use `authbind`;
- use a controlled container runtime capability setup.

Avoid running the honeypot as root just to bind port `22`.

---

## Limitations

This is a pet project and a low-interaction honeypot.

It does not:

- execute real commands;
- provide a real filesystem;
- support SFTP or SCP file transfer;
- support SSH port forwarding;
- emulate a full Linux system;
- perfectly emulate Bash line editing;
- handle complex shell syntax perfectly;
- download files from the internet;
- provide production-grade attacker emulation.

Command parsing is intentionally simple.

For example:

```bash
echo hello; whoami
```

is split into:

```bash
echo hello
whoami
```

More complex shell syntax may not behave exactly like a real shell.

---

## Troubleshooting

### Cannot bind to port 22

Ports below 1024 usually require root privileges.

Use port `2222` instead:

```bash
docker compose up -d
```

Or use a reverse proxy / port forwarder.

---

### SSH client warns about changed host key

Example:

```text
WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!
```

This can happen if the honeypot volume was removed and the SSH host key was regenerated.

For testing, use:

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 test@localhost
```

Or remove the old key:

```bash
ssh-keygen -R "[localhost]:2222"
```

---

### Logs are not written to JSONL file

Check container logs:

```bash
docker compose logs -f ssh-honeypot
```

If the honeypot cannot write to `/app/data`, it falls back to stdout logging.

Copy logs from stdout:

```bash
docker compose logs --no-color ssh-honeypot > honeypot-stdout.log
```

---

### Container exits immediately

Check logs:

```bash
docker compose logs ssh-honeypot
```

Common causes:

- port already in use;
- permission problems;
- invalid Python syntax after local modifications;
- missing dependencies.

Rebuild the image:

```bash
docker compose up --build -d
```

---

### Port is already in use

Check what is using port `2222`:

```bash
sudo ss -ltnp | grep 2222
```

Change the published port in `docker-compose.yml`:

```yaml
ports:
  - "2223:2222"
```

Then connect:

```bash
ssh -p 2223 test@localhost
```

---

### SSH negotiation errors

Some SSH clients and servers may disagree on key exchange or host key algorithms.

Make sure:

- Paramiko is up to date;
- OpenSSH client is up to date;
- Docker image was rebuilt after dependency changes.

Rebuild:

```bash
docker compose build --no-cache
docker compose up -d
```

---

## Roadmap

Possible improvements:

- [ ] More fake commands
- [ ] More realistic fake filesystem
- [ ] Fake `wget`/`curl` download metadata without real network access
- [ ] Telegram notifications
- [ ] GeoIP enrichment
- [ ] ASN enrichment
- [ ] Session recording
- [ ] SFTP honeypot support
- [ ] Elasticsearch export
- [ ] Loki/Promtail integration
- [ ] Grafana dashboard
- [ ] Fail2ban integration
- [ ] Multiple fake OS profiles
- [ ] Randomized system banners
- [ ] IPv6 support
- [ ] Unit tests
- [ ] Integration tests

---

## Alternatives

If you need a more mature SSH honeypot, consider:

- [Cowrie](https://github.com/cowrie/cowrie)
- [Dionaea](https://github.com/DinoTools/dionaea)
- [Honeyd](https://github.com/provos/honeyd)

This project is intentionally smaller and simpler. It is a good starting point for learning how SSH honeypots work.

---

## Contributing

Contributions are welcome.

Ideas for pull requests:

- bug fixes;
- new fake commands;
- better documentation;
- tests;
- log analysis examples;
- Docker improvements.

Before submitting a PR, make sure:

- Python code is readable;
- comments are in English;
- program output is in English;
- Docker build works;
- no real command execution is introduced.

---

## License

Add a license file before publishing if you want others to use the project.

For a simple permissive license, you can use MIT.

Without a license, others may not have explicit rights to use, modify, or redistribute the code.
