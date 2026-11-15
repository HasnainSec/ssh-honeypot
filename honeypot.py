#!/usr/bin/env python3
"""Minimal SSH honeypot.

Pretends to be an OpenSSH server, rejects EVERY login, and records who tried.

Two outputs:
  honeypot_auth.log     sshd-style lines ("Failed password for invalid user ...")
                        so ssh-log-analyzer can read it directly.
  honeypot_creds.jsonl  one JSON object per attempt, including the password and
                        the client's SSH version string, for deeper analysis.

Nobody ever gets a shell: authentication always fails and no channel is opened.
Only run this on an isolated machine, on a high port (default 2222), never as root.
"""
import argparse
import json
import os
import socket
import threading
import time

import paramiko

BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
AUTH_TIMEOUT = 30          # seconds a client may stay connected
MAX_CONNECTIONS = 50       # simultaneous connections


def syslog_time(ts=None):
    """Timestamp in classic syslog form, e.g. 'Nov 15 19:50:01' (day space-padded)."""
    t = time.localtime(ts)
    return f"{time.strftime('%b', t)} {t.tm_mday:2d} {time.strftime('%H:%M:%S', t)}"


def format_failed_line(username, ip, port, pid, hostname="honeypot", ts=None):
    """Same shape as a real sshd failed-password line."""
    return (f"{syslog_time(ts)} {hostname} sshd[{pid}]: "
            f"Failed password for invalid user {username} from {ip} port {port} ssh2")


class Recorder:
    """Thread-safe writer for the two log files."""

    def __init__(self, auth_log, creds_log):
        self.auth_log = auth_log
        self.creds_log = creds_log
        self.lock = threading.Lock()

    def record(self, username, password, ip, port, client_version):
        pid = 1000 + (threading.get_ident() % 9000)
        line = format_failed_line(username, ip, port, pid)
        entry = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "ip": ip,
            "port": port,
            "username": username,
            "password": password,
            "client_version": client_version,
        }
        with self.lock:
            with open(self.auth_log, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            with open(self.creds_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        print(line, flush=True)


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, recorder, ip, port):
        self.recorder = recorder
        self.ip = ip
        self.port = port
        self.transport = None

    def _client_version(self):
        return getattr(self.transport, "remote_version", "") if self.transport else ""

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self.recorder.record(username, password, self.ip, self.port, self._client_version())
        time.sleep(1)  # slow bots down a little
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


def handle_client(client, addr, host_key, recorder, slots):
    ip, port = addr[0], addr[1]
    transport = None
    try:
        client.settimeout(AUTH_TIMEOUT)
        transport = paramiko.Transport(client)
        transport.local_version = BANNER
        transport.add_server_key(host_key)
        server = HoneypotServer(recorder, ip, port)
        server.transport = transport
        transport.start_server(server=server)
        deadline = time.time() + AUTH_TIMEOUT
        while transport.is_active() and time.time() < deadline:
            time.sleep(0.5)
    except (paramiko.SSHException, EOFError, OSError):
        pass  # scanners often disconnect mid-handshake; that is normal
    finally:
        try:
            if transport:
                transport.close()
            client.close()
        finally:
            slots.release()


def load_host_key(path):
    if os.path.exists(path):
        return paramiko.RSAKey(filename=path)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    os.chmod(path, 0o600)
    return key


def main():
    ap = argparse.ArgumentParser(description="Minimal SSH honeypot (rejects every login)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--auth-log", default="honeypot_auth.log")
    ap.add_argument("--creds-log", default="honeypot_creds.jsonl")
    ap.add_argument("--host-key", default="host_rsa.key")
    args = ap.parse_args()

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("Refusing to run as root. Use a normal user and a port above 1024.")
        raise SystemExit(1)

    host_key = load_host_key(args.host_key)
    recorder = Recorder(args.auth_log, args.creds_log)
    slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(100)
    print(f"Honeypot listening on {args.host}:{args.port}  (Ctrl+C to stop)", flush=True)

    try:
        while True:
            client, addr = sock.accept()
            if not slots.acquire(blocking=False):
                client.close()
                continue
            threading.Thread(
                target=handle_client,
                args=(client, addr, host_key, recorder, slots),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
