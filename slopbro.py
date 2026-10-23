#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SlopBro
# by throwaway96
# https://github.com/throwaway96/slopbro
# Copyright 2026. Licensed under AGPL v3 or later. No warranties.

"""
slopbro.py - Connect to an LG webOS TV over SSAP, pair, and
launch various apps with a self-hosted payload page.

Standard library only. Requires trusted HTTPS payload delivery and a TV
certificate pin. See README.md and --help for prerequisites and usage.
"""

import argparse
import base64
import json
import hmac
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import threading
import time
import tempfile
from hashlib import sha1, sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlencode
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

PORT_TLS = 3001
PORT_PLAIN = 3000

# TODO: Support complete webOS version numbers (or firmware versions?).
# TODO: Figure out actual webOS version ranges for each app.
TARGET_APPS = [
    ("com.webos.app.voiceweb", "URL", [11]),
    (
        "com.webos.app.adoverlayex",
        "interactiveUrl",
        [3, 4, 5, 6, 7, 8, 9, 10],
    ),
    # TODO: Figure out why this doesn't always work on webOS 6.5.3.
    ("com.webos.app.adoverlay", "interactiveUrl", [3, 4, 5, 6, 7, 8, 9, 10]),
    ("com.webos.app.acroverlay", "contentTarget", [3, 4, 5, 6, 7, 8, 9, 10]),
    ("com.webos.app.tinybrowser", "contentTarget", [3, 4, 5, 6, 7, 8, 9, 10]),
    # May not work on certain webOS versions (e.g., 6.5.x) even if present
    # because of region restrictions.
    ("com.webos.app.dangbei-overlay", "target", [3, 4, 6, 7, 8, 9, 10]),
]

ENTRY_PAGE = "index.html"
SHELL_SCRIPT = "autoroot.sh"
SERVICE_FILES = [
    "package.json",
    "main.js",
    "luna-helper.js",
    "hbchannel-startup.sh",
]
HBC_NAME = "hbchannel.ipk"
HBC_SHA256 = "d10bf3c753551d7c72fb7a92b20fcd2317e502a220ac668ba8e76f6ea78b363c"
HBC_URL = "https://github.com/webosbrew/webos-homebrew-channel/releases/download/v0.7.3/org.webosbrew.hbchannel_0.7.3_all.ipk"
MAX_PACKAGE_BYTES = 8 * 1024 * 1024
MAX_WS_BYTES = 8 * 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024

ASSET_SOURCE_AUTO = "auto"
ASSET_SOURCE_DIR = "dir"
ASSET_SOURCE_EMBEDDED = "embedded"
ASSET_SOURCES = (ASSET_SOURCE_AUTO, ASSET_SOURCE_DIR, ASSET_SOURCE_EMBEDDED)

TEST_SERVER_SIMPLE = "simple"
TEST_SERVER_PAYLOAD = "payload"
TEST_SERVER_MODES = (TEST_SERVER_SIMPLE, TEST_SERVER_PAYLOAD)

# Should exist on all targeted webOS versions.
DEFAULT_FAKE_SERVICE_PATH = "/usr/palm/services/com.palm.service.devmode"

# --- BEGIN EMBEDDED WWWROOT ---
EMBEDDED_WWWROOT = {}
# --- END EMBEDDED WWWROOT ---

# seconds
CONNECT_TIMEOUT = 10.0
PAIR_TIMEOUT = 60.0

# Manifest distilled from the reference clients. Broad permission set so the
# launcher works across firmware versions; the TV grants what it recognizes.
DEFAULT_MANIFEST = {
    "manifestVersion": 1,
    "appVersion": "1.0",
    "appId": "lol.slopbro",
    "vendorId": "throwaway96",
    "localizedAppNames": {"": "SlopBro"},
    "localizedVendorNames": {"": "throwaway96"},
    "permissions": [
        "LAUNCH",
        "CLOSE",
        "READ_APP_STATUS",
        "READ_INSTALLED_APPS",
        "READ_RUNNING_APPS",
    ],
}


def log(msg):
    """Print a timestamped status line to stderr so stdout stays parse-friendly."""
    sys.stderr.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), msg))
    sys.stderr.flush()


def die(msg, code=1):
    log("error: " + msg)
    sys.exit(code)


# ---------------------------------------------------------------------------
# Minimal RFC 6455 WebSocket client (text frames only, client-side masking).
# ---------------------------------------------------------------------------


class WebSocketError(Exception):
    pass


class WebSocket:
    """A tiny blocking WebSocket client over a raw (optionally TLS) socket.

    Only what SSAP needs: a client handshake with no Origin header, masked text
    frames, ping/pong handling, and a clean close. Not a general-purpose library.
    """

    OP_TEXT = 0x1
    OP_CLOSE = 0x8
    OP_PING = 0x9
    OP_PONG = 0xA

    def __init__(self, sock):
        self._sock = sock
        self._recv_buf = b""
        self._recv_deadline = None
        self.closed = False

    @classmethod
    def connect(cls, host, port, secure=True, timeout=CONNECT_TIMEOUT, fingerprint=None):
        if not secure or not fingerprint:
            raise WebSocketError("a verified TV certificate SHA-256 fingerprint is required")
        raw = socket.create_connection((host, port), timeout)
        sock = None
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # A TV normally has a self-signed certificate. Authenticate its
            # exact DER bytes before sending a saved key or pairing request.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            sock = context.wrap_socket(raw, server_hostname=host)
            actual = sha256(sock.getpeercert(binary_form=True)).hexdigest()
            if not hmac.compare_digest(actual, fingerprint):
                sock.close()
                raise WebSocketError("TV certificate fingerprint mismatch; no credentials sent")
            ws = cls(sock)
            ws._recv_deadline = time.monotonic() + timeout
            ws._handshake(host, port, secure)
            ws._recv_deadline = None
            return ws
        except BaseException:
            (sock if sock is not None else raw).close()
            raise

    def _handshake(self, host, port, secure):
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        # Deliberately no Origin header: that is what lets a native client past
        # the SSAP server's web-origin filter.
        lines = [
            "GET / HTTP/1.1",
            "Host: %s:%d" % (host, port),
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Key: %s" % key,
            "Sec-WebSocket-Version: 13",
            "",
            "",
        ]
        self._sock.sendall("\r\n".join(lines).encode("ascii"))

        header = self._read_http_headers()
        status_line = header.split("\r\n", 1)[0]
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or parts[1] != "101":
            raise WebSocketError("unexpected handshake response: %s" % status_line)

        expected = base64.b64encode(
            sha1((key + WS_GUID).encode("ascii")).digest()
        ).decode("ascii")
        accept = None
        for line in header.split("\r\n")[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                if name.strip().lower() == "sec-websocket-accept":
                    accept = value.strip()
                    break
        if accept != expected:
            raise WebSocketError("invalid Sec-WebSocket-Accept value")

    def _read_http_headers(self):
        while b"\r\n\r\n" not in self._recv_buf:
            chunk = self._receive(4096)
            if not chunk:
                raise WebSocketError("connection closed during handshake")
            self._recv_buf += chunk
            if len(self._recv_buf) > MAX_HEADER_BYTES:
                raise WebSocketError("WebSocket handshake headers exceed the size limit")
        header_bytes, self._recv_buf = self._recv_buf.split(b"\r\n\r\n", 1)
        return header_bytes.decode("latin-1")

    def _recv_exact(self, n):
        while len(self._recv_buf) < n:
            chunk = self._receive(max(4096, n - len(self._recv_buf)))
            if not chunk:
                raise WebSocketError("connection closed")
            self._recv_buf += chunk
        data, self._recv_buf = self._recv_buf[:n], self._recv_buf[n:]
        return data

    def _receive(self, size):
        if self._recv_deadline is not None:
            remaining = self._recv_deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("WebSocket receive deadline exceeded")
            self._sock.settimeout(remaining)
        return self._sock.recv(size)

    def send_text(self, text):
        self._send_frame(self.OP_TEXT, text.encode("utf-8"))

    def _send_frame(self, opcode, payload):
        if self.closed:
            raise WebSocketError("socket is closed")
        header = bytearray()
        header.append(0x80 | opcode)  # FIN + opcode
        length = len(payload)
        mask_bit = 0x80  # client frames must be masked
        if length < 126:
            header.append(mask_bit | length)
        elif length < 65536:
            header.append(mask_bit | 126)
            header += struct.pack("!H", length)
        else:
            header.append(mask_bit | 127)
            header += struct.pack("!Q", length)
        mask = os.urandom(4)
        header += mask
        masked = bytearray(payload)
        for i in range(len(masked)):
            masked[i] ^= mask[i % 4]
        self._sock.sendall(bytes(header) + bytes(masked))

    def recv_text(self, timeout=None):
        """Return the next text-frame payload as a unicode string.

        Transparently answers pings. Returns
        None if the peer sends a close frame.
        """
        deadline = time.monotonic() + timeout if timeout is not None else None
        self._recv_deadline = deadline
        fragments = []
        size = 0
        while True:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout("WebSocket message deadline exceeded")
                self._sock.settimeout(remaining)
            fin, opcode, payload = self._read_frame()
            if opcode == self.OP_TEXT:
                if fragments:
                    raise WebSocketError("unexpected text frame during fragmented message")
                fragments.append(payload)
                size += len(payload)
            elif opcode == 0x0:
                if not fragments:
                    raise WebSocketError("unexpected continuation frame")
                fragments.append(payload)
                size += len(payload)
            elif opcode == self.OP_PING:
                self._send_frame(self.OP_PONG, payload)
                continue
            elif opcode == self.OP_PONG:
                continue
            elif opcode == self.OP_CLOSE:
                self._send_close()
                self.closed = True
                return None
            else:
                raise WebSocketError("unsupported WebSocket opcode")
            if size > MAX_WS_BYTES:
                raise WebSocketError("WebSocket message exceeds the size limit")
            if fin:
                try:
                    return b"".join(fragments).decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise WebSocketError("invalid UTF-8 WebSocket message") from exc

    def _read_frame(self):
        b0, b1 = struct.unpack("!BB", self._recv_exact(2))
        if b0 & 0x70 or b1 & 0x80:
            raise WebSocketError("unexpected WebSocket extensions or masked server frame")
        fin = bool(b0 & 0x80)
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recv_exact(8))[0]
        if length > MAX_WS_BYTES or (opcode >= 8 and (not fin or length > 125)):
            raise WebSocketError("invalid or oversized WebSocket frame")
        mask = self._recv_exact(4) if masked else None
        payload = self._recv_exact(length) if length else b""
        if mask:
            payload = bytearray(payload)
            for i in range(len(payload)):
                payload[i] ^= mask[i % 4]
            payload = bytes(payload)
        return fin, opcode, payload

    def _send_close(self):
        try:
            self._send_frame(self.OP_CLOSE, b"")
        except (WebSocketError, OSError):
            pass

    def close(self):
        if not self.closed:
            self._send_close()
            self.closed = True
        try:
            self._sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# SSAP client layer
# ---------------------------------------------------------------------------


class SSAPError(Exception):
    pass


class SSAPClient:
    def __init__(self, ws):
        self._ws = ws
        self._counter = 0

    def _next_id(self, prefix):
        self._counter += 1
        return "%s_%d" % (prefix, self._counter)

    def _send(self, message):
        self._ws.send_text(json.dumps(message))

    def register(self, client_key, manifest, timeout=PAIR_TIMEOUT):
        """Perform the SSAP register handshake.

        Returns the client-key string from the 'registered' reply. If no key was
        stored, the TV shows a pairing prompt and this blocks (up to timeout)
        until the user accepts.
        """
        payload = {
            "forcePairing": False,
            "pairingType": "PROMPT",
            "manifest": manifest,
        }
        if client_key:
            payload["client-key"] = client_key
        msg_id = self._next_id("register")
        self._send({"id": msg_id, "type": "register", "payload": payload})

        prompted = False
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SSAPError("timed out waiting for registration")
            try:
                raw = self._ws.recv_text(timeout=remaining)
            except socket.timeout:
                raise SSAPError("timed out waiting for registration")
            if raw is None:
                raise SSAPError("connection closed during registration")
            msg = json.loads(raw)
            mtype = msg.get("type")
            if mtype == "registered":
                return (msg.get("payload") or {}).get("client-key", client_key)
            if mtype == "response" and (msg.get("payload") or {}).get("pairingType"):
                if not prompted:
                    prompted = True
                    log("accept the pairing prompt on the TV screen ...")
                continue
            if mtype == "error":
                raise SSAPError(msg.get("error") or "registration rejected")
            # Ignore anything else (e.g. stray notifications) and keep waiting.

    def request(self, uri, payload=None, timeout=15.0):
        """Send an SSAP request and return the matching response message."""
        msg_id = self._next_id("req")
        self._send(
            {
                "id": msg_id,
                "type": "request",
                "uri": uri,
                "payload": payload or {},
            }
        )
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SSAPError("timed out waiting for response to %s" % uri)
            try:
                raw = self._ws.recv_text(timeout=remaining)
            except socket.timeout:
                raise SSAPError("timed out waiting for response to %s" % uri)
            if raw is None:
                raise SSAPError("connection closed while awaiting %s" % uri)
            msg = json.loads(raw)
            if msg.get("id") == msg_id:
                return msg
            # Different id: not ours, keep reading.

    def close(self):
        self._ws.close()


# ---------------------------------------------------------------------------
# Client-key persistence
# ---------------------------------------------------------------------------


def key_path(ip):
    return os.path.join(os.getcwd(), "%s.key" % ip)


def load_client_key(ip):
    path = key_path(ip)
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def save_client_key(ip, client_key):
    path = key_path(ip)
    directory = os.path.dirname(path) or "."
    temporary = None
    try:
        os.makedirs(directory, exist_ok=True)
        # Create with mode 0600 before any secret is written, then replace the
        # directory entry atomically rather than following a preexisting link.
        fd, temporary = tempfile.mkstemp(prefix=".slopbro-key-", dir=directory)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(client_key)
        os.replace(temporary, path)
    except OSError as exc:
        log("warning: could not save client key to %s (%s)" % (path, exc))
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


# ---------------------------------------------------------------------------
# High-level flow
# ---------------------------------------------------------------------------


def target_apps_for_webos_version(candidates, webos_version):
    """Return launcher candidates compatible with the given webOS version."""
    if webos_version is None:
        return [(app_id, url_param_name) for app_id, url_param_name, _ in candidates]

    try:
        major_version = int(str(webos_version).split(".", 1)[0])
    except (TypeError, ValueError):
        raise ValueError("invalid webOS version: %s" % webos_version)

    return [
        (app_id, url_param_name)
        for app_id, url_param_name, major_versions in candidates
        if major_version in major_versions
    ]


def verify_app_present(client, candidates):
    """Check installed apps and return the first matching (app_id, url_param_name).

    Falls back to the first candidate if the check fails or no match is found.
    """
    fallback = candidates[0]
    try:
        resp = client.request(
            "ssap://com.webos.applicationManager/listApps", {}, timeout=8.0
        )
    except SSAPError as exc:
        log("warning: could not verify app presence (%s)" % exc)
        return fallback
    if resp.get("type") == "error":
        log(
            "warning: listApps denied (%s); skipping app check"
            % resp.get("error", "unknown")
        )
        return fallback
    apps = (resp.get("payload") or {}).get("apps") or []
    installed_ids = set(
        a.get("id") for a in apps if isinstance(a, dict) and a.get("id")
    )
    for app_id, url_param_name in candidates:
        if app_id in installed_ids:
            log("confirmed app is installed: %s" % app_id)
            return app_id, url_param_name
    log(
        "warning: none of [%s] found in listApps; launch may do nothing"
        % ", ".join(a for a, _ in candidates)
    )
    return fallback


def launch_app(client, app_id, params):
    resp = client.request(
        "ssap://system.launcher/launch", {"id": app_id, "params": params}
    )
    if resp.get("type") == "error" or (resp.get("payload") or {}).get("returnValue") is not True:
        raise SSAPError("launch failed: %s" % resp.get("error", "unknown"))
    return resp.get("payload") or {}


def get_webos_version(client):
    """Query the TV's webOS version over SSAP and return it as a string.

    Uses 'major_ver'/'minor_ver' from getCurrentSWInformation to build a
    "<major>.<minor>" version string. Returns None if the query fails or
    the response doesn't contain usable version fields.

    TODO: use the detected version to choose which target app(s) to try.
    """
    try:
        resp = client.request(
            "ssap://com.webos.service.update/getCurrentSWInformation",
            {},
            timeout=8.0,
        )
    except SSAPError as exc:
        log("warning: could not query webOS version (%s)" % exc)
        return None
    if resp.get("type") == "error":
        log(
            "warning: getCurrentSWInformation denied (%s)"
            % resp.get("error", "unknown")
        )
        return None
    payload = resp.get("payload") or {}
    major_ver = payload.get("major_ver")
    minor_ver = payload.get("minor_ver")
    if major_ver and minor_ver:
        return "%s.%s" % (major_ver, minor_ver)
    if major_ver:
        return str(major_ver)
    log("warning: getCurrentSWInformation response missing version fields")
    return None


def local_ip_for_remote(remote_host, remote_port=80):
    """Choose a LAN-reachable local IPv4 for a given remote host."""
    remote_ip = socket.gethostbyname(remote_host)
    route_ip = _route_selected_local_ip(remote_ip, remote_port)

    # LunaDownloadMgr seems to choke on 127.0.0.1
    if route_ip and route_ip.startswith("127."):
        # Arbitrary external address; doesn't have to be reachable
        lan_ip = _route_selected_local_ip("8.8.8.8", 80)
        if lan_ip and not lan_ip.startswith("127."):
            log("detected loopback route; using LAN IP %s instead" % lan_ip)
            return lan_ip

    if route_ip:
        return route_ip
    raise RuntimeError("could not determine local IPv4 address")


def guess_local_ip(target_host=None, local_ip_override=None):
    """Resolve the local IPv4 to advertise, without necessarily knowing a target.

    Prefers an explicit override, then a route lookup toward target_host (if
    given), then falls back to the route toward an arbitrary external address.
    """
    if local_ip_override:
        return local_ip_override
    if target_host:
        return local_ip_for_remote(target_host)
    # Arbitrary external address; doesn't have to be reachable
    route_ip = _route_selected_local_ip("8.8.8.8", 80)
    if route_ip:
        return route_ip
    raise RuntimeError("could not determine local IPv4 address")


def _route_selected_local_ip(remote_ip, remote_port):
    """Ask the kernel route table which source IP it would pick."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect((remote_ip, remote_port))
            return sock.getsockname()[0]
        except OSError:
            return None


def required_files():
    return [ENTRY_PAGE, SHELL_SCRIPT] + list(SERVICE_FILES)


def resolve_wwwroot_path():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.join(script_dir, "wwwroot")
    return root_dir


def _embedded_meta_for(rel_path):
    if not isinstance(EMBEDDED_WWWROOT, dict):
        return None
    meta = EMBEDDED_WWWROOT.get(rel_path)
    if not isinstance(meta, dict):
        return None
    return meta


def _read_embedded_file(rel_path):
    meta = _embedded_meta_for(rel_path)
    if meta is None:
        return None
    encoding = meta.get("encoding", "base64")
    if encoding != "base64":
        raise RuntimeError(
            "unsupported embedded encoding for %s: %s" % (rel_path, encoding)
        )
    payload = meta.get("data", "")
    return base64.b64decode(payload)


def _read_filesystem_file(root_dir, rel_path):
    if not root_dir:
        return None
    abs_path = os.path.join(root_dir, rel_path.replace("/", os.sep))
    if not os.path.isfile(abs_path):
        return None
    with open(abs_path, "rb") as fh:
        return fh.read()


def _missing_required_files(
    tracked_files,
    root_dir,
    allow_embedded_assets,
    allow_filesystem_fallback,
):
    missing = []
    for rel_path in tracked_files:
        if allow_embedded_assets and _embedded_meta_for(rel_path) is not None:
            continue
        if (
            allow_filesystem_fallback
            and _read_filesystem_file(root_dir, rel_path) is not None
        ):
            continue
        missing.append(rel_path)
    return missing


def resolve_asset_root(asset_source, tracked_files):
    dir_root = resolve_wwwroot_path()
    if asset_source not in ASSET_SOURCES:
        raise RuntimeError(
            "invalid --asset-source '%s' (expected one of: %s)"
            % (asset_source, ", ".join(ASSET_SOURCES))
        )

    allow_embedded_assets = asset_source != ASSET_SOURCE_DIR
    allow_filesystem_fallback = asset_source != ASSET_SOURCE_EMBEDDED
    if allow_filesystem_fallback and not os.path.isdir(dir_root):
        dir_root = None

    missing = _missing_required_files(
        tracked_files,
        dir_root,
        allow_embedded_assets,
        allow_filesystem_fallback,
    )
    if missing:
        raise RuntimeError(
            "required files not found in %s: %s"
            % (
                (
                    "wwwroot"
                    if asset_source == ASSET_SOURCE_DIR
                    else (
                        "embedded data"
                        if asset_source == ASSET_SOURCE_EMBEDDED
                        else "embedded data or wwwroot"
                    )
                ),
                ", ".join(missing),
            )
        )

    if asset_source == ASSET_SOURCE_DIR:
        source_desc = ASSET_SOURCE_DIR
    elif allow_filesystem_fallback and dir_root is not None:
        source_desc = "embedded+dir"
    elif allow_filesystem_fallback:
        source_desc = "embedded"
    else:
        source_desc = ASSET_SOURCE_EMBEDDED
    return dir_root, source_desc, allow_embedded_assets, allow_filesystem_fallback


class RequestedFilesTracker:
    """Transfer diagnostics only; never interpreted as installation success."""
    def __init__(self, tracked_files):
        self._tracked = set(tracked_files)
        self._seen = set()
        self._lock = threading.Lock()

    def mark_seen(self, name):
        with self._lock:
            self._seen.add(name)

    def missing_files(self):
        with self._lock:
            return sorted(self._tracked - self._seen)


class SecureSession:
    def __init__(self, assets, peer_ip, debug=False):
        self.assets = dict(assets)
        self.peer_ip = peer_ip
        self.debug = debug
        self.token = secrets.token_hex(32)
        self.tracker = RequestedFilesTracker(self.assets)
        self.result = None
        self._event = threading.Event()
        self._lock = threading.Lock()

    def manifest(self):
        return json.dumps({
            "session": self.token,
            "files": sorted(name for name in self.assets if name != ENTRY_PAGE),
            "sha256": {name: sha256(data).hexdigest() for name, data in self.assets.items()},
            "package_sha256": HBC_SHA256,
        }, sort_keys=True).encode("utf-8")

    def receive_result(self, payload):
        if not isinstance(payload, dict) or set(payload) - {"ok", "root_verified", "phase", "error"}:
            raise ValueError("invalid result object")
        if type(payload.get("ok")) is not bool or type(payload.get("root_verified")) is not bool:
            raise ValueError("result must contain boolean status fields")
        if not isinstance(payload.get("phase"), str) or len(payload["phase"]) > 64:
            raise ValueError("invalid result phase")
        if "error" in payload and (not isinstance(payload["error"], str) or len(payload["error"]) > 500):
            raise ValueError("invalid result error")
        if payload["ok"] and (not payload["root_verified"] or self.tracker.missing_files()):
            raise ValueError("success requires completed transfers and a root check")
        with self._lock:
            if self.result is not None:
                raise ValueError("a terminal result was already received")
            self.result = payload
            self._event.set()

    def wait(self, timeout):
        if not self._event.wait(timeout):
            raise RuntimeError("no terminal installer result received before the deadline; inspect the TV before retrying or rebooting")
        if not self.result["ok"]:
            raise RuntimeError("TV installer failed in phase %s: %s" % (
                self.result["phase"], self.result.get("error", "unspecified failure")))
        return dict(self.result, reboot_verified=False)


def make_tracking_handler(session):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            # Bound the entire connection as well as individual socket reads.
            # A trickled TLS handshake or HTTP header must not hold a worker.
            self._deadline_timer = threading.Timer(15.0, self._expire)
            self._deadline_timer.daemon = True
            self._deadline_timer.start()
            try:
                self.request = self.server.tls_context.wrap_socket(self.request, server_side=True)
                super().setup()
            except BaseException:
                self._deadline_timer.cancel()
                raise

        def _expire(self):
            try:
                self.request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        def finish(self):
            try:
                super().finish()
            finally:
                self._deadline_timer.cancel()
                # wrap_socket detaches the original socket held by socketserver.
                # Close the SSL socket itself rather than the detached original.
                self.request.close()

        def log_message(self, *_):
            # Request URLs contain a per-run capability. Never log them.
            pass

        def _asset_name(self):
            if self.client_address[0] != session.peer_ip:
                return None
            path = urlsplit(self.path).path
            parts = path.split("/")
            if len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{64}", parts[1]):
                return None
            if not hmac.compare_digest(parts[1], session.token):
                return None
            return parts[2]

        def _headers(self, code, length=0, ctype="application/octet-stream"):
            self.send_response(code)
            self.send_header("Content-Length", str(length))
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            self.end_headers()

        def _serve(self, body):
            name = self._asset_name()
            if name == "manifest.json":
                data, ctype = session.manifest(), "application/json"
            elif name in session.assets:
                data = session.assets[name]
                ctype = "text/html; charset=utf-8" if name == ENTRY_PAGE else "application/octet-stream"
            else:
                self._headers(404)
                return
            self._headers(200, len(data), ctype)
            if body:
                self.wfile.write(data)
                self.wfile.flush()
                if name in session.assets:
                    session.tracker.mark_seen(name)

        def do_GET(self):
            self._serve(True)

        def do_HEAD(self):
            self._serve(False)

        def do_POST(self):
            if self._asset_name() != "result":
                self._headers(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                # Consume a bounded small error body so closing TLS does not
                # discard the error response because of unread application data.
                body = self.rfile.read(min(max(length, 0), 2049))
                if not 0 < length <= 2048 or self.headers.get("Transfer-Encoding"):
                    raise ValueError("invalid body length")
                if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
                    raise ValueError("invalid content type")
                if len(body) != length:
                    raise ValueError("incomplete body")
                payload = json.loads(body)
                session.receive_result(payload)
            except (ValueError, UnicodeError):
                self._headers(400)
                return
            self._headers(204)

    return Handler


class BoundedTLSServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, handler, context):
        self.tls_context = context
        self._slots = threading.BoundedSemaphore(8)
        super().__init__(address, handler)

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(5.0)
        return sock, address

    def process_request(self, request, address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self._slots.release()

    def handle_error(self, request, address):
        # Timeouts, invalid TLS and disconnects are expected on a LAN listener.
        pass


def start_http_server(session, bind_host, certfile, keyfile, preferred_port=8080):
    if not certfile or not keyfile:
        raise RuntimeError("HTTPS certificate and private key are required for executable assets")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile, keyfile)
    handler = make_tracking_handler(session)
    for port in (preferred_port, 0):
        try:
            server = BoundedTLSServer((bind_host, port), handler, context)
            break
        except OSError:
            if port == 0:
                raise
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def verify_payload_certificate(server, bind_ip, hostname):
    # Fail before pairing if this computer cannot validate the payload server's
    # chain, validity period and DNS name. The TV must also trust this CA.
    context = ssl.create_default_context()
    with socket.create_connection((bind_ip, server.server_port), 5.0) as raw:
        with context.wrap_socket(raw, server_hostname=hostname):
            pass


def _start_http_server(handler, bind_host, preferred_port):
    # Plain HTTP is retained exclusively for the fixed-text diagnostic.
    for port in (preferred_port, 0):
        try:
            server = ThreadingHTTPServer((bind_host, port), handler)
            break
        except OSError:
            if port == 0:
                raise
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class HTTPSOnlyRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != "https":
            raise RuntimeError("package download attempted a non-HTTPS redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def load_hbchannel_ipk(path=None):
    if path:
        with open(path, "rb") as stream:
            data = stream.read(MAX_PACKAGE_BYTES + 1)
    else:
        opener = build_opener(HTTPSOnlyRedirectHandler(), HTTPSHandler(context=ssl.create_default_context()))
        deadline = time.monotonic() + 120
        chunks, size = [], 0
        with opener.open(Request(HBC_URL, headers={"User-Agent": "SlopBro-security-fork"}), timeout=15) as stream:
            if stream.status != 200 or urlsplit(stream.geturl()).scheme != "https":
                raise RuntimeError("package download did not return an HTTPS 200 response")
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_PACKAGE_BYTES or time.monotonic() > deadline:
                    raise RuntimeError("package download exceeded its size or time limit")
                chunks.append(chunk)
        data = b"".join(chunks)
    if len(data) > MAX_PACKAGE_BYTES or not hmac.compare_digest(sha256(data).hexdigest(), HBC_SHA256):
        raise RuntimeError("Homebrew Channel package SHA-256 mismatch; no TV changes made")
    return data


def load_session_assets(asset_source, ipk_path=None):
    names = required_files()
    root, _, embedded, filesystem = resolve_asset_root(asset_source, names)
    assets = {}
    for name in names:
        data = _read_embedded_file(name) if embedded else None
        if data is None and filesystem:
            data = _read_filesystem_file(root, name)
        if data is None:
            raise RuntimeError("missing executable asset: %s" % name)
        assets[name] = data
    assets[HBC_NAME] = load_hbchannel_ipk(ipk_path)
    return assets


def build_self_hosted_url(payload_host, server_port, session, debug=False,
                          fake_service_path=DEFAULT_FAKE_SERVICE_PATH):
    query = {"fake-service-path": fake_service_path} if fake_service_path else {}
    if debug:
        query["debug"] = "1"
    url = "https://%s:%d/%s/%s" % (payload_host, server_port, session.token, ENTRY_PAGE)
    return url + ("?" + urlencode(query) if query else "")


def _validate_ipv4_address(ip_text):
    try:
        socket.inet_aton(ip_text)
    except OSError:
        return False
    return ip_text.count(".") == 3


TEST_CONNECTION_MESSAGE = "Here's your slop, bro!\n"


def make_test_connection_handler():
    """Build a minimal request handler that answers every request the same way.

    Used only to prove that the TV (or any browser on the LAN) can reach this
    host over HTTP; it doesn't serve any real payload/exploit files.
    """
    body = TEST_CONNECTION_MESSAGE.encode("utf-8")

    class TestConnectionHandler(BaseHTTPRequestHandler):
        def _send_headers(self, include_body):
            self.send_response(200)
            self.send_header("Content-type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if include_body:
                self.wfile.write(body)

        def do_GET(self):
            self._send_headers(True)

        def do_HEAD(self):
            self._send_headers(False)

        def log_message(self, format, *args):
            log("request from %s: %s" % (self.client_address[0], format % args))

    return TestConnectionHandler


def start_test_connection_server(bind_host="0.0.0.0", preferred_port=8080):
    handler = make_test_connection_handler()
    return _start_http_server(handler, bind_host, preferred_port)


def run_test_connection(host=None, local_ip_override=None):
    """Serve a fixed plain-text response to test basic HTTP connectivity only.

    Doesn't serve the real payload/exploit files and doesn't perform any SSAP
    pairing; just prints the URL to open manually in the TV's (or any) web
    browser to confirm that the TV can reach this host over HTTP. host is
    optional here since no SSAP connection or route-to-TV lookup is required.
    """
    if not host:
        log(
            "warning: no <tv-ip-or-host> given; the guessed local IP may be "
            "wrong (recommended: pass the TV's IP address)"
        )

    http_server = None
    url = None
    try:
        http_server = start_test_connection_server()
        local_ip = guess_local_ip(
            target_host=host, local_ip_override=local_ip_override
        )
        url = "http://%s:%d/" % (local_ip, http_server.server_port)
    except Exception as exc:
        die("could not start test HTTP server: %s" % exc)

    log("test mode: minimal HTTP connectivity check (no payload served)")
    log("open this URL in the TV's web browser to test HTTP connectivity:")
    log("    %s" % url)
    log("press Ctrl+C to stop")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("stopping test server")
    finally:
        if http_server is not None:
            try:
                http_server.shutdown()
            except Exception:
                pass
            try:
                http_server.server_close()
            except Exception:
                pass


def run_test_payload(host, tls_cert, tls_key, payload_host, hbchannel_ipk=None,
                     local_ip_override=None, asset_source=ASSET_SOURCE_AUTO,
                     debug=False, fake_service_path=DEFAULT_FAKE_SERVICE_PATH):
    assets = load_session_assets(asset_source, hbchannel_ipk)
    session = SecureSession(assets, socket.gethostbyname(host), debug)
    bind_ip = guess_local_ip(host, local_ip_override)
    server = start_http_server(session, bind_ip, tls_cert, tls_key)
    try:
        verify_payload_certificate(server, bind_ip, payload_host)
        url = build_self_hosted_url(payload_host, server.server_port, session, debug, fake_service_path)
        log("HTTPS payload diagnostic; no pairing or app launch is performed")
        log("Private session URL (do not share): %s" % url)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


def run(host, tls_cert, tls_key, payload_host, tv_cert_sha256,
        hbchannel_ipk=None, debug=False, asset_source=ASSET_SOURCE_AUTO,
        local_ip_override=None, webos_version_override=None,
        operation_timeout=180.0, fake_service_path=DEFAULT_FAKE_SERVICE_PATH):
    if not webos_version_override:
        raise RuntimeError("specify the TV's internal webOS version with --webos-version")
    candidates = target_apps_for_webos_version(TARGET_APPS, webos_version_override)
    if not candidates:
        raise RuntimeError("no configured apps for this internal webOS version")
    assets = load_session_assets(asset_source, hbchannel_ipk)
    session = SecureSession(assets, socket.gethostbyname(host), debug)
    bind_ip = guess_local_ip(host, local_ip_override)
    server = start_http_server(session, bind_ip, tls_cert, tls_key)
    client = None
    try:
        verify_payload_certificate(server, bind_ip, payload_host)
        page_url = build_self_hosted_url(payload_host, server.server_port, session, debug, fake_service_path)
        log("serving authenticated HTTPS assets on %s:%d for the selected TV" % (bind_ip, server.server_port))
        ws = WebSocket.connect(host, PORT_TLS, fingerprint=tv_cert_sha256)
        client = SSAPClient(ws)
        stored = load_client_key(host)
        key = client.register(stored, DEFAULT_MANIFEST)
        if key and key != stored:
            save_client_key(host, key)
        app_id, param = verify_app_present(client, candidates)
        log("launching %s; waiting for the installer's verified terminal result" % app_id)
        launch_app(client, app_id, {param: page_url})
        result = session.wait(operation_timeout)
        print(json.dumps(result, sort_keys=True))
        log("installer completed and current root was verified; reboot persistence was not tested")
        return result
    finally:
        if client is not None:
            client.close()
        server.shutdown()
        server.server_close()


def _fake_service_path_arg(value):
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", value) or ".." in value.split("/"):
        raise argparse.ArgumentTypeError("use an absolute path without spaces, traversal or shell metacharacters")
    return value


def _fingerprint_arg(value):
    normalized = value.replace(":", "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", normalized):
        raise argparse.ArgumentTypeError("expected a SHA-256 certificate fingerprint")
    return normalized


def _hostname_arg(value):
    labels = value.split(".")
    if len(value) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels):
        raise argparse.ArgumentTypeError("expected a DNS hostname or IPv4 address, without a URL or port")
    return value


def _positive_timeout(value):
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a positive timeout")
    if not 1 <= seconds <= 600:
        raise argparse.ArgumentTypeError("timeout must be between 1 and 600 seconds")
    return seconds


def main(argv=None):
    parser = argparse.ArgumentParser(description="Security-hardened SlopBro: verified HTTPS payloads and closed remote-access defaults")
    parser.add_argument("host", nargs="?", type=_hostname_arg, metavar="<tv-ip-or-host>")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--tls-cert", help="payload server's trusted certificate chain (PEM)")
    parser.add_argument("--tls-key", help="payload server's private key (PEM)")
    parser.add_argument("--payload-host", type=_hostname_arg, help="TV-resolvable hostname matching the trusted HTTPS certificate")
    parser.add_argument("--tv-cert-sha256", type=_fingerprint_arg, help="TV certificate fingerprint verified through a trusted channel")
    parser.add_argument("--hbchannel-ipk", help="local Homebrew Channel v0.7.3 package; its pinned SHA-256 is always checked")
    parser.add_argument("--local-ip", help="local IPv4 interface to bind")
    parser.add_argument("--webos-version", help="internal webOS version (for example 10), not an LG firmware number")
    parser.add_argument("--operation-timeout", type=_positive_timeout, default=180.0)
    parser.add_argument("--asset-source", choices=ASSET_SOURCES, default=ASSET_SOURCE_AUTO)
    parser.add_argument("--fake-service-path", type=_fake_service_path_arg, default=DEFAULT_FAKE_SERVICE_PATH)
    parser.add_argument("--no-fake-service-path", dest="fake_service_path", action="store_const", const="")
    parser.add_argument("--test-server", choices=TEST_SERVER_MODES)
    args = parser.parse_args(argv)
    if args.local_ip is not None and not _validate_ipv4_address(args.local_ip):
        parser.error("invalid --local-ip value")
    if args.test_server != TEST_SERVER_SIMPLE:
        for name in ("host", "tls_cert", "tls_key", "payload_host"):
            if not getattr(args, name):
                parser.error("%s is required for executable payloads" % name.replace("_", "-"))
        if args.test_server is None and (not args.tv_cert_sha256 or not args.webos_version):
            parser.error("--tv-cert-sha256 and --webos-version are required before pairing")
    try:
        if args.test_server == TEST_SERVER_SIMPLE:
            run_test_connection(args.host, local_ip_override=args.local_ip)
        elif args.test_server == TEST_SERVER_PAYLOAD:
            run_test_payload(args.host, args.tls_cert, args.tls_key, args.payload_host,
                hbchannel_ipk=args.hbchannel_ipk, local_ip_override=args.local_ip,
                asset_source=args.asset_source, debug=args.debug,
                fake_service_path=args.fake_service_path)
        else:
            run(args.host, args.tls_cert, args.tls_key, args.payload_host, args.tv_cert_sha256,
                hbchannel_ipk=args.hbchannel_ipk, local_ip_override=args.local_ip,
                asset_source=args.asset_source, debug=args.debug,
                fake_service_path=args.fake_service_path,
                webos_version_override=args.webos_version, operation_timeout=args.operation_timeout)
    except (OSError, RuntimeError, ValueError, SSAPError, WebSocketError) as exc:
        log("error: %s" % exc)
        return 1
    except KeyboardInterrupt:
        log("interrupted; inspect the TV's state before retrying")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
