#!/usr/bin/env python3
import argparse
import hashlib
import http.client
import json
import re
import socket
import ssl
import struct
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


MAX_VERIFY_BODY = 1024 * 1024
MAX_EARLY_RESPONSE = 65536


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def load_request(path, marker, host):
    raw = path.read_bytes()
    if b"${marker}" not in raw:
        raise ValueError(f"${{marker}} is missing from {path}")
    raw = raw.replace(b"${marker}", marker.encode("ascii"))
    linebreak = b"\r\n" if raw.partition(b"\n")[0].endswith(b"\r") else b"\n"
    head, sep, body = raw.partition(linebreak * 2)
    if not sep:
        if not raw.endswith(linebreak):
            raise ValueError(f"request has no header terminator: {path}")
        head, body = raw[:-len(linebreak)], b""
    lines = head.split(linebreak)
    parts = lines[0].split(b" ")
    if len(parts) != 3 or parts[2] != b"HTTP/1.1":
        raise ValueError(f"expected HTTP/1.1 request line: {path}")
    method, target = parts[:2]
    if not re.fullmatch(rb"[A-Z]+", method) or not target.startswith(b"/") or target.startswith(b"//"):
        raise ValueError(f"invalid request line: {path}")
    headers = []
    names = set()
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if not colon or not re.fullmatch(rb"[A-Za-z0-9-]+", name):
            raise ValueError(f"invalid request header: {path}")
        lower = name.lower()
        if lower == b"transfer-encoding":
            raise ValueError("chunked requests are not supported")
        if lower not in (b"content-length", b"connection"):
            headers.append((name, value.strip()))
            names.add(lower)
    if b"host" not in names:
        headers.append((b"Host", host.encode("ascii")))
    headers.append((b"Connection", b"close"))
    if body:
        headers.append((b"Content-Length", str(len(body)).encode("ascii")))
    normalized = method + b" " + target + b" HTTP/1.1\r\n"
    normalized += b"\r\n".join(name + b": " + value for name, value in headers) + b"\r\n\r\n"
    return method, normalized, body


def tls_context(insecure):
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def open_socket(origin, timeout, context):
    sock = socket.create_connection((origin.hostname, origin.port or (443 if origin.scheme == "https" else 80)), timeout)
    sock.settimeout(timeout)
    if origin.scheme == "https":
        try:
            return context.wrap_socket(sock, server_hostname=origin.hostname)
        except Exception:
            sock.close()
            raise
    return sock


def verify(origin, request, marker, timeout, context, status, mode):
    method, head, body = load_request(request, marker, origin.netloc)
    if method != b"GET" or body:
        raise ValueError("verification request must be a bodyless GET")
    sock = open_socket(origin, timeout, context)
    response = None
    try:
        sock.sendall(head)
        response = http.client.HTTPResponse(sock)
        response.begin()
        payload = response.read(MAX_VERIFY_BODY + 1)
        if len(payload) > MAX_VERIFY_BODY:
            raise ValueError("verification response exceeds 1 MiB")
        matched = response.status == status and (mode == "status" or marker.encode("ascii") in payload)
        return {"status": response.status, "body_sha256": sha256(payload), "matched": matched}
    finally:
        if response is not None:
            response.close()
        sock.close()


def trial(origin, request, marker, timeout, context, cut, delay_ms, close_mode, elapsed):
    method, head, body = load_request(request, marker, origin.netloc)
    if cut == "after-headers" and not body:
        raise ValueError("after-headers requires a request body")
    sock = open_socket(origin, timeout, context)
    events = [{"event": "connected", "ms": elapsed()}]
    received = bytearray()
    server_closed = False
    receive_error = None
    try:
        sock.sendall(head)
        events.append({"event": "headers_sent", "ms": elapsed()})
        if cut != "after-headers":
            sock.sendall(body)
            events.append({"event": "body_sent", "ms": elapsed()})
        if cut == "delay":
            deadline = time.monotonic() + delay_ms / 1000
            while len(received) < MAX_EARLY_RESPONSE:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                try:
                    chunk = sock.recv(MAX_EARLY_RESPONSE - len(received))
                except socket.timeout:
                    break
                except OSError as exc:
                    server_closed = True
                    receive_error = type(exc).__name__
                    break
                if not chunk:
                    server_closed = True
                    break
                received.extend(chunk)
        events.append({"event": "server_closed" if server_closed else "client_cut", "ms": elapsed()})
        if close_mode == "rst" and not server_closed:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        elif close_mode == "fin" and not server_closed:
            sock.shutdown(socket.SHUT_WR)
    finally:
        sock.close()
    status_line = bytes(received).partition(b"\r\n")[0]
    match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?: .*)?", status_line)
    return {
        "method": method.decode("ascii"),
        "request_sha256": sha256(head + body),
        "sent_body_bytes": 0 if cut == "after-headers" else len(body),
        "response_bytes_before_cut": len(received),
        "response_sha256_before_cut": sha256(received),
        "response_status_before_cut": int(match.group(1)) if match else None,
        "client_cut": not server_closed,
        "server_closed_before_cut": server_closed,
        "receive_error": receive_error,
        "events": events,
    }


def run(args, report):
    origin = urlsplit(args.origin)
    if (origin.scheme not in ("http", "https") or not origin.hostname or
            origin.path not in ("", "/") or origin.query or origin.fragment or
            origin.username or origin.password):
        raise ValueError("--origin must be an HTTP origin")
    if args.cut == "delay" and args.delay_ms <= 0:
        raise ValueError("--delay-ms must be positive with --cut delay")
    if args.verify_window <= 0 or args.verify_interval <= 0 or args.timeout <= 0:
        raise ValueError("timeouts and intervals must be positive")
    if not 100 <= args.verify_status <= 599:
        raise ValueError("--verify-status must be a three-digit HTTP status")
    marker = args.marker or uuid.uuid4().hex
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", marker):
        raise ValueError("marker must contain only letters, digits, dots, underscores, or hyphens")
    context = tls_context(args.insecure)
    start = time.monotonic_ns()
    elapsed = lambda: round((time.monotonic_ns() - start) / 1_000_000, 3)
    report.update({
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "origin": args.origin,
        "marker": marker,
        "cut": args.cut,
        "close": args.close,
        "verification": [],
    })
    report["baseline"] = verify(origin, args.verify, marker, args.timeout, context, args.verify_status, args.verify_mode)
    if report["baseline"]["matched"]:
        raise ValueError("verification already matches before the trial")
    report["trial"] = trial(origin, args.request, marker, args.timeout, context,
                            args.cut, args.delay_ms, args.close, elapsed)
    deadline = time.monotonic() + args.verify_window
    while True:
        try:
            result = verify(origin, args.verify, marker, args.timeout, context,
                            args.verify_status, args.verify_mode)
        except (OSError, http.client.HTTPException) as exc:
            result = {"error": type(exc).__name__}
        result["ms"] = elapsed()
        report["verification"].append(result)
        if result.get("matched"):
            report["state_observed_on_readback"] = True
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            report["state_observed_on_readback"] = False
            break
        time.sleep(min(args.verify_interval, remaining))


def main():
    parser = argparse.ArgumentParser(description="Cut an HTTP request and check its state through a separate GET")
    parser.add_argument("--origin", required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--verify", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cut", choices=("after-headers", "after-body", "delay"), default="after-body")
    parser.add_argument("--delay-ms", type=int, default=0)
    parser.add_argument("--close", choices=("rst", "fin"), default="rst")
    parser.add_argument("--marker")
    parser.add_argument("--verify-mode", choices=("marker", "status"), default="marker")
    parser.add_argument("--verify-status", type=int, default=200)
    parser.add_argument("--verify-window", type=float, default=5)
    parser.add_argument("--verify-interval", type=float, default=0.25)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()
    report = {}
    with args.out.open("x") as output:
        try:
            run(args, report)
        except Exception as exc:
            report["error"] = type(exc).__name__
            print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        json.dump(report, output, indent=2)
        output.write("\n")
    print(args.out)
    return 2 if "error" in report else 0


if __name__ == "__main__":
    sys.exit(main())
