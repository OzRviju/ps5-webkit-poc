#!/usr/bin/env python3
"""
Multipart x-mixed-replace fuzzer server for PS5 WebKit CurlMultipartHandle.

Target: CurlMultipartHandle::findBoundary() / parseHeadersIfPossible()
in Source/WebCore/platform/network/curl/CurlMultipartHandle.cpp

Serves malformed multipart/x-mixed-replace responses designed to trigger
OOB reads/writes in the boundary parser.

Usage:
    python multipart-server.py [port]
    Default port: 8888

Then point the PS5 browser to: http://YOUR_PC_IP:8888/fuzz
Or use multipart-fuzzer.html with SERVER set to this address.
"""

import http.server
import random
import struct
import os
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8888


def random_bytes(n):
    return os.urandom(n)


def build_normal_boundary():
    return f"----boundary{random.randint(0, 999999):06d}"


# Mutation strategies for multipart responses
STRATEGIES = []


def strategy(fn):
    STRATEGIES.append(fn)
    return fn


@strategy
def truncated_header(boundary):
    """Part with header truncated mid-line (no CRLFCRLF terminator)"""
    resp = f"--{boundary}\r\nContent-Type: image/jpe".encode()
    return resp  # No closing \r\n\r\n


@strategy
def missing_crlf_before_boundary(boundary):
    """Boundary not preceded by CRLF — parser must handle"""
    part1 = f"--{boundary}\r\nContent-Type: text/plain\r\n\r\nHello".encode()
    # Missing \r\n before next boundary
    part2 = f"--{boundary}\r\nContent-Type: text/plain\r\n\r\nWorld".encode()
    close = f"\r\n--{boundary}--\r\n".encode()
    return part1 + part2 + close


@strategy
def lf_only_boundaries(boundary):
    """Use LF instead of CRLF (the parser has fallback for this)"""
    part = f"--{boundary}\nContent-Type: text/plain\n\ndata\n--{boundary}--\n".encode()
    return part


@strategy
def boundary_size_0xFFFFFFFF(boundary):
    """Extremely long boundary string — test allocation"""
    long_boundary = "A" * 8192
    header = f"Content-Type: multipart/x-mixed-replace; boundary={long_boundary}\r\n\r\n"
    body = f"--{long_boundary}\r\nContent-Type: text/plain\r\n\r\ntest\r\n--{long_boundary}--\r\n"
    return header.encode() + body.encode(), long_boundary


@strategy
def huge_header_block(boundary):
    """Header block > 300KB (the maxHeaderSize limit)"""
    huge_header = "X-Fuzz: " + "A" * (301 * 1024) + "\r\n"
    part = f"--{boundary}\r\n{huge_header}\r\n\r\ndata\r\n--{boundary}--\r\n"
    return part.encode()


@strategy
def nested_boundary_in_data(boundary):
    """Data that contains the boundary string (confuse parser)"""
    fake_data = f"some data --{boundary} more data --{boundary}-- end"
    part = f"--{boundary}\r\nContent-Type: text/plain\r\n\r\n{fake_data}\r\n--{boundary}--\r\n"
    return part.encode()


@strategy
def close_delimiter_without_crlf(boundary):
    """Close delimiter not followed by CRLF"""
    part = f"--{boundary}\r\nContent-Type: text/plain\r\n\r\ndata\r\n--{boundary}--"
    return part.encode()  # No trailing \r\n


@strategy
def empty_parts(boundary):
    """Multiple empty parts (zero-length body)"""
    parts = ""
    for _ in range(100):
        parts += f"--{boundary}\r\nContent-Type: text/plain\r\n\r\n"
    parts += f"--{boundary}--\r\n"
    return parts.encode()


@strategy
def transport_padding(boundary):
    """Transport padding (spaces/tabs) after boundary"""
    part = f"--{boundary}   \t  \r\nContent-Type: text/plain\r\n\r\ndata\r\n--{boundary}--\r\n"
    return part.encode()


@strategy
def binary_data_in_body(boundary):
    """Binary data in body (random bytes including null bytes)"""
    binary = random_bytes(4096)
    header = f"--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n".encode()
    footer = f"\r\n--{boundary}--\r\n".encode()
    return header + binary + footer


@strategy
def partial_boundary_at_end(boundary):
    """Data ends with partial boundary match"""
    partial = f"--{boundary}"[:len(boundary) // 2]
    part = f"--{boundary}\r\nContent-Type: text/plain\r\n\r\ndata{partial}".encode()
    return part  # Truncated — no close delimiter


@strategy
def rapid_parts(boundary):
    """Hundreds of tiny parts (stress test cleanup/alloc)"""
    parts = ""
    for i in range(500):
        parts += f"--{boundary}\r\nContent-Type: text/plain\r\n\r\n{i}\r\n"
    parts += f"--{boundary}--\r\n"
    return parts.encode()


@strategy
def null_bytes_in_boundary(_):
    """Boundary containing null bytes"""
    boundary = "bound\x00ary123"
    ct = f"multipart/x-mixed-replace; boundary={boundary}"
    body = f"--{boundary}\r\nContent-Type: text/plain\r\n\r\ntest\r\n--{boundary}--\r\n"
    return body.encode(), boundary, ct


@strategy
def double_close_delimiter(boundary):
    """Two close delimiters"""
    part = f"--{boundary}\r\nContent-Type: text/plain\r\n\r\ndata\r\n--{boundary}--\r\n--{boundary}--\r\n"
    return part.encode()


class FuzzHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/fuzz'):
            self.send_fuzzed_multipart()
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(b'<h1>Multipart Fuzzer Server</h1><p>Use /fuzz endpoint</p>')

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET')
        self.end_headers()

    def send_fuzzed_multipart(self):
        boundary = build_normal_boundary()
        strategy = random.choice(STRATEGIES)

        result = strategy(boundary)

        custom_ct = None
        if isinstance(result, tuple):
            if len(result) == 3:
                body, boundary, custom_ct = result
            else:
                body, boundary = result
        else:
            body = result

        content_type = custom_ct or f'multipart/x-mixed-replace; boundary={boundary}'

        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()

        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

        print(f"[{strategy.__name__}] boundary={boundary[:40]}... size={len(body)}")

    def log_message(self, format, *args):
        pass  # Suppress default logging


if __name__ == '__main__':
    print(f"Starting multipart fuzzer server on port {PORT}")
    print(f"Point PS5 browser to: http://YOUR_PC_IP:{PORT}/fuzz")
    print(f"Or use multipart-fuzzer.html")
    print(f"Strategies: {len(STRATEGIES)}")
    server = http.server.HTTPServer(('0.0.0.0', PORT), FuzzHandler)
    server.serve_forever()
