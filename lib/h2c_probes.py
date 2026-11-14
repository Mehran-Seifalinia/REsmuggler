from socket import create_connection, socket
from ssl import CERT_NONE, create_default_context
from typing import Dict, List, Optional

from lib.canary import CanaryGenerator


class H2CProbe:
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

    def _send_recv(self, request: bytes) -> Optional[bytes]:
        sock = None
        data: Optional[bytes] = None
        try:
            try:
                sock = self._connect()
            except OSError:
                return None
            try:
                sock.sendall(request)
            except OSError:
                return None
            try:
                data = sock.recv(65535)
            except OSError:
                data = None
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        return data

    @staticmethod
    def _is_switching_protocols(data: Optional[bytes]) -> bool:
        if not data:
            return False
        head = data.split(b"\r\n", 1)[0]
        parts = head.split(b" ", 2)
        if len(parts) < 2:
            return False
        try:
            return int(parts[1]) == 101
        except ValueError:
            return False

    def probe_h2c_upgrade(self, endpoint: str, host_header: str) -> Dict[str, object]:
        request = (
            f"GET {endpoint} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: AAMAAABkAAQAAP__\r\n"
            f"\r\n"
        ).encode("latin-1")
        data = self._send_recv(request)
        upgraded = self._is_switching_protocols(data)
        return {
            "type": "H2C_UPGRADE",
            "response": data,
            "upgraded": upgraded,
            "canary_hit": False,
            "desync_suspected": False,
            "needs_escalation": upgraded,
            "raw": request,
        }

    def probe_h2c_smuggle(self, endpoint: str, host_header: str) -> Dict[str, object]:
        canary_path = self.canary.new_path()
        smuggled = (
            f"GET {canary_path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"\r\n"
        )
        request = (
            f"GET {endpoint} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: AAMAAABkAAQAAP__\r\n"
            f"\r\n"
            f"{smuggled}"
        ).encode("latin-1", errors="replace")
        data = self._send_recv(request)
        hit = self.canary.validate(data, canary_path)
        return {
            "type": "H2C_SMUGGLE",
            "canary_path": canary_path,
            "response": data,
            "canary_hit": hit,
            "desync_suspected": hit,
            "needs_escalation": False,
            "raw": request,
        }

    def run_all(self, endpoint: str, host_header: str) -> List[Dict[str, object]]:
        results = []
        for fn in (self.probe_h2c_upgrade, self.probe_h2c_smuggle):
            try:
                results.append(fn(endpoint, host_header))
            except OSError:
                results.append({"type": fn.__name__, "error": "connection_failed",
                                "desync_suspected": False,
                                "needs_escalation": False})
        return results
