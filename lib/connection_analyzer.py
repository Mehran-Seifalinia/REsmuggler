"""Distinguishes connection-locked smuggling from normal pipelining."""

from socket import create_connection
from ssl import CERT_NONE, create_default_context
from typing import Dict, Optional, Tuple


class ConnectionAnalyzer:
    def __init__(self, host: str, port: int, use_tls: bool, timeout: float) -> None:
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout

    def _connect(self):
        sock = create_connection((self.host, self.port), self.timeout)
        sock.settimeout(self.timeout)
        if self.use_tls:
            ctx = create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
        return sock

    def _send_single(self, payload: bytes) -> Optional[bytes]:
        try:
            sock = self._connect()
            sock.sendall(payload)
            try:
                data = sock.recv(65535)
            except OSError:
                data = None
            sock.close()
            return data
        except OSError:
            return None

    def _send_reused(self, payload_a: bytes, payload_b: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
        first = None
        second = None
        try:
            sock = self._connect()
            sock.sendall(payload_a)
            try:
                first = sock.recv(65535)
            except OSError:
                first = None
            sock.sendall(payload_b)
            try:
                second = sock.recv(65535)
            except OSError:
                second = None
            sock.close()
        except OSError:
            pass
        return first, second

    def analyze(self, payload_a: bytes, payload_b: bytes) -> Dict[str, object]:
        """Classify behavior: normal pipelining, connection-locked, or clean.

        Per James Kettle's research, if a PoC only works on a reused
        connection, it is probably a false positive unless it is a
        connection-locked vulnerability.
        """
        separate = self._send_single(payload_a)
        reused_first, reused_second = self._send_reused(payload_a, payload_b)

        separate_ok = separate is not None and len(separate) > 0
        reused_ok = reused_first is not None and len(reused_first) > 0
        second_ok = reused_second is not None and len(reused_second) > 0

        if separate_ok and not reused_ok:
            classification = "normal_single"
        elif not separate_ok and reused_ok and second_ok:
            classification = "connection_locked"
        elif separate_ok and reused_ok and second_ok:
            classification = "normal_pipelining"
        else:
            classification = "inconclusive"

        return {
            "classification": classification,
            "separate_works": separate_ok,
            "reused_works": reused_ok,
            "second_response_received": second_ok,
            "is_connection_locked": classification == "connection_locked",
            "is_normal_pipelining": classification == "normal_pipelining",
        }

    def is_connection_locked_desync(self, payload_a: bytes, payload_b: bytes) -> bool:
        result = self.analyze(payload_a, payload_b)
        return result.get("is_connection_locked", False)