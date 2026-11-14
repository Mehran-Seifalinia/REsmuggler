from socket import create_connection, socket, timeout as SocketTimeout
from ssl import CERT_NONE, create_default_context
from typing import Dict, Optional, Tuple

from lib.canary import _parse_status_line


class ConnectionAnalyzer:
    def __init__(self, host: str, port: int, use_tls: bool, timeout: float) -> None:
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout

    def _connect(self) -> socket:
        sock = create_connection((self.host, self.port), self.timeout)
        sock.settimeout(self.timeout)
        if self.use_tls:
            ctx = create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
        return sock

    @staticmethod
    def _status_of(data: Optional[bytes]) -> int:
        if not data:
            return -1
        status = _parse_status_line(data)
        return status if status is not None else -1

    def _send_single(self, payload: bytes) -> Tuple[Optional[bytes], bool]:
        closed = False
        sock = None
        try:
            try:
                sock = self._connect()
            except OSError:
                return None, True
            try:
                sock.sendall(payload)
            except OSError:
                return None, True
            try:
                data = sock.recv(65535)
            except SocketTimeout:
                data = None
            except OSError:
                data = None
                closed = True
            return data, closed
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _send_reused(self, payload_a: bytes, payload_b: bytes) -> Dict[str, object]:
        first: Optional[bytes] = None
        second: Optional[bytes] = None
        closed_before_second = False
        closed_after_second = False
        sock = None
        try:
            try:
                sock = self._connect()
            except OSError:
                return {"first": None, "second": None,
                        "closed_before_second": True,
                        "closed_after_second": True}
            try:
                sock.sendall(payload_a)
            except OSError:
                return {"first": None, "second": None,
                        "closed_before_second": True,
                        "closed_after_second": True}
            try:
                first = sock.recv(65535)
            except (SocketTimeout, OSError):
                first = None
            try:
                sock.sendall(payload_b)
            except OSError:
                closed_before_second = True
            else:
                try:
                    second = sock.recv(65535)
                except SocketTimeout:
                    second = None
                except OSError:
                    second = None
                    closed_after_second = True
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        return {
            "first": first,
            "second": second,
            "closed_before_second": closed_before_second,
            "closed_after_second": closed_after_second,
        }

    def analyze(self, payload_a: bytes, payload_b: bytes) -> Dict[str, object]:
        separate, separate_closed = self._send_single(payload_a)
        reused = self._send_reused(payload_a, payload_b)

        reused_first = reused["first"]
        reused_second = reused["second"]

        separate_ok = separate is not None and len(separate) > 0
        reused_ok = reused_first is not None and len(reused_first) > 0
        second_ok = reused_second is not None and len(reused_second) > 0

        first_status = self._status_of(reused_first)
        first_rejected = 400 <= first_status < 600
        closed_before_second = bool(reused["closed_before_second"])
        closed_after_second = bool(reused["closed_after_second"])
        separate_rejected = 400 <= self._status_of(separate) < 600

        if separate_ok and not reused_ok:
            classification = "normal_single"
        elif not separate_ok and reused_ok and second_ok:
            classification = "connection_locked"
        elif separate_ok and reused_ok and second_ok:
            classification = "normal_pipelining"
        elif reused_ok and closed_before_second:
            classification = "connection_closed_after_response"
        else:
            classification = "inconclusive"

        needs_escalation = (
            classification in ("connection_closed_after_response", "inconclusive")
            and (first_rejected or separate_rejected or closed_after_second)
        )

        return {
            "classification": classification,
            "separate_works": separate_ok,
            "reused_works": reused_ok,
            "second_response_received": second_ok,
            "first_response": reused_first,
            "second_response": reused_second,
            "first_status": first_status,
            "first_rejected": first_rejected,
            "separate_rejected": separate_rejected,
            "closed_before_second": closed_before_second,
            "closed_after_second": closed_after_second,
            "separate_closed": separate_closed,
            "is_connection_locked": classification == "connection_locked",
            "is_normal_pipelining": classification == "normal_pipelining",
            "needs_escalation": needs_escalation,
        }

    def is_connection_locked_desync(self, payload_a: bytes, payload_b: bytes) -> bool:
        result = self.analyze(payload_a, payload_b)
        return bool(result.get("is_connection_locked", False))
