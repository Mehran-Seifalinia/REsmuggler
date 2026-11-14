from socket import (HAS_IPV6, create_connection, socket,
                    timeout as SocketTimeout)
from ssl import CERT_NONE, HAS_ALPN, create_default_context
from typing import List, Optional, Tuple


RECV_DATA = 0
RECV_TIMEOUT = 1
RECV_CLOSED = 2

DEFAULT_MAX_BYTES = 1_048_576
RECV_CHUNK = 65535


def _response_complete(data: bytes) -> bool:
    if b"\r\n\r\n" not in data:
        return False
    head, _, body = data.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0]
    parts = status_line.split(b" ", 2)
    if len(parts) < 2:
        return False
    try:
        status = int(parts[1])
    except ValueError:
        return False
    if 100 <= status < 200:
        return False
    lower_head = head.lower()
    for line in head.split(b"\r\n")[1:]:
        lower = line.lower()
        if lower.startswith(b"content-length:"):
            try:
                need = int(line.split(b":", 1)[1].strip())
            except ValueError:
                return True
            return len(body) >= need
    if b"transfer-encoding:" in lower_head and b"chunked" in lower_head:
        return body.endswith(b"\r\n0\r\n\r\n") or body.rstrip(b"\r\n") == b"0"
    return True


class HTTPClient:
    def __init__(self, host: str, port: int, use_tls: bool, timeout: float,
                 alpn: Optional[List[str]] = None) -> None:
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.alpn = alpn
        self._sock: Optional[socket] = None
        self.selected_alpn: Optional[str] = None

    def connect(self) -> None:
        sock = create_connection((self.host, self.port), self.timeout)
        sock.settimeout(self.timeout)
        if self.use_tls:
            ctx = create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = CERT_NONE
            if self.alpn and HAS_ALPN:
                ctx.set_alpn_protocols(self.alpn)
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
            if HAS_ALPN:
                self.selected_alpn = sock.selected_alpn_protocol()
        self._sock = sock

    def send(self, data: bytes) -> None:
        if self._sock is None:
            raise RuntimeError("socket is not connected")
        self._sock.sendall(data)

    def receive(self) -> Tuple[int, Optional[bytes]]:
        if self._sock is None:
            return RECV_CLOSED, None
        try:
            data = self._sock.recv(RECV_CHUNK)
        except SocketTimeout:
            return RECV_TIMEOUT, None
        except OSError:
            return RECV_CLOSED, None
        if not data:
            return RECV_CLOSED, None
        return RECV_DATA, data

    def receive_full(self, max_bytes: int = DEFAULT_MAX_BYTES) -> Tuple[int, Optional[bytes]]:
        if self._sock is None:
            return RECV_CLOSED, None
        chunks: List[bytes] = []
        total = 0
        closed = False
        while total < max_bytes:
            try:
                chunk = self._sock.recv(min(RECV_CHUNK, max_bytes - total))
            except SocketTimeout:
                break
            except OSError:
                closed = True
                break
            if not chunk:
                closed = True
                break
            chunks.append(chunk)
            total += len(chunk)
            if _response_complete(b"".join(chunks)):
                break
        if not chunks:
            return (RECV_CLOSED if closed else RECV_TIMEOUT), None
        return RECV_DATA, b"".join(chunks)

    @staticmethod
    def _looks_complete(data: bytes) -> bool:
        return _response_complete(data)

    def receive_all(self) -> List[bytes]:
        responses = []
        while True:
            status, data = self.receive()
            if status == RECV_DATA and data is not None:
                responses.append(data)
            else:
                break
        return responses

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
