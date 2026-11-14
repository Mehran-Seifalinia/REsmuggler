"""Raw-socket HTTP client with buffered response reading."""

from socket import create_connection, timeout as SocketTimeout, socket
from ssl import CERT_NONE, create_default_context, HAS_ALPN
from typing import List, Optional, Tuple


RECV_DATA = 0
RECV_TIMEOUT = 1
RECV_CLOSED = 2

DEFAULT_MAX_BYTES = 1_048_576


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
            data = self._sock.recv(65535)
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
        while total < max_bytes:
            try:
                chunk = self._sock.recv(min(65535, max_bytes - total))
            except SocketTimeout:
                break
            except OSError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if self._looks_complete(b"".join(chunks)):
                break
        if not chunks:
            return RECV_TIMEOUT, None
        return RECV_DATA, b"".join(chunks)

    @staticmethod
    def _looks_complete(data: bytes) -> bool:
        if b"\r\n\r\n" not in data:
            return False
        head, _, body = data.partition(b"\r\n\r\n")
        lower_head = head.lower()
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                try:
                    need = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    return True
                return len(body) >= need
        if b"transfer-encoding:" in lower_head and b"chunked" in lower_head:
            return body.rstrip(b"\r\n").endswith(b"0")
        return True

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