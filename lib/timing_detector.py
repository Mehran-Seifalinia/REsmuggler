from time import monotonic
from typing import Dict, List

from lib.http_client import HTTPClient


def _parse_status(data):
    if not data:
        return -1
    first_line = data.split(b"\r\n", 1)[0]
    parts = first_line.split(b" ", 2)
    if len(parts) < 2:
        return -1
    try:
        return int(parts[1])
    except ValueError:
        return -1


def _has_connection_close(data):
    if not data:
        return False
    header_end = data.find(b"\r\n\r\n")
    if header_end < 0:
        return False
    headers = data[:header_end].lower()
    for line in headers.split(b"\r\n")[1:]:
        if line.startswith(b"connection:"):
            value = line.split(b":", 1)[1].strip()
            if b"close" in value:
                return True
    return False


class TimingDetector:
    def __init__(self, host: str, port: int, use_tls: bool, timeout: float) -> None:
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.attempts = 5

    def _measure(self, payload: bytes, repeat: int) -> List[Dict[str, object]]:
        samples: List[Dict[str, object]] = []
        for _ in range(repeat):
            client = HTTPClient(
                host=self.host, port=self.port,
                use_tls=self.use_tls, timeout=self.timeout,
            )
            try:
                client.connect()
                start = monotonic()
                client.send(payload)
                status, data = client.receive_full()
                elapsed = monotonic() - start
                samples.append({
                    "elapsed": elapsed,
                    "data": data,
                    "status": _parse_status(data),
                    "connection_close": _has_connection_close(data),
                    "error": False,
                })
            except OSError:
                samples.append({"elapsed": -1.0, "data": None, "status": -1,
                                "connection_close": False, "error": True})
            finally:
                client.close()
        return samples

    def _baseline(self, endpoint: str, host_header: str) -> float:
        payload = (
            f"POST {endpoint} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
        ).encode("latin-1")
        samples = self._measure(payload, repeat=3)
        valid = [s["elapsed"] for s in samples
                 if not s["error"] and s["elapsed"] > 0]
        return sum(valid) / len(valid) if valid else 1.0

    def _run_probe(self, payload: bytes, endpoint: str, host_header: str,
                   label: str) -> Dict[str, object]:
        samples = self._measure(payload, repeat=self.attempts)
        baseline = self._baseline(endpoint, host_header)
        threshold = max(baseline * 4.0, baseline + 2.0)
        valid = [s for s in samples if not s["error"] and s["elapsed"] > 0]
        stalls = sum(1 for s in valid if s["elapsed"] > threshold)
        fast_rejects = sum(
            1 for s in valid
            if s["status"] == 503
            and s["connection_close"]
            and s["elapsed"] < baseline * 0.5
        )
        times = [s["elapsed"] for s in samples]
        statuses = [s["status"] for s in samples]
        desync = len(valid) >= 3 and (stalls >= 3 or fast_rejects >= 3)
        return {
            "type": label,
            "times": times,
            "statuses": statuses,
            "baseline": baseline,
            "threshold": threshold,
            "stalls": stalls,
            "fast_rejects": fast_rejects,
            "attempts": len(valid),
            "desync_suspected": desync,
            "heuristic": True,
            "raw": payload,
        }

    def probe_clte_timing(self, endpoint: str, host_header: str) -> Dict[str, object]:
        payload = (
            f"POST {endpoint} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"A"
        ).encode("latin-1")
        return self._run_probe(payload, endpoint, host_header, "CL.TE_TIMING")

    def probe_tecl_timing(self, endpoint: str, host_header: str) -> Dict[str, object]:
        payload = (
            f"POST {endpoint} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Content-Length: 200\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode("latin-1")
        return self._run_probe(payload, endpoint, host_header, "TE.CL_TIMING")

    def run_all(self, endpoint: str, host_header: str) -> List[Dict[str, object]]:
        results = []
        for fn in (self.probe_clte_timing, self.probe_tecl_timing):
            try:
                results.append(fn(endpoint, host_header))
            except OSError:
                results.append({"type": fn.__name__, "error": "connection_failed",
                                "desync_suspected": False, "heuristic": True})
        return results
