"""Timing-based desync detection (heuristic only)."""

from time import monotonic
from typing import Dict, List

from lib.http_client import HTTPClient


class TimingDetector:
    def __init__(self, host: str, port: int, use_tls: bool, timeout: float) -> None:
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.attempts = 5

    def _measure(self, payload: bytes, repeat: int) -> List[float]:
        times = []
        for _ in range(repeat):
            client = HTTPClient(
                host=self.host, port=self.port,
                use_tls=self.use_tls, timeout=self.timeout,
            )
            try:
                client.connect()
                start = monotonic()
                client.send(payload)
                client.receive()
                elapsed = monotonic() - start
                times.append(elapsed)
            except OSError:
                times.append(-1.0)
            finally:
                client.close()
        return times

    def _baseline(self, endpoint: str, host_header: str) -> float:
        payload = (
            f"POST {endpoint} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
        ).encode("latin-1")
        times = self._measure(payload, repeat=3)
        valid = [t for t in times if t > 0]
        return sum(valid) / len(valid) if valid else 1.0

    def _run_probe(self, payload: bytes, endpoint: str, host_header: str,
                   label: str) -> Dict[str, object]:
        times = self._measure(payload, repeat=self.attempts)
        baseline = self._baseline(endpoint, host_header)
        threshold = max(baseline * 4.0, baseline + 2.0)
        valid = [t for t in times if t > 0]
        stalls = sum(1 for t in valid if t > threshold)
        return {
            "type": label,
            "times": times,
            "baseline": baseline,
            "threshold": threshold,
            "stalls": stalls,
            "attempts": len(valid),
            "desync_suspected": len(valid) >= 3 and stalls >= 3,
            "heuristic": True,
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