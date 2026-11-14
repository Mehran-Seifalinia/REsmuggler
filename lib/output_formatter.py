from csv import QUOTE_MINIMAL, writer as csv_writer
from datetime import datetime, timezone
from io import StringIO
from json import dumps
from typing import Dict, List
from uuid import uuid4


CSV_COLUMNS = ["kind", "name", "payload", "evidence", "canary_path",
               "confidence", "heuristic", "timestamp"]


class OutputFormatter:
    def __init__(self, target: str, config: str, method: str) -> None:
        self.scan_id = str(uuid4())
        self.target = target
        self.config = config
        self.method = method
        self.findings: List[Dict[str, object]] = []
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.targets_tested = 0

    def add_finding(self, kind: str, name: str, payload: str = "",
                    evidence: str = "", canary_path: str = "",
                    confidence: float = 0.0, heuristic: bool = False) -> None:
        self.findings.append({
            "kind": kind,
            "name": name,
            "payload": payload,
            "evidence": evidence,
            "canary_path": canary_path,
            "confidence": confidence,
            "heuristic": heuristic,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def to_json(self) -> str:
        confirmed = sum(1 for f in self.findings if not f.get("heuristic"))
        heuristic = sum(1 for f in self.findings if f.get("heuristic"))
        return dumps({
            "scan_id": self.scan_id,
            "target": self.target,
            "config": self.config,
            "method": self.method,
            "started_at": self.started_at,
            "summary": {
                "findings_count": len(self.findings),
                "confirmed_count": confirmed,
                "heuristic_count": heuristic,
                "targets_tested": self.targets_tested,
            },
            "findings": self.findings,
        }, indent=2)

    def to_csv(self) -> str:
        buf = StringIO()
        writer = csv_writer(buf, quoting=QUOTE_MINIMAL, lineterminator="\n")
        writer.writerow(CSV_COLUMNS)
        for f in self.findings:
            writer.writerow([
                f.get("kind", ""),
                f.get("name", ""),
                f.get("payload", ""),
                f.get("evidence", ""),
                f.get("canary_path", ""),
                f.get("confidence", 0.0),
                f.get("heuristic", False),
                f.get("timestamp", ""),
            ])
        return buf.getvalue()

    def exit_code(self) -> int:
        return 1 if any(not f.get("heuristic") for f in self.findings) else 0


class BatchOutputFormatter:
    def __init__(self, config: str, method: str) -> None:
        self.scan_id = str(uuid4())
        self.config = config
        self.method = method
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.targets: List[Dict[str, object]] = []

    def add_target(self, target: str, findings: List[Dict[str, object]]) -> None:
        confirmed = sum(1 for f in findings if not f.get("heuristic"))
        heuristic = sum(1 for f in findings if f.get("heuristic"))
        self.targets.append({
            "target": target,
            "findings_count": len(findings),
            "confirmed_count": confirmed,
            "heuristic_count": heuristic,
            "findings": findings,
        })

    def to_json(self) -> str:
        total = sum(t["findings_count"] for t in self.targets)
        confirmed = sum(t["confirmed_count"] for t in self.targets)
        heuristic = sum(t["heuristic_count"] for t in self.targets)
        return dumps({
            "scan_id": self.scan_id,
            "config": self.config,
            "method": self.method,
            "started_at": self.started_at,
            "summary": {
                "targets_tested": len(self.targets),
                "total_findings": total,
                "confirmed_findings": confirmed,
                "heuristic_findings": heuristic,
                "vulnerable_targets": sum(1 for t in self.targets
                                          if t["confirmed_count"] > 0),
            },
            "targets": self.targets,
        }, indent=2)

    def to_csv(self) -> str:
        buf = StringIO()
        writer = csv_writer(buf, quoting=QUOTE_MINIMAL, lineterminator="\n")
        writer.writerow(["target"] + CSV_COLUMNS)
        for t in self.targets:
            for f in t["findings"]:
                writer.writerow([
                    t["target"],
                    f.get("kind", ""),
                    f.get("name", ""),
                    f.get("payload", ""),
                    f.get("evidence", ""),
                    f.get("canary_path", ""),
                    f.get("confidence", 0.0),
                    f.get("heuristic", False),
                    f.get("timestamp", ""),
                ])
        return buf.getvalue()

    def exit_code(self) -> int:
        return 1 if any(t["confirmed_count"] > 0 for t in self.targets) else 0
