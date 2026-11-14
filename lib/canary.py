from random import randint
from typing import List, Optional


CANARY_PREFIX = "canary_"
MAX_RESPONSES = 16


def _parse_status_line(head: bytes) -> Optional[int]:
    first_line = head.split(b"\r\n", 1)[0]
    parts = first_line.split(b" ", 2)
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def split_http_responses(blob: bytes) -> List[bytes]:
    responses: List[bytes] = []
    remaining = blob
    while remaining and len(responses) < MAX_RESPONSES:
        header_end = remaining.find(b"\r\n\r\n")
        if header_end < 0:
            responses.append(remaining)
            break
        head = remaining[:header_end]
        body_need = 0
        chunked = False
        status = _parse_status_line(head)
        informational = status is not None and 100 <= status < 200
        if not informational:
            for line in head.split(b"\r\n")[1:]:
                lower = line.lower()
                if lower.startswith(b"content-length:"):
                    try:
                        body_need = int(line.split(b":", 1)[1].strip())
                    except ValueError:
                        body_need = 0
                elif lower.startswith(b"transfer-encoding:") and b"chunked" in lower:
                    chunked = True
        if chunked:
            end = header_end + 4
            while end < len(remaining):
                term = remaining.find(b"\r\n", end)
                if term < 0:
                    end = len(remaining)
                    break
                try:
                    size = int(remaining[end:term].split(b";", 1)[0].strip(), 16)
                except ValueError:
                    end = len(remaining)
                    break
                end = term + 2 + size + 2
                if size == 0:
                    end += 2
                    break
            responses.append(remaining[:end])
            remaining = remaining[end:]
        else:
            end = header_end + 4 + body_need
            if end > len(remaining):
                end = len(remaining)
            responses.append(remaining[:end])
            remaining = remaining[end:]
    return responses


class CanaryGenerator:
    def __init__(self) -> None:
        self._counter = 0

    def new_path(self) -> str:
        self._counter += 1
        token = randint(10**9, 10**10 - 1)
        return f"/{CANARY_PREFIX}{token}_{self._counter}"

    @staticmethod
    def parse_status(response: bytes) -> Optional[int]:
        if not response:
            return None
        return _parse_status_line(response)

    @staticmethod
    def validate(response: Optional[bytes], canary_path: str) -> bool:
        if not response:
            return False
        marker = canary_path.encode("latin-1", errors="replace")
        for resp in split_http_responses(response):
            if not resp or marker not in resp:
                continue
            status = CanaryGenerator.parse_status(resp)
            if status is None:
                return True
            if 100 <= status < 200:
                continue
            return True
        return False

    @staticmethod
    def validate_strict(response: Optional[bytes], canary_path: str) -> bool:
        if not response:
            return False
        marker = canary_path.encode("latin-1", errors="replace")
        for resp in split_http_responses(response):
            if not resp or marker not in resp:
                continue
            status = CanaryGenerator.parse_status(resp)
            if status is None:
                return True
            if 100 <= status < 200:
                continue
            if 200 <= status < 300:
                continue
            return True
        return False

    @staticmethod
    def validate_differential(response_a: Optional[bytes], response_b: Optional[bytes],
                              canary_a: str, canary_b: str) -> bool:
        if not response_a or not response_b:
            return False
        marker_a = canary_a.encode("latin-1", errors="replace")
        marker_b = canary_b.encode("latin-1", errors="replace")
        return (marker_a in response_a and marker_b not in response_a
                and marker_b in response_b and marker_a not in response_b)
