"""Canary generation with strict desync verification."""

from random import randint
from typing import Optional


CANARY_PREFIX = "canary_"


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
        first_line = response.split(b"\r\n", 1)[0]
        parts = first_line.split(b" ", 2)
        if len(parts) < 2:
            return None
        try:
            return int(parts[1])
        except ValueError:
            return None

    @staticmethod
    def validate(response: Optional[bytes], canary_path: str) -> bool:
        if not response:
            return False
        marker = canary_path.encode("latin-1", errors="replace")
        if marker not in response:
            return False
        status = CanaryGenerator.parse_status(response)
        if status is None:
            return True
        if 200 <= status < 300:
            return False
        return True

    @staticmethod
    def validate_differential(response_a: Optional[bytes], response_b: Optional[bytes],
                              canary_a: str, canary_b: str) -> bool:
        if not response_a or not response_b:
            return False
        marker_a = canary_a.encode("latin-1", errors="replace")
        marker_b = canary_b.encode("latin-1", errors="replace")
        return (marker_a in response_a and marker_b not in response_a
                and marker_b in response_b and marker_a not in response_b)