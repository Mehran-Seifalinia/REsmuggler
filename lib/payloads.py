"""Payload representation and chunked-encoding helpers."""

from dataclasses import dataclass
from random import randint
from typing import Optional


END_CHUNK = "0\r\n\r\n"


@dataclass
class Payload:
    """A single HTTP request that can be serialized to raw bytes."""

    host: str
    method: str
    endpoint: str
    header: str
    body: str = ""
    content_length: Optional[int] = None

    def render(self) -> bytes:
        """Substitute placeholders and serialize the request to bytes."""
        content_length = self.content_length if self.content_length is not None else 0
        header = (
            self.header
            .replace("__METHOD__", self.method)
            .replace("__ENDPOINT__", self.endpoint)
            .replace("__RANDOM__", str(randint(10 ** 9, 10 ** 10 - 1)))
            .replace("__HOST__", self.host)
            .replace("__REPLACE_CL__", str(content_length))
        )
        return (header + "\r\n" + self.body).encode("latin-1", errors="replace")


def chunked(data: str) -> str:
    """Wrap a string as a single HTTP chunk."""
    length = len(data.encode("latin-1", errors="replace"))
    return f"{length:x}\r\n{data}\r\n"