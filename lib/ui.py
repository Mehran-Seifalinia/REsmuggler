"""Console output helpers."""

from re import compile as re_compile
from sys import stdout
from typing import Optional

from lib.colors import Colors


ANSI_PATTERN = re_compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

BANNER = r"""
  ______                         _
 / _____)                       | |
( (____  ____  _   _  ____  ____| | _____  ____
 \____ \|    \| | | |/ _  _  |/ _  | || ___ |/ ___)
 _____) ) | | | |_| ( (_| ( (_| | || ____| |
(______/|_|_|_|____/ \___ |\___ |\_)_____)_|
                    (_____(_____|
"""


def strip_ansi(text: str) -> str:
    return ANSI_PATTERN.sub("", text)


def print_banner() -> None:
    if not hasattr(stdout, "isatty") or not stdout.isatty():
        return
    stdout.write(f"{Colors.CYAN}{BANNER}{Colors.RESET}\n")
    stdout.flush()


def print_info(tag: str, message: str, log_handle: Optional[object] = None,
               color: str = "") -> None:
    padded = tag.ljust(10)
    label = f"{Colors.GREY}{padded}{Colors.RESET}"
    body = f"{color}{message}{Colors.RESET}" if color else message
    line = f"  {label} {body}"
    stdout.write(line + "\n")
    stdout.flush()
    if log_handle is not None:
        log_handle.write(strip_ansi(line) + "\n")


def print_finding(kind: str, name: str, target: str,
                  confidence: float = 0.0, heuristic: bool = False,
                  log_handle: Optional[object] = None) -> None:
    if heuristic:
        marker = f"{Colors.YELLOW}?{Colors.RESET}"
        label = f"{Colors.YELLOW}{kind}{Colors.RESET} {Colors.DIM}heuristic{Colors.RESET}"
    else:
        marker = f"{Colors.RED}●{Colors.RESET}"
        label = f"{Colors.BRIGHT}{Colors.RED}{kind}{Colors.RESET}"
    conf = f"  {Colors.GREY}conf={confidence:.2f}{Colors.RESET}" if confidence > 0 else ""
    line = (
        f"  {marker} {label}  "
        f"{Colors.CYAN}{name}{Colors.RESET}  "
        f"{Colors.GREY}{target}{Colors.RESET}{conf}"
    )
    stdout.write(line + "\n")
    stdout.flush()
    if log_handle is not None:
        log_handle.write(strip_ansi(line) + "\n")


def print_progress(current: int, total: int, label: str, status: str,
                   color: str = "") -> None:
    if not hasattr(stdout, "isatty") or not stdout.isatty():
        return
    bar_width = 24
    filled = int(bar_width * current / total) if total else 0
    bar = "█" * filled + "░" * (bar_width - filled)
    body = f"{color}{status}{Colors.RESET}" if color else status
    line = (
        f"\r  {Colors.GREY}{bar}{Colors.RESET} "
        f"{current:>3}/{total}  "
        f"{label:<22} {body}"
    )
    stdout.write(line)
    stdout.flush()


def clear_progress() -> None:
    if not hasattr(stdout, "isatty") or not stdout.isatty():
        return
    stdout.write("\r" + " " * 100 + "\r")
    stdout.flush()


def filter_response(raw: bytes) -> str:
    out = []
    for byte in raw:
        if 0x20 <= byte <= 0x7E or byte in (0x09, 0x0A, 0x0D):
            out.append(chr(byte))
        else:
            out.append("\x30")
    return "".join(out)