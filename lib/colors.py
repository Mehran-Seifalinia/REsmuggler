"""ANSI color constants with runtime enable/disable."""

from os import environ, system
from sys import platform, stdout


def _enable_windows_ansi() -> bool:
    if platform != "win32":
        return True
    try:
        system("")
    except Exception:
        pass
    try:
        from ctypes import byref, windll
        from ctypes.wintypes import DWORD
        kernel32 = windll.kernel32
        for handle_id in (-11, -12):
            handle = kernel32.GetStdHandle(handle_id)
            if handle in (0, -1):
                continue
            mode = DWORD()
            if not kernel32.GetConsoleMode(handle, byref(mode)):
                continue
            ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            kernel32.SetConsoleMode(
                handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
        return True
    except Exception:
        return False


class Colors:
    RESET = ""
    BRIGHT = ""
    DIM = ""
    CYAN = ""
    MAGENTA = ""
    GREEN = ""
    YELLOW = ""
    RED = ""
    BLUE = ""
    WHITE = ""
    GREY = ""

    _ANSI = {
        "RESET": "\033[0m", "BRIGHT": "\033[1m", "DIM": "\033[2m",
        "CYAN": "\033[36m", "MAGENTA": "\033[35m", "GREEN": "\033[32m",
        "YELLOW": "\033[33m", "RED": "\033[31m", "BLUE": "\033[34m",
        "WHITE": "\033[37m", "GREY": "\033[90m",
    }

    @classmethod
    def enable(cls) -> None:
        for name, code in cls._ANSI.items():
            setattr(cls, name, code)

    @classmethod
    def disable(cls) -> None:
        for name in cls._ANSI:
            setattr(cls, name, "")

    @classmethod
    def autodetect(cls, force: bool = False, disabled: bool = False) -> None:
        if disabled or environ.get("NO_COLOR"):
            cls.disable()
            return
        if force or environ.get("FORCE_COLOR"):
            if _enable_windows_ansi():
                cls.enable()
            else:
                cls.disable()
            return
        if not hasattr(stdout, "isatty") or not stdout.isatty():
            cls.disable()
            return
        if not _enable_windows_ansi():
            cls.disable()
            return
        cls.enable()