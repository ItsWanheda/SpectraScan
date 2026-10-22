"""Atomic and consistent report storage helpers for SpectraScan."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional

REPORT_EXTENSIONS = {".json", ".html", ".csv", ".txt"}


def get_report_dir() -> Path:
    """Return and create the configured report directory."""
    configured = os.environ.get("SPECTRASCAN_HOME")
    directory = Path(configured).expanduser() if configured else (
        Path.home() / ".local" / "share" / "SpectraScan"
    )
    directory.mkdir(parents=True, exist_ok=True)
    return directory.resolve()


def atomic_write_text(path: os.PathLike[str] | str, content: str, encoding: str = "utf-8") -> str:
    """Write text atomically in the destination directory."""
    destination = Path(path).expanduser().absolute()
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return str(destination)


def atomic_write_json(path: os.PathLike[str] | str, data: Any) -> str:
    return atomic_write_text(
        path,
        json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n",
    )


def safe_csv_cell(value: Any) -> str:
    """Prevent spreadsheet formula execution from untrusted CSV values."""
    text = "" if value is None else str(value)
    probe = text.lstrip(" \t\r\n")
    if probe.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


class ReportStore:
    """Shared interface for report paths and history operations."""

    def __init__(self, directory: Optional[os.PathLike[str] | str] = None) -> None:
        self.directory = Path(directory).expanduser().resolve() if directory else get_report_dir()
        self.directory.mkdir(parents=True, exist_ok=True)

    def save_text(self, filename: str, content: str) -> str:
        return atomic_write_text(self.directory / filename, content)

    def save_json(self, filename: str, data: Any) -> str:
        return atomic_write_json(self.directory / filename, data)

    def list_reports(self) -> list[str]:
        return sorted(
            (
                item.name for item in self.directory.iterdir()
                if not item.is_symlink() and item.is_file()
                and item.suffix.lower() in REPORT_EXTENSIONS
            ),
            key=str.casefold,
        )

    def _safe_path(self, filename: str) -> Path:
        candidate = Path(filename)
        if candidate.name != filename or filename in {"", ".", ".."}:
            raise ValueError("Report name must be a plain filename")
        path = self.directory / filename
        if path.is_symlink() or not path.is_file():
            raise FileNotFoundError(filename)
        if path.resolve().parent != self.directory:
            raise ValueError("Report path escapes the report directory")
        return path

    def read_text(self, filename: str, encoding: str = "utf-8") -> str:
        return self._safe_path(filename).read_text(encoding=encoding)

    def delete(self, filename: str) -> None:
        self._safe_path(filename).unlink()
