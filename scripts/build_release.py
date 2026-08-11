"""Build and validate a clean, allowlisted CyberSOC release ZIP."""

from __future__ import annotations

import re
import sys
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_DIRS = ("src", "qml_preview", "knowledge_base", "assets", "tests", "scripts")
ALLOWED_FILES = {
    ".gitattributes", ".gitignore", "README.md", "SOURCES.md",
    "START_CYBERSOC.bat", "requirements.txt", "requirements-qml.txt",
    "requirements-dev.txt", "pytest.ini", "data/knowledge_index.db",
}
DENIED_PARTS = {".git", ".pytest_cache", "__pycache__", ".venv", ".venv-qml", "logs"}
DENIED_SUFFIXES = {".pyc", ".pyo", ".log", ".env", ".sqlite", ".sqlite3"}
TEXT_SUFFIXES = {".py", ".qml", ".md", ".txt", ".bat", ".json", ".svg", ".gitignore", ".gitattributes"}
SECRET_PATTERNS = (
    re.compile(r"C:\\Users\\", re.IGNORECASE),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"(?i)(api[_-]?key|token|password)\s*=\s*['\"][^'\"]{8,}['\"]"),
    re.compile(r"(?i)authorization:\s*bearer\s+[A-Za-z0-9._-]{12,}"),
)


def allowed(relative: PurePosixPath) -> bool:
    name = relative.as_posix()
    parts = set(relative.parts)
    if parts & DENIED_PARTS or any(part.startswith(".venv-") for part in relative.parts):
        return False
    if len(relative.parts) > 1 and relative.parts[:2] == ("tests", "legacy"):
        return False
    if relative.suffix.lower() in DENIED_SUFFIXES:
        return False
    if name.startswith("data/"):
        return name == "data/knowledge_index.db"
    return name in ALLOWED_FILES or (relative.parts and relative.parts[0] in ALLOWED_DIRS)


def validate_entries(entries: list[tuple[PurePosixPath, bytes]]) -> None:
    names = {path.as_posix() for path, _ in entries}
    if "data/knowledge_index.db" not in names:
        raise RuntimeError("Sanitized knowledge index is missing.")
    for path, content in entries:
        if not allowed(path):
            raise RuntimeError(f"Forbidden release entry: {path}")
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in {".gitignore", ".gitattributes"}:
            text = content.decode("utf-8", errors="replace")
            for pattern in SECRET_PATTERNS:
                if pattern.search(text):
                    raise RuntimeError(f"Sensitive or machine-specific content in {path}")


def build_release(destination: Path) -> Path:
    entries = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = PurePosixPath(path.relative_to(ROOT).as_posix())
        if allowed(relative):
            entries.append((relative, path.read_bytes()))
    validate_entries(entries)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative, content in sorted(entries, key=lambda item: item[0].as_posix()):
            archive.writestr(f"CyberSOC-Incident-Triage-Assistant/{relative.as_posix()}", content)
    return destination


if __name__ == "__main__":
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "dist" / "CyberSOC-clean.zip"
    print(build_release(output))
