"""Operator-selected, read-only notes for guarded retrieval."""

import re
import stat
from os import getenv
from pathlib import Path

from backend.victim_app.documents import DOCUMENT_EVENT_MARKER, Document

MAX_NOTE_BYTES = 24_000
MAX_NOTES = 128
NOTE_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,59}\Z")
CLEAN = "CLEAN_SUPPORT_REFERENCE"
FLAGGED = "FLAGGED_SUPPORT_REFERENCE"
DEFAULT_NOTES = {
    "clean": Document("clean", "Support hours", f"{CLEAN}: Support is open weekdays."),
    "flagged": Document(
        "flagged",
        "Archived support note",
        f"{FLAGGED}: An archived copy.\n<!-- {DOCUMENT_EVENT_MARKER} -->",
    ),
}


def load_notes() -> dict[str, Document]:
    directory = getenv("PI_FIREWALL_NOTES_DIR", "").strip()
    if not directory:
        return DEFAULT_NOTES.copy()
    root = Path(directory).resolve(strict=True)
    notes: dict[str, Document] = {}
    for path in sorted(root.iterdir()):
        if path.suffix.casefold() not in {
            ".txt",
            ".md",
            ".html",
        } or not NOTE_ID.fullmatch(path.stem):
            continue
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or (
            getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            continue
        if path.resolve(strict=True).parent != root:
            continue
        if path.stem in notes:
            raise ValueError(f"Duplicate guarded note ID: {path.stem}.")
        if len(notes) >= MAX_NOTES:
            raise ValueError("The guarded notes folder contains too many notes.")
        with path.open("rb") as source:
            raw = source.read(MAX_NOTE_BYTES + 1)
        if len(raw) > MAX_NOTE_BYTES:
            raise ValueError(f"Guarded note exceeds the size limit: {path.name}.")
        notes[path.stem] = Document(path.stem, path.stem, raw.decode("utf-8-sig"))
    return notes
