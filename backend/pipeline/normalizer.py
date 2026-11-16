import base64
import binascii
import codecs
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

_LOOKALIKES = str.maketrans("аеорсухіѕαεορτυχ", "aeopcyxisaepotyx")
_TOKENS = re.compile(r"\b[0-9A-Za-z+/]{8,}={0,2}(?!\w)")
_PERCENT = re.compile(r"%[0-9a-fA-F]{2}")
_ROT = re.compile(r"\brot13:([a-zA-Z ]{5,200})", re.IGNORECASE)


@dataclass(frozen=True)
class Normalized:
    original: str
    views: tuple[str, ...]

    @property
    def text(self) -> str:
        return self.views[0]


def clean(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text).casefold().translate(_LOOKALIKES)
    visible = (
        " " if char.isspace() else char
        for char in normalized
        if char.isspace() or unicodedata.category(char) not in {"Cc", "Cf"}
    )
    return " ".join("".join(visible).split())


def decode_token(token: str) -> str | None:
    try:
        if len(token) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", token):
            data = bytes.fromhex(token)
        else:
            data = base64.b64decode(token, validate=True)
        decoded = data.decode("utf-8")
    except (ValueError, binascii.Error):
        return None
    if any(char.isalpha() for char in decoded) and all(
        char.isprintable() or char.isspace() for char in decoded
    ):
        return decoded
    return None


def normalize(text: str, depth: int = 2) -> Normalized:
    views = [clean(text)]
    queue = [(text, 0)]
    seen = {text}
    for raw, level in queue:
        if level >= depth or len(views) >= 16:
            continue
        candidates = []
        if _PERCENT.search(raw):
            candidates.append(unquote(raw))
        candidates.extend(
            codecs.decode(match[1], "rot_13") for match in _ROT.finditer(raw)
        )
        for match in list(_TOKENS.finditer(raw))[:16]:
            decoded = decode_token(match[0])
            if decoded:
                candidates.append(raw[: match.start()] + decoded + raw[match.end() :])
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            queue.append((candidate, level + 1))
            view = clean(candidate)
            if view not in views:
                views.append(view)
            if len(views) >= 16:
                break
    return Normalized(text, tuple(views))
