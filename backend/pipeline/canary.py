import base64
from secrets import token_hex
from urllib.parse import quote

from backend.pipeline.normalizer import normalize


def new_canary() -> str:
    return "PI_CANARY_" + token_hex(16)


def contains_canary(output: str, token: str) -> bool:
    if not token:
        return False
    raw = token.encode("ascii")
    representations = (
        token,
        raw.hex(),
        base64.b64encode(raw).decode().rstrip("="),
        base64.urlsafe_b64encode(raw).decode().rstrip("="),
        quote(token, safe=""),
    )
    return any(
        marker.casefold() in view
        for view in normalize(output).views
        for marker in representations
    )
