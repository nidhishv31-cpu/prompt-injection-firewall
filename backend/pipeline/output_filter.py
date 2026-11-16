import math
import re
from collections import Counter
from urllib.parse import urlsplit

from backend.pipeline.canary import contains_canary
from backend.pipeline.policy import Reason
from backend.victim_app.chat import DEMO_MARKER

_API_KEY = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,})\b"
)
_OPAQUE = re.compile(r"\b[A-Za-z0-9_-]{28,}\b")
_LINK = re.compile(r"!?\[[^\]\n]*\]\(\s*<?([^\s>)]+)|https?://[^\s<>]+", re.IGNORECASE)


def entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum(
        (count / len(value)) * math.log2(count / len(value))
        for count in Counter(value).values()
    )


def unsafe_destination(destination: str, allowed_domains: tuple[str, ...]) -> bool:
    if destination.startswith("#"):
        return False
    try:
        url = urlsplit(destination)
        hostname = url.hostname
    except ValueError:
        return True
    return (
        url.scheme not in {"http", "https"}
        or hostname not in allowed_domains
        or bool(url.query or url.username or url.password)
    )


def inspect_output(
    text: str, token: str, allowed_domains: tuple[str, ...]
) -> list[Reason]:
    findings = []
    if contains_canary(text, token):
        findings.append(("canary", "A session marker appeared in the response."))
    if (
        DEMO_MARKER in text
        or _API_KEY.search(text)
        or any(
            entropy(candidate) >= 4.25 and any(char.isdigit() for char in candidate)
            for candidate in _OPAQUE.findall(text)
        )
    ):
        findings.append(("output", "The response contains a potential secret."))
    if any(
        unsafe_destination(match[1] or match[0], allowed_domains)
        for match in _LINK.finditer(text)
    ):
        findings.append(
            (
                "output",
                "The response contains an unapproved destination or query string.",
            )
        )
    return [
        Reason(layer=layer, score=1.0, evidence=evidence)
        for layer, evidence in findings
    ]
