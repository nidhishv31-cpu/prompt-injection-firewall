"""Local, deterministic profanity moderation."""

import re
from enum import StrEnum
from functools import lru_cache

from backend.config import ModerationMode, ModerationSettings
from backend.pipeline.normalizer import clean

# Ignore explicit quotations and inline code in contextual mode. Strict mode
# checks the same language wherever it appears in the submitted text.
_QUOTED = re.compile(
    r"""(?<!\w)(?:["“][^"”\n]*["”]|['‘][^'’\n]*['’]|`[^`\n]*`)(?!\w)"""
)
_ADDRESS = re.compile(r"\byou(?:(?:['’]re| are| were| sound like)(?: \w+){0,4})?\W*$")
_DIRECT = re.compile(r"\byou\b")
_INTENSIFIED_INSULT = re.compile(r"(?:idiot|moron|stupid|useless|jerk)\b")


class ModerationOutcome(StrEnum):
    CLEAR = "clear"
    REPORTED = "reported"
    BLOCKED = "blocked"


@lru_cache(maxsize=32)
def lexicon(terms: tuple[str, ...]) -> re.Pattern[str]:
    words = {clean(term) for term in terms}
    alternatives = "|".join(
        re.escape(word)
        for word in sorted(words - {""}, key=lambda word: (-len(word), word))
    )
    return re.compile(rf"(?<!\w)(?:{alternatives})(?!\w)" if alternatives else r"(?!)")


def moderate(text: str, settings: ModerationSettings) -> ModerationOutcome:
    mode = settings.mode
    if mode == ModerationMode.OFF:
        return ModerationOutcome.CLEAR
    candidate = clean(
        _QUOTED.sub(" ", text) if mode == ModerationMode.CONTEXTUAL else text
    )
    for match in lexicon(settings.terms).finditer(candidate):
        if mode == ModerationMode.REPORT_ONLY:
            return ModerationOutcome.REPORTED
        if mode == ModerationMode.STRICT:
            return ModerationOutcome.BLOCKED
        before = candidate[max(0, match.start() - 80) : match.start()]
        after = candidate[match.end() : match.end() + 16].lstrip()
        directed = _ADDRESS.search(before) and (
            match[0] != "fucking" or _INTENSIFIED_INSULT.match(after)
        )
        if directed or (match[0] == "fuck" and _DIRECT.match(after)):
            return ModerationOutcome.BLOCKED
    return ModerationOutcome.CLEAR
