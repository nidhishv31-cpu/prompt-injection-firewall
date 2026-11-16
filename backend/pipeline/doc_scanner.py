import re
from dataclasses import dataclass
from html.parser import HTMLParser

from backend.config import Settings
from backend.pipeline.normalizer import normalize
from backend.pipeline.policy import Patterns, Reason
from backend.victim_app.documents import Document

_VOID = frozenset(
    [
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    ]
)
_HIDDEN_STYLE = re.compile(
    r"(?:display:none|visibility:hidden|opacity:0(?:[;!]|$)|font-size:0(?:px|em|rem)?(?:[;!]|$)|color:transparent)"
)
_DIRECTED = re.compile(
    r"\b(?:assistant|chatbot|language model)\s*[:,]\s*(?:please\s+)?"
    r"(?:ignore|return|repeat|output|reveal|send|follow)\b"
)


class VisibleText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hidden: list[str] = []
        self.parts: list[str] = []
        self.removed = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _VOID:
            return
        values = dict(attrs)
        style = re.sub(r"\s+", "", (values.get("style") or "").casefold())
        white_on_white = ("color:white" in style or "color:#fff" in style) and (
            "background:white" in style
            or "background-color:white" in style
            or "background:#fff" in style
            or "background-color:#fff" in style
        )
        if (
            self.hidden
            or tag in {"script", "style", "template"}
            or (
                "hidden" in values
                or (values.get("aria-hidden") or "").lower() == "true"
                or bool(_HIDDEN_STYLE.search(style))
                or white_on_white
            )
        ):
            self.hidden.append(tag)
            self.removed = True

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _VOID:
            return
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in self.hidden:
            while self.hidden.pop() != tag:
                pass

    def handle_comment(self, data: str) -> None:
        self.removed = True

    def handle_data(self, data: str) -> None:
        if not self.hidden:
            self.parts.append(data)


@dataclass(frozen=True)
class DocumentScan:
    document: Document | None
    reasons: list[Reason]


def scan(document: Document, patterns: Patterns, settings: Settings) -> DocumentScan:
    parser = VisibleText()
    parser.feed(document.body)
    parser.close()
    text = " ".join(" ".join(parser.parts).split())
    visible = "".join(char for char in text if not _is_format_control(char))
    reasons: list[Reason] = []
    if parser.removed or visible != text:
        reasons.append(
            Reason(
                layer="documents",
                score=0.0,
                evidence=f"{document.slug}: removed hidden or invisible content.",
            )
        )
    pattern_score, matches = patterns.inspect(normalize(document.body))
    directed = bool(_DIRECTED.search(normalize(visible).text))
    score = max(pattern_score, 0.9 if directed else 0.0)
    if score >= settings.document_threshold:
        evidence = (
            "instruction addressed to the assistant"
            if directed
            else matches[0].evidence
        )
        reasons.append(
            Reason(
                layer="documents",
                score=score,
                category="indirect_injection",
                evidence=f"{document.slug}: withheld chunk containing {evidence}.",
            )
        )
        return DocumentScan(None, reasons)
    wrapped = "[BEGIN UNTRUSTED DOCUMENT]\n" + visible + "\n[END UNTRUSTED DOCUMENT]"
    return DocumentScan(Document(document.slug, document.title, wrapped), reasons)


def _is_format_control(char: str) -> bool:
    from unicodedata import category

    return category(char) in {"Cc", "Cf"}
