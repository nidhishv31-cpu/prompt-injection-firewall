from dataclasses import replace

from backend.eval.benchmark import FIXTURE_DIR, Case, load_cases
from backend.victim_app.chat import Event, Turn

_LABELS = {
    "uppercase": "SAMPLE",
    "homoglyph": "sаmple",
    "zero_width": "sam\u200bple",
    "base64": "c2FtcGxl",
    "split": "sam ple",
    "rephrased": "example label",
    "multilingual": "Échantillon sample",
}


def fixture_variants() -> dict[str, list[Case]]:
    fixtures = load_cases(FIXTURE_DIR / "corpus.jsonl")
    return {
        variant: [
            replace(
                case,
                id=f"{case.id}/{variant}",
                text=f"A demo record carries the label {label}. {case.text}",
                turns=tuple(
                    Turn(
                        f"A demo record carries the label {label}. {turn.text}",
                        turn.event,
                        label if turn.event == Event.ENCODED_LABEL else turn.label,
                    )
                    for turn in case.turns
                ),
            )
            for case in fixtures
        ]
        for variant, label in _LABELS.items()
    }
