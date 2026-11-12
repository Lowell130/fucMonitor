"""Translations. English is the reference; Italian derives from it with the same keys."""

import json
from pathlib import Path

LANGUAGES = {"en": "English", "it": "Italiano"}
_DIR = Path(__file__).parent / "locales"
_CATALOG = {code: json.loads((_DIR / f"{code}.json").read_text(encoding="utf-8")) for code in LANGUAGES}


def translate(lang: str, key: str, **values) -> str:
    text = _CATALOG.get(lang, {}).get(key) or _CATALOG["en"].get(key) or key
    return text.format(**values) if values else text
