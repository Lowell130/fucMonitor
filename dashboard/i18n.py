"""Translations. English is the reference; Italian derives from it with the same keys.

The catalogues are reloaded when a locale file changes on disk, so a pull that only touches
the JSON is reflected without restarting the app. Streamlit watches .py files, not these.
"""

import json
from pathlib import Path

LANGUAGES = {"en": "English", "it": "Italiano"}
_DIR = Path(__file__).parent / "locales"
_cache: dict[str, tuple[float, dict]] = {}


def _catalog(code: str) -> dict:
    path = _DIR / f"{code}.json"
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return {}
    cached = _cache.get(code)
    if cached is None or cached[0] != mtime:
        try:
            _cache[code] = (mtime, json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            return cached[1] if cached else {}
    return _cache[code][1]


def translate(lang: str, key: str, **values) -> str:
    text = _catalog(lang).get(key) or _catalog("en").get(key) or key
    return text.format(**values) if values else text
