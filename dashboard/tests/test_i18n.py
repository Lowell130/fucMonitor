"""English is the reference: Italian must have exactly the same keys and placeholders,
and every key used in app.py must exist."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EN = json.loads((ROOT / "locales" / "en.json").read_text(encoding="utf-8"))
IT = json.loads((ROOT / "locales" / "it.json").read_text(encoding="utf-8"))
SOURCE = (ROOT / "app.py").read_text(encoding="utf-8")
PLACEHOLDER = re.compile(r"\{(\w+)\}")


def _table_columns() -> set[str]:
    """Column names passed to table(...) calls; each needs a col.<name> label."""
    columns = set()
    for match in re.finditer(r"\btable\(\n?", SOURCE):
        depth, i = 1, match.end()
        while depth and i < len(SOURCE):
            depth += {"(": 1, ")": -1}.get(SOURCE[i], 0)
            i += 1
        call = SOURCE[match.end():i]
        subscripts = set(re.findall(r'\["([a-z_]+)"\]', call))  # e.g. response["items"]
        columns |= set(re.findall(r'"([a-z_]+)"', call)) - subscripts
    return columns


def test_same_keys_in_both_languages():
    assert sorted(EN) == sorted(IT)


def test_same_placeholders_and_no_empty_text():
    for key, text in EN.items():
        assert text.strip() and IT[key].strip(), key
        assert sorted(PLACEHOLDER.findall(text)) == sorted(PLACEHOLDER.findall(IT[key])), key


def test_keys_used_in_the_app_exist():
    used = set(re.findall(r"""\bt\(\s*["']([\w.]+)["']""", SOURCE))
    pages = re.search(r"PAGES = \[(.*?)\]", SOURCE).group(1)
    used |= {f"nav.{p}" for p in re.findall(r'"(\w+)"', pages)}
    columns = _table_columns()
    assert len(columns) > 15  # guards the extractor itself
    used |= {f"col.{c}" for c in columns}
    missing = sorted(k for k in used if k not in EN)
    assert not missing, missing


def test_no_unused_keys():
    used = set(re.findall(r"""\bt\(\s*["']([\w.]+)["']""", SOURCE))
    unused = sorted(k for k in EN if not k.startswith(("col.", "nav.", "kind.")) and k not in used)
    assert not unused, unused
