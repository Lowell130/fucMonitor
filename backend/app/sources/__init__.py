"""Registry of data sources. Add a new source here and it shows up in the API and scheduler."""

from .base import IngestResult, Source
from .epss import EpssSource
from .kev import KevSource
from .news import NewsSource

SOURCES: dict[str, Source] = {s.name: s for s in (KevSource(), EpssSource(), NewsSource())}

__all__ = ["SOURCES", "Source", "IngestResult"]
