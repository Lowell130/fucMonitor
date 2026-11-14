"""Registry of data sources. Add a new source here and it shows up in the API and scheduler."""

from .base import IngestResult, Source
from .epss import EpssSource
from .exploits import ExploitsSource
from .kev import KevSource
from .news import NewsSource
from .scans import ScansSource
from .nvd import NvdSource

SOURCES: dict[str, Source] = {s.name: s for s in (KevSource(), EpssSource(), NvdSource(), ExploitsSource(), NewsSource(), ScansSource())}

__all__ = ["SOURCES", "Source", "IngestResult"]
