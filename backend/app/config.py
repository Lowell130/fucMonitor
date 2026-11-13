"""Application settings. Every value can be overridden with a FUC_* environment variable."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FUC_", env_file=".env", extra="ignore")

    data_dir: Path = Path("/data")

    # --- sources -----------------------------------------------------------
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    # Official location documented at https://www.first.org/epss/data (it redirects).
    epss_url: str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    # Template for one historical day, used by the backfill. {date} = YYYY-MM-DD.
    epss_dated_url: str = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"

    # --- NVD -----------------------------------------------------------------
    nvd_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    # A free key raises the rate limit from 5 to 50 requests per 30 seconds:
    # https://nvd.nist.gov/developers/request-an-api-key
    nvd_api_key: str | None = None
    nvd_page_size: int = 2000
    nvd_max_retries: int = 4
    # Seconds between requests. Left empty, it follows NIST's advice for the key in use.
    nvd_delay_seconds: float | None = None

    # --- public exploits -------------------------------------------------------
    metasploit_url: str = (
        "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
    )
    nuclei_url: str = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
    exploitdb_url: str = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

    # --- news ----------------------------------------------------------------
    # Minutes between news collections. Feeds are fetched with conditional requests.
    news_interval_minutes: int = 60
    # Optional replacement for backend/app/sources/feeds.json.
    news_feeds_file: Path | None = None

    http_timeout: float = 180.0
    user_agent: str = "fucMonitor/0.1 (local research project)"

    # --- scheduler ---------------------------------------------------------
    scheduler_enabled: bool = True
    # Comma separated HH:MM times, UTC. Two runs a day make a missed one harmless.
    schedule_times_utc: str = "06:15,18:15"
    # Ingest at startup when a source has no snapshot for today yet.
    run_on_startup: bool = True

    def nvd_delay(self) -> float:
        if self.nvd_delay_seconds is not None:
            return self.nvd_delay_seconds
        return 0.8 if self.nvd_api_key else 6.5

    def exploit_urls(self) -> dict[str, str]:
        urls = {"metasploit": self.metasploit_url, "nuclei": self.nuclei_url, "exploitdb": self.exploitdb_url}
        return {name: url for name, url in urls.items() if url}

    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"

    @property
    def curated_dir(self) -> Path:
        return self.data_dir / "curated"

    @property
    def state_db(self) -> Path:
        return self.data_dir / "state" / "fucmonitor.sqlite"


@lru_cache
def get_settings() -> Settings:
    return Settings()
