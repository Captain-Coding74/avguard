"""VirusTotal lookups: opt-in, rate limited, cached, and never fatal.

The original build called VirusTotal for every single file it scanned, with no
cache and no rate limiting. Its own log shows it looping on antivirus_log.txt
and spending one API call per iteration. The free tier allows 4 requests a
minute and 500 a day, so a single full scan of an ordinary folder exhausts the
daily budget in a couple of minutes and every later lookup silently returns
nothing useful.

Sending a hash also tells a third party something about a file on the user's
machine, so this is off until it is switched on.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import requests

from . import config

log = logging.getLogger(__name__)

VT_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 15

# Free tier: 4 requests/minute.
DEFAULT_RATE_PER_MINUTE = 4


class TokenBucket:
    """Hands out at most `rate` permits per minute, blocking callers past that."""

    def __init__(self, rate_per_minute: int = DEFAULT_RATE_PER_MINUTE):
        self.capacity = float(rate_per_minute)
        self.tokens = float(rate_per_minute)
        self.refill_per_second = rate_per_minute / 60.0
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def try_acquire(self) -> bool:
        """Take a permit if one is free. Never blocks."""
        with self._lock:
            now = time.monotonic()
            self.tokens = min(self.capacity,
                              self.tokens + (now - self._last) * self.refill_per_second)
            self._last = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False

    def seconds_until_token(self) -> float:
        with self._lock:
            if self.tokens >= 1.0:
                return 0.0
            return (1.0 - self.tokens) / self.refill_per_second


@dataclass
class CloudResult:
    sha256: str
    malicious: int
    suspicious: int
    total: int
    known: bool


class VirusTotalClient:
    """Cached, budgeted access to the VirusTotal file-report endpoint."""

    def __init__(
        self,
        cfg: config.Config,
        cache_path: Path = config.VT_CACHE_PATH,
        session: requests.Session | None = None,
    ) -> None:
        self.cfg = cfg
        self.cache_path = cache_path
        self.session = session or requests.Session()

        # The API key rides in a custom x-apikey header. requests strips
        # Authorization on a cross-host redirect but not custom headers, so a
        # redirect would hand the key to whatever host it points at. And
        # trust_env lets HTTPS_PROXY or REQUESTS_CA_BUNDLE in the environment
        # reroute or intercept the request. Neither is wanted here.
        for attr, value in (("trust_env", False), ("max_redirects", 0)):
            try:
                setattr(self.session, attr, value)
            except AttributeError:
                pass  # a test double need not support these

        self.bucket = TokenBucket()
        self._lock = threading.Lock()
        self._cache: dict[str, dict] = {}
        self._spent_today = 0
        self._budget_date = date.today().isoformat()
        self._cooldown_until = 0.0
        self._load_cache()

    # --------------------------------------------------------------- cache

    def _load_cache(self) -> None:
        try:
            raw = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = {}
        self._cache = raw.get("entries", {})
        self._spent_today = raw.get("spent_today", 0)
        self._budget_date = raw.get("budget_date", date.today().isoformat())

    def save_cache(self) -> None:
        with self._lock:
            payload = {
                "entries": dict(self._cache),
                "spent_today": self._spent_today,
                "budget_date": self._budget_date,
            }
        try:
            config.atomic_write_text(self.cache_path, json.dumps(payload))
        except OSError as exc:
            log.warning("could not save VirusTotal cache: %s", exc)

    def _cached(self, sha256: str) -> CloudResult | None:
        entry = self._cache.get(sha256)
        if not entry:
            return None
        age_hours = (time.time() - entry.get("fetched_at", 0)) / 3600
        if age_hours > self.cfg.cloud_cache_ttl_hours:
            return None
        return CloudResult(
            sha256=sha256,
            malicious=entry.get("malicious", 0),
            suspicious=entry.get("suspicious", 0),
            total=entry.get("total", 0),
            known=entry.get("known", False),
        )

    def _store(self, result: CloudResult) -> None:
        with self._lock:
            self._cache[result.sha256] = {
                "malicious": result.malicious,
                "suspicious": result.suspicious,
                "total": result.total,
                "known": result.known,
                "fetched_at": time.time(),
            }

    # -------------------------------------------------------------- budget

    def _budget_available(self) -> bool:
        today = date.today().isoformat()
        with self._lock:
            if today != self._budget_date:
                self._budget_date = today
                self._spent_today = 0
            return self._spent_today < self.cfg.cloud_daily_budget

    def _charge(self) -> None:
        with self._lock:
            self._spent_today += 1

    @property
    def spent_today(self) -> int:
        with self._lock:
            return self._spent_today

    # -------------------------------------------------------------- lookup

    def lookup(self, sha256: str) -> CloudResult | None:
        """Return a report for this hash, or None if we could not get one.

        Returning None is normal and never an error the caller must handle:
        the cloud stage is advisory, and a file is not treated as clean or
        malicious just because the lookup did not happen.
        """
        if not self.cfg.cloud_enabled:
            return None

        cached = self._cached(sha256)
        if cached is not None:
            return cached

        api_key = self.cfg.vt_api_key
        if not api_key:
            log.info("cloud lookups are enabled but VT_API_KEY is not set; skipping")
            return None

        if time.monotonic() < self._cooldown_until:
            return None

        if not self._budget_available():
            log.info("daily VirusTotal budget of %d used; skipping cloud lookups until tomorrow",
                     self.cfg.cloud_daily_budget)
            return None

        if not self.bucket.try_acquire():
            log.debug("VirusTotal rate limit reached; skipping this lookup")
            return None

        try:
            response = self.session.get(
                VT_URL.format(sha256=sha256),
                headers={"x-apikey": api_key, "Accept": "application/json"},
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            # Log the exception type and message only. A full traceback of a
            # requests error can echo back the prepared request headers, which
            # carry the API key.
            log.warning("VirusTotal request failed: %s", type(exc).__name__)
            return None

        self._charge()

        if response.status_code == 404:
            # Not in the database. That is information: record it so we do not
            # spend another call on the same hash.
            result = CloudResult(sha256, 0, 0, 0, known=False)
            self._store(result)
            return result

        if response.status_code == 429:
            self._cooldown_until = time.monotonic() + 60
            log.warning("VirusTotal rate limit hit; pausing cloud lookups for 60 seconds")
            return None

        if response.status_code in (401, 403):
            log.error("VirusTotal rejected the API key; disabling cloud lookups for this session")
            self.cfg.cloud_enabled = False
            return None

        if not response.ok:
            log.warning("VirusTotal returned HTTP %d", response.status_code)
            return None

        try:
            stats = (response.json()["data"]["attributes"]["last_analysis_stats"])
        except (ValueError, KeyError, TypeError):
            log.warning("VirusTotal returned a response we could not read")
            return None

        result = CloudResult(
            sha256=sha256,
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            total=sum(int(v) for v in stats.values() if isinstance(v, int)),
            known=True,
        )
        self._store(result)
        return result

    # ------------------------------------------------- scanner integration

    def reasons_for(self, sha256: str, path: Path) -> list[str]:
        """Adapter matching the scanner's cloud_lookup signature.

        Requires several engines to agree before calling something malicious.
        A single detection on VirusTotal is very often a false positive from a
        low-quality engine.
        """
        result = self.lookup(sha256)
        if result is None or not result.known:
            return []
        if result.malicious >= 3:
            return [f"VirusTotal: {result.malicious} of {result.total} engines flagged this file"]
        if result.malicious > 0:
            log.info("%s: only %d engine(s) flagged this file; not treating as a threat",
                     path.name, result.malicious)
        return []
