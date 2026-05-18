from dataclasses import dataclass
from datetime import datetime, timezone
from gzip import decompress
import itertools
import json
import os
from pathlib import Path
from importlib.metadata import version as _version
import sys
import time
from typing import Any, Dict, Iterable, Iterator, List, Optional, TextIO, Union
import urllib.error
import urllib.request
from urllib.parse import urlencode

from cvss import CVSS2, CVSS3, CVSSError
from dateutil.parser import isoparse
from tqdm import tqdm

from .cpe import And, Negate, Or, parse_formatted_string, Testable, VersionRange
from .cve import Configurations, CVE, Description, Reference
from .feed import Data, DataSource, Feed

BASE_JSON_URL: str = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"
PRE_SEED_DATA_DIR: Path = Path(__file__).absolute().parent / "data"


def camel_to_underscore(text: str) -> str:
    def process(i: int, c: str):
        if i == 0:
            return c.lower()
        elif ord("A") <= ord(c) <= ord("Z"):
            return f"_{c.lower()}"
        else:
            return c

    return "".join(process(*v) for v in enumerate(text))


@dataclass(order=True, unsafe_hash=True, frozen=True)
class Meta:
    last_modified_date: datetime
    size: int
    zip_size: int
    gz_size: int
    sha256: bytes

    @staticmethod
    def loads(meta_str: Union[str, bytes]) -> "Meta":
        kvs = {}
        for line in meta_str.splitlines():
            if isinstance(line, str):
                line = line.encode("utf-8")
            if line.strip() == b"":
                continue
            first_colon = line.find(b":")
            if first_colon <= 0:
                raise ValueError(f"Unexpected line: {line!r}")
            key = camel_to_underscore(line[:first_colon].decode("utf-8"))
            if key in kvs:
                raise ValueError(f"Duplicate metadata key: {key!r}")
            value = line[first_colon+1:].decode("utf-8")
            if key == "last_modified_date":
                value = isoparse(value)
            elif key == "sha256":
                value = bytes.fromhex(value)
            else:
                value = int(value)
            kvs[key] = value
        return Meta(**kvs)

    @staticmethod
    def load(stream: TextIO) -> "Meta":
        return Meta.loads(stream.read())


class JsonDataSource(DataSource):
    def __init__(self, meta: Meta, cves: Iterable[CVE]):
        super().__init__(meta.last_modified_date)
        self.meta: Meta = meta
        if isinstance(cves, list):
            self.cves: List[CVE] = cves
        else:
            self.cves = list(cves)

    def __iter__(self) -> Iterator[CVE]:
        return iter(self.cves)

    def __len__(self):
        return len(self.cves)

    @staticmethod
    def _parse_config_node(node: Dict[str, Any]) -> Testable:
        if "cpe23Uri" in node:
            cpe = parse_formatted_string(node["cpe23Uri"])
            if not node.get("vulnerable", True):
                cpe = Negate(cpe)
            vs = node.get("versionStartExcluding", None)
            include_start = vs is None
            vs = node.get("versionStartIncluding", vs)
            ve = node.get("versionEndExcluding", None)
            include_end = ve is None
            ve = node.get("versionEndIncluding", ve)
            if vs is not None or ve is not None:
                cpe = VersionRange(cpe, start=vs, end=ve, include_start=include_start, include_end=include_end)
            if node.get("cpe_name"):
                raise NotImplementedError("Add support for cpe_name key with value")
            unhandled_keys = node.keys() - {"cpe23Uri", "vulnerable", "versionStartIncluding", "versionStartExcluding",
                                            "versionEndIncluding", "versionEndExcluding", "cpe_name"}
            if unhandled_keys:
                raise NotImplementedError(f"Add support for CPE 23 URI node keys {unhandled_keys!r}")
            return cpe
        elif "operator" in node:
            if node["operator"].upper() == "AND":
                op_class = And
            elif node["operator"].upper() == "OR":
                op_class = Or
            else:
                raise NotImplementedError(f"Unimplemented CVE configuration node operator {node['operator']!r}")
            return op_class(
                map(JsonDataSource._parse_config_node,
                    itertools.chain(node.get("children", []), node.get("cpe_match", []))),
                negate=not node.get("vulnerable", True)
            )
        else:
            raise ValueError(f"Unknown configuration node type: {node!r}")

    @staticmethod
    def parse_configurations(config_dict: Dict[str, Any]) -> Configurations:
        if config_dict.get("CVE_data_version", "4.0") != "4.0":
            raise ValueError(f"Unsupported configuration CVE_data_version: {config_dict['CVE_data_version']}")
        return Configurations(JsonDataSource._parse_config_node(node) for node in config_dict["nodes"])

    @staticmethod
    def parse_cve(cve_obj: Dict[str, Any]) -> CVE:
        cve_id = cve_obj["cve"]["CVE_data_meta"]["ID"]
        assigner = cve_obj["cve"]["CVE_data_meta"].get("ASSIGNER", None)
        references = tuple(
            Reference(
                url=ref.get("url", None),
                name=ref.get("name", None)
            )
            for ref in cve_obj["cve"].get("references", {}).get("reference_data", [])
        )
        descriptions = tuple(
            Description(
                lang=desc["lang"],
                value=desc["value"]
            )
            for desc in cve_obj["cve"].get("description", {}).get("description_data", [])
        )
        published_date = isoparse(cve_obj["publishedDate"])
        last_modified_date = isoparse(cve_obj["lastModifiedDate"])
        if "baseMetricV3" in cve_obj["impact"]:
            impact = CVSS3(cve_obj["impact"]["baseMetricV3"]["cvssV3"]["vectorString"])
        elif "baseMetricV2" in cve_obj["impact"]:
            impact = CVSS2(cve_obj["impact"]["baseMetricV2"]["cvssV2"]["vectorString"])
        else:
            impact = None
        return CVE(
            cve_id=cve_id,
            published_date=published_date,
            last_modified_date=last_modified_date,
            impact=impact,
            descriptions=descriptions,
            references=references,
            assigner=assigner,
            configurations=JsonDataSource.parse_configurations(cve_obj.get("configurations", {}))
        )

    @staticmethod
    def load(json_obj: Dict[str, Any], meta: Optional[Meta] = None) -> "JsonDataSource":
        for key, expected in (("CVE_data_type", "CVE"), ("CVE_data_format", "MITRE"), ("CVE_data_version", "4.0")):
            if json_obj.get(key, expected) != expected:
                raise ValueError(f"Expected {key} to be {expected!r} but instead got {json_obj[key]!r}")
        if meta is None:
            if "CVE_data_timestamp" not in json_obj:
                raise ValueError("If `meta` is None, `json_obj[\"CVE_data_timestamp\"]` must contain a timestamp")
            meta = Meta(isoparse(json_obj["CVE_data_timestamp"]).astimezone(), 0, 0, 0, b"")
        return JsonDataSource(meta, (
            JsonDataSource.parse_cve(cve_obj) for cve_obj in json_obj.get("CVE_Items", ())
        ))


def download(url: str, size: Optional[int] = None, show_progress: bool = True) -> bytes:
    cvedb_version = _version("cvedb")
    request = urllib.request.Request(
        url=url,
        data=None,
        headers={
            "User-Agent":
                f"Mozilla/5.0 ({sys.platform}) AppleWebKit/605.1.15 (KHTML, like Gecko) CVEdb/{cvedb_version}"
        }
    )
    with urllib.request.urlopen(request, timeout=120) as req:
        if not show_progress:
            return req.read()
        ret = bytearray()
        filename = url[url.rfind("/")+1:]
        with tqdm(desc=filename, unit=" b", leave=False) as t:
            if size is not None:
                t.total = size
            while True:
                chunk = req.read(65536)
                n = len(chunk)
                if n == 0:
                    break
                t.update(n)
                ret.extend(chunk)
        return bytes(ret)


class JsonFeed(Feed):
    def __init__(self, name: str, initial_data: Optional[Data] = None):
        super().__init__(name, initial_data)
        self.meta_url: str = f"{BASE_JSON_URL}{self.name}.meta"
        self.gz_url: str = f"{BASE_JSON_URL}{self.name}.json.gz"
        self.cached_meta_path: Path = PRE_SEED_DATA_DIR / f"nvdcve-1.1-{self.name}.meta"
        self.cached_json_path: Path = PRE_SEED_DATA_DIR / f"nvdcve-1.1-{self.name}.json.gz"

    def reload(self, existing_data: Optional[Data] = None) -> DataSource:
        # Try to fetch updated data from NVD feeds
        try:
            with urllib.request.urlopen(self.meta_url, timeout=30) as req:
                new_meta = Meta.load(req)
            if existing_data is not None and existing_data.last_modified_date is not None and \
                    new_meta.last_modified_date <= existing_data.last_modified_date:
                return existing_data
            compressed = download(self.gz_url, new_meta.gz_size, sys.stderr.isatty())
            decompressed = decompress(compressed)
            data = json.loads(decompressed)
            return JsonDataSource.load(data, new_meta)
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            pass
        # NVD feeds unavailable; fall back to shipped seed data or existing data
        if existing_data is not None and len(existing_data) > 0:
            return existing_data
        if self.cached_json_path.exists() and self.cached_meta_path.exists():
            with open(self.cached_meta_path, "r") as meta:
                with open(self.cached_json_path, "rb") as compressed_json:
                    return JsonDataSource.load(json.loads(decompress(compressed_json.read())), Meta.load(meta))
        # No data available at all — return empty
        return JsonDataSource.load(
            {"CVE_data_type": "CVE", "CVE_data_format": "MITRE", "CVE_data_version": "4.0",
             "CVE_data_timestamp": datetime.fromtimestamp(0).isoformat(), "CVE_Items": []}
        )


for year in range(2002, datetime.now().year + 1):
    JsonFeed(str(year))


class RateLimiter:
    def __init__(self):
        self.api_key = os.environ.get("NVD_API_KEY")
        self.max_requests = 50 if self.api_key else 5
        self.window_seconds = 30
        self.request_times = []

    def wait(self):
        now = time.time()
        self.request_times = [t for t in self.request_times
                              if now - t < self.window_seconds]
        if len(self.request_times) >= self.max_requests:
            sleep_time = self.window_seconds - (now - self.request_times[0])
            if sleep_time > 0:
                time.sleep(sleep_time)
        self.request_times.append(time.time())


class ApiDataSource(DataSource):
    def __init__(self, last_modified_date: datetime, cves: Iterable[CVE]):
        super().__init__(last_modified_date)
        self.cves: List[CVE] = list(cves)

    def __iter__(self) -> Iterator[CVE]:
        return iter(self.cves)

    def __len__(self) -> int:
        return len(self.cves)

    @staticmethod
    def parse_cve_api(cve_obj: Dict[str, Any]) -> CVE:
        cve_id = cve_obj["id"]
        assigner = cve_obj.get("sourceIdentifier")

        descriptions = tuple(
            Description(lang=desc["lang"], value=desc["value"])
            for desc in cve_obj.get("descriptions", [])
        )

        references = tuple(
            Reference(url=ref.get("url"), name=ref.get("source"))
            for ref in cve_obj.get("references", [])
        )

        published_date = isoparse(cve_obj["published"])
        last_modified_date = isoparse(cve_obj["lastModified"])

        impact = None
        metrics = cve_obj.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
            if metric_key in metrics and metrics[metric_key]:
                try:
                    impact = CVSS3(metrics[metric_key][0]["cvssData"]["vectorString"])
                    break
                except (CVSSError, KeyError):
                    pass
        if impact is None and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            try:
                impact = CVSS2(metrics["cvssMetricV2"][0]["cvssData"]["vectorString"])
            except (CVSSError, KeyError):
                pass

        configurations = Configurations(())
        config_list = cve_obj.get("configurations", [])
        if config_list:
            all_nodes = []
            for config in config_list:
                all_nodes.extend(config.get("nodes", []))
            if all_nodes:
                configurations = JsonDataSource.parse_configurations(
                    {"nodes": all_nodes, "CVE_data_version": "4.0"}
                )

        return CVE(
            cve_id=cve_id,
            published_date=published_date,
            last_modified_date=last_modified_date,
            impact=impact,
            descriptions=descriptions,
            references=references,
            assigner=assigner,
            configurations=configurations,
        )


class ApiFeed(Feed):
    API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, name: str, fallback_feeds: Optional[List[Feed]] = None):
        super().__init__(name)
        self.fallback_feeds: List[Feed] = fallback_feeds or []
        self.rate_limiter = RateLimiter()

    def _fetch(self, url: str) -> bytes:
        self.rate_limiter.wait()
        cvedb_version = _version("cvedb")
        request = urllib.request.Request(
            url=url,
            headers={
                "User-Agent":
                    f"Mozilla/5.0 ({sys.platform}) AppleWebKit/605.1.15 (KHTML, like Gecko) CVEdb/{cvedb_version}"
            }
        )
        with urllib.request.urlopen(request, timeout=120) as resp:
            return resp.read()

    def _build_url(self, last_mod_start: Optional[datetime],
                   start_index: int = 0, results_per_page: int = 2000) -> str:
        params = {
            "startIndex": str(start_index),
            "resultsPerPage": str(results_per_page),
        }
        if last_mod_start is not None:
            params["lastModStartDate"] = last_mod_start.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.000")
            params["lastModEndDate"] = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.000")
        if self.rate_limiter.api_key:
            params["apiKey"] = self.rate_limiter.api_key
        return f"{self.API_BASE}?{urlencode(params)}"

    def reload(self, existing_data: Optional[Data] = None) -> DataSource:
        try:
            if existing_data is not None and existing_data.last_modified_date is not None:
                last_mod = existing_data.last_modified_date
            else:
                last_mod = None

            all_cves = []
            start_index = 0
            total_results = None
            pbar = None

            while total_results is None or start_index < total_results:
                url = self._build_url(last_mod, start_index)
                response = self._fetch(url)
                data = json.loads(response)

                if total_results is None:
                    total_results = data.get("totalResults", 0)
                    if total_results == 0:
                        break
                    if sys.stderr.isatty():
                        pbar = tqdm(total=total_results, desc="fetching CVEs",
                                    unit=" CVEs", leave=False)

                for vuln in data.get("vulnerabilities", []):
                    cve_obj = vuln.get("cve", {})
                    if cve_obj:
                        all_cves.append(ApiDataSource.parse_cve_api(cve_obj))

                fetched = len(data.get("vulnerabilities", []))
                if pbar:
                    pbar.update(fetched)
                start_index += data.get("resultsPerPage", 2000)

            if pbar:
                pbar.close()

            if all_cves:
                max_date = max(cve.last_modified_date for cve in all_cves)
                return ApiDataSource(max_date, all_cves)
            if existing_data is not None and len(existing_data) > 0:
                return existing_data
            return ApiDataSource(datetime.fromtimestamp(0, timezone.utc), [])
        except Exception:
            pass

        # Fall back to existing data or seed data from yearly feeds
        if existing_data is not None and len(existing_data) > 0:
            return existing_data
        all_cves = []
        max_date = None
        for feed in self.fallback_feeds:
            try:
                source = feed.reload(None)
                if len(source) > 0:
                    all_cves.extend(source)
                    cve_max = max(cve.last_modified_date for cve in source)
                    if max_date is None or cve_max > max_date:
                        max_date = cve_max
            except Exception:
                pass
        if all_cves:
            return ApiDataSource(max_date or datetime.now(timezone.utc), all_cves)
        return ApiDataSource(datetime.fromtimestamp(0, timezone.utc), [])


# Keep yearly JsonFeed instances as unregistered fallbacks for seed data
JsonFeed.register = False
_FALLBACK_FEEDS: List[Feed] = []
for year in range(2002, datetime.now().year + 1):
    _FALLBACK_FEEDS.append(JsonFeed(str(year)))

# Register the API feed as the primary data source
ApiFeed("nvd-api", fallback_feeds=_FALLBACK_FEEDS)
