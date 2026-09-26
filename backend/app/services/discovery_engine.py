import asyncio
import heapq
import json
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, Callable, Tuple

from app.services.safe_client import SafeHttpClient, SafeHttpResponse
from app.services.url_normalizer import (
    normalize_url,
    is_same_origin,
    is_same_host,
    extract_query_param_names,
    generate_duplicate_key
)
from app.services.scan_config import DEFAULT_SAFETY_CONFIG, ScanSafetyConfig

logger = logging.getLogger("autopentest.discovery")


@dataclass(order=True)
class CrawlCandidate:
    priority: int
    url: str = field(compare=False)
    depth: int = field(compare=False)
    source_url: Optional[str] = field(default=None, compare=False)
    discovery_reason: str = field(default="LINK", compare=False)
    method: str = field(default="GET", compare=False)


@dataclass
class DiscoveredAsset:
    asset_type: str  # PAGE, ENDPOINT, FORM, API, SCRIPT, RESOURCE, DOCUMENT, ROBOTS, SITEMAP, WEB_SOCKET, GRAPHQL, REDIRECT
    url: str
    normalized_url: str
    hostname: str
    path: str
    query_parameters: List[str]
    http_method: str
    content_type: Optional[str]
    status_code: Optional[int]
    discovered_from: str  # HTML, JAVASCRIPT, ROBOTS, SITEMAP, OPENAPI, REDIRECT
    source_url: Optional[str]
    evidence: Dict[str, Any]
    confidence: str  # High, Medium, Low
    evidence_status: str  # OBSERVED, INFERRED, VERIFIED
    in_scope: bool
    external: bool
    duplicate_key: str


class DiscoveryEngine:
    """
    Evidence-based, bounded attack surface discovery engine.
    Discovers same-origin pages, endpoints, forms, APIs, scripts, WebSockets,
    and GraphQL endpoints without aggressive exploitation or payload injection.
    """

    def __init__(
        self,
        target_url: str,
        config: Optional[ScanSafetyConfig] = None,
        client: Optional[SafeHttpClient] = None,
        max_depth: int = 2,
        max_urls: int = 200,
        max_requests: int = 250,
        max_concurrency: int = 4
    ):
        self.raw_target_url = target_url
        self.config = config or DEFAULT_SAFETY_CONFIG
        self.client = client or SafeHttpClient(config=self.config)

        self.max_depth = max_depth
        self.max_urls = max_urls
        self.max_requests = max_requests
        self.max_concurrency = max_concurrency

        # Target origin reference
        self.normalized_target = normalize_url(target_url)
        parsed = urllib.parse.urlparse(self.normalized_target)
        self.target_scheme = parsed.scheme
        self.target_hostname = (parsed.hostname or "").lower()
        self.target_origin = f"{self.target_scheme}://{parsed.netloc}"

        # Frontier and state
        self.frontier: List[CrawlCandidate] = []
        self.visited_urls: Set[str] = set()
        self.assets: Dict[str, DiscoveredAsset] = {}
        self.semaphore = asyncio.Semaphore(self.max_concurrency)

        # Telemetry & metrics
        self.requests_total = 0
        self.bytes_received = 0
        self.crawl_urls_discovered = 0
        self.crawl_urls_verified = 0
        self.limits_reached: List[str] = []

    def _add_asset(self, asset: DiscoveredAsset) -> bool:
        """Add asset if not already present; update if transitioning from INFERRED to VERIFIED."""
        key = asset.duplicate_key
        if key in self.assets:
            existing = self.assets[key]
            # Upgrade evidence status if newly verified
            if existing.evidence_status != "VERIFIED" and asset.evidence_status == "VERIFIED":
                existing.evidence_status = "VERIFIED"
                existing.status_code = asset.status_code
                existing.content_type = asset.content_type
            return False

        if len(self.assets) >= self.max_urls:
            if "MAX_DISCOVERED_URLS" not in self.limits_reached:
                self.limits_reached.append("MAX_DISCOVERED_URLS")
            return False

        self.assets[key] = asset
        self.crawl_urls_discovered += 1
        return True

    def _enqueue(self, candidate: CrawlCandidate):
        """Enqueue crawl candidate if within depth and URL limits and not visited."""
        norm = normalize_url(candidate.url)
        if norm in self.visited_urls:
            return
        if candidate.depth > self.max_depth:
            return
        if len(self.visited_urls) + len(self.frontier) >= self.max_urls:
            if "MAX_DISCOVERED_URLS" not in self.limits_reached:
                self.limits_reached.append("MAX_DISCOVERED_URLS")
            return

        heapq.heappush(self.frontier, candidate)

    async def _safe_fetch(self, method: str, url: str) -> Optional[SafeHttpResponse]:
        """Safely fetch HTTP endpoint using SafeHttpClient with global accounting."""
        if self.requests_total >= self.max_requests:
            if "MAX_REQUESTS_PER_SCAN" not in self.limits_reached:
                self.limits_reached.append("MAX_REQUESTS_PER_SCAN")
            return None

        async with self.semaphore:
            self.requests_total += 1
            try:
                if method.upper() == "HEAD":
                    resp = await self.client.head(url)
                elif method.upper() == "OPTIONS":
                    resp = await self.client.options(url)
                else:
                    resp = await self.client.get(url)
                self.bytes_received += len(resp.content_bytes)
                return resp
            except Exception as e:
                logger.debug(f"DiscoveryEngine: Safe fetch failed for {url}: {e}")
                return None

    # -------------------------------------------------------------------------
    # HTML Parsing
    # -------------------------------------------------------------------------

    def _parse_html_assets(self, base_url: str, html_text: str, current_depth: int):
        """Extract links, forms, scripts, stylesheets, and media from HTML."""
        # 1. Page Title
        title_match = re.search(r"<title[^>]*>([^<]+)</title>", html_text, re.I)
        page_title = title_match.group(1).strip() if title_match else "N/A"

        # 2. Forms Discovery
        form_matches = re.finditer(r"<form([^>]*)>(.*?)</form>", html_text, re.I | re.S)
        for f in form_matches:
            attrs = f.group(1)
            content = f.group(2)

            method_m = re.search(r'method=["\']?([a-zA-Z]+)["\']?', attrs, re.I)
            method = method_m.group(1).upper() if method_m else "GET"

            action_m = re.search(r'action=["\']?([^"\'\s>]+)["\']?', attrs, re.I)
            action = action_m.group(1) if action_m else base_url
            full_action = normalize_url(action, base_url)

            # Extract inputs, textareas, selects
            inputs = []
            field_names = []
            for inp in re.finditer(r'<input([^>]*)>', content, re.I):
                inp_attrs = inp.group(1)
                name_m = re.search(r'name=["\']?([^"\'\s>]+)["\']?', inp_attrs, re.I)
                type_m = re.search(r'type=["\']?([^"\'\s>]+)["\']?', inp_attrs, re.I)
                req_m = "required" in inp_attrs.lower()
                if name_m:
                    fname = name_m.group(1)
                    ftype = type_m.group(1).lower() if type_m else "text"
                    inputs.append({"name": fname, "type": ftype, "required": req_m})
                    field_names.append(fname)

            for ta in re.finditer(r'<textarea([^>]*)>', content, re.I):
                name_m = re.search(r'name=["\']?([^"\'\s>]+)["\']?', ta.group(1), re.I)
                if name_m:
                    fname = name_m.group(1)
                    inputs.append({"name": fname, "type": "textarea", "required": "required" in ta.group(1).lower()})
                    field_names.append(fname)

            for sel in re.finditer(r'<select([^>]*)>', content, re.I):
                name_m = re.search(r'name=["\']?([^"\'\s>]+)["\']?', sel.group(1), re.I)
                if name_m:
                    fname = name_m.group(1)
                    inputs.append({"name": fname, "type": "select", "required": "required" in sel.group(1).lower()})
                    field_names.append(fname)

            parsed_action = urllib.parse.urlparse(full_action)
            is_same = is_same_host(full_action, self.raw_target_url)
            sorted_fields = ",".join(sorted(field_names))

            form_asset = DiscoveredAsset(
                asset_type="FORM",
                url=full_action,
                normalized_url=full_action,
                hostname=parsed_action.hostname or self.target_hostname,
                path=parsed_action.path or "/",
                query_parameters=extract_query_param_names(full_action),
                http_method=method,
                content_type="application/x-www-form-urlencoded",
                status_code=None,
                discovered_from="HTML",
                source_url=base_url,
                evidence={
                    "source": "html",
                    "element": "form",
                    "action": action,
                    "method": method,
                    "fields_count": len(inputs),
                    "fields": inputs,
                    "page_title": page_title
                },
                confidence="High",
                evidence_status="OBSERVED",
                in_scope=is_same,
                external=not is_same,
                duplicate_key=generate_duplicate_key("FORM", full_action, method, sorted_fields)
            )
            self._add_asset(form_asset)

        # 3. Hyperlinks (<a href>)
        for a_match in re.finditer(r'<a[^>]+href=["\']([^"\'#\s>]+)["\']', html_text, re.I):
            href = a_match.group(1).strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue

            full_url = normalize_url(href, base_url)
            if not full_url:
                continue

            parsed_url = urllib.parse.urlparse(full_url)
            same_host = is_same_host(full_url, self.raw_target_url)

            if same_host:
                dup_key = generate_duplicate_key("PAGE", full_url)
                asset = DiscoveredAsset(
                    asset_type="PAGE",
                    url=full_url,
                    normalized_url=full_url,
                    hostname=parsed_url.hostname or self.target_hostname,
                    path=parsed_url.path or "/",
                    query_parameters=extract_query_param_names(full_url),
                    http_method="GET",
                    content_type="text/html",
                    status_code=None,
                    discovered_from="HTML",
                    source_url=base_url,
                    evidence={"source": "html", "element": "a", "attribute": "href", "observed_value": href},
                    confidence="High",
                    evidence_status="OBSERVED",
                    in_scope=True,
                    external=False,
                    duplicate_key=dup_key
                )
                if self._add_asset(asset):
                    # Enqueue for crawling if depth allows
                    self._enqueue(CrawlCandidate(priority=2, url=full_url, depth=current_depth + 1, source_url=base_url, discovery_reason="NAV_LINK"))
            else:
                # External URL: Record as external resource, DO NOT enqueue
                dup_key = generate_duplicate_key("PAGE", full_url)
                asset = DiscoveredAsset(
                    asset_type="PAGE",
                    url=full_url,
                    normalized_url=full_url,
                    hostname=parsed_url.hostname or "external",
                    path=parsed_url.path or "/",
                    query_parameters=extract_query_param_names(full_url),
                    http_method="GET",
                    content_type=None,
                    status_code=None,
                    discovered_from="HTML",
                    source_url=base_url,
                    evidence={"source": "html", "element": "a", "attribute": "href", "observed_value": href},
                    confidence="High",
                    evidence_status="OBSERVED",
                    in_scope=False,
                    external=True,
                    duplicate_key=dup_key
                )
                self._add_asset(asset)

        # 4. Script tags (<script src>)
        for s_match in re.finditer(r'<script[^>]+src=["\']([^"\'\s>]+)["\']', html_text, re.I):
            src = s_match.group(1).strip()
            full_src = normalize_url(src, base_url)
            if not full_src:
                continue

            parsed_s = urllib.parse.urlparse(full_src)
            same_host = is_same_host(full_src, self.raw_target_url)

            asset = DiscoveredAsset(
                asset_type="SCRIPT",
                url=full_src,
                normalized_url=full_src,
                hostname=parsed_s.hostname or self.target_hostname,
                path=parsed_s.path or "/",
                query_parameters=extract_query_param_names(full_src),
                http_method="GET",
                content_type="application/javascript",
                status_code=None,
                discovered_from="HTML",
                source_url=base_url,
                evidence={"source": "html", "element": "script", "attribute": "src", "observed_value": src},
                confidence="High",
                evidence_status="OBSERVED",
                in_scope=same_host,
                external=not same_host,
                duplicate_key=generate_duplicate_key("SCRIPT", full_src)
            )
            if self._add_asset(asset) and same_host and current_depth <= self.max_depth:
                # Enqueue script for static JS analysis
                self._enqueue(CrawlCandidate(priority=5, url=full_src, depth=current_depth, source_url=base_url, discovery_reason="SCRIPT_ANALYSIS"))

        # 5. Stylesheets & Preload links (<link href>)
        for l_match in re.finditer(r'<link[^>]+href=["\']([^"\'\s>]+)["\']', html_text, re.I):
            href = l_match.group(1).strip()
            rel_m = re.search(r'rel=["\']([^"\']+)["\']', l_match.group(0), re.I)
            rel_type = rel_m.group(1).lower() if rel_m else "link"

            full_link = normalize_url(href, base_url)
            if not full_link:
                continue

            parsed_l = urllib.parse.urlparse(full_link)
            same_host = is_same_host(full_link, self.raw_target_url)

            asset_type = "RESOURCE"
            if "stylesheet" in rel_type:
                asset_type = "RESOURCE"
            elif "canonical" in rel_type or "alternate" in rel_type:
                asset_type = "PAGE"

            asset = DiscoveredAsset(
                asset_type=asset_type,
                url=full_link,
                normalized_url=full_link,
                hostname=parsed_l.hostname or self.target_hostname,
                path=parsed_l.path or "/",
                query_parameters=extract_query_param_names(full_link),
                http_method="GET",
                content_type=None,
                status_code=None,
                discovered_from="HTML",
                source_url=base_url,
                evidence={"source": "html", "element": "link", "rel": rel_type, "observed_value": href},
                confidence="High",
                evidence_status="OBSERVED",
                in_scope=same_host,
                external=not same_host,
                duplicate_key=generate_duplicate_key(asset_type, full_link)
            )
            self._add_asset(asset)

    # -------------------------------------------------------------------------
    # JavaScript Static Analysis
    # -------------------------------------------------------------------------

    def _analyze_javascript_content(self, script_url: str, js_code: str):
        """
        Analyze JavaScript code statically using regex patterns.
        Identifies potential API endpoints, fetch/axios calls, WebSockets, and GraphQL references.
        Zero JS execution. All candidates marked as INFERRED.
        """
        # 1. API endpoint patterns (e.g. /api/v1/users, /rest/v2/items, /graphql)
        api_patterns = [
            r'["\'](/api/[a-zA-Z0-9_\-\/\.\?=&]+)["\']',
            r'["\'](/v[0-9]+/[a-zA-Z0-9_\-\/\.\?=&]+)["\']',
            r'["\'](/rest/[a-zA-Z0-9_\-\/\.\?=&]+)["\']',
            r'["\'](/graphql(?:[a-zA-Z0-9_\-\/\.\?=&]*)?)["\']'
        ]

        for pat in api_patterns:
            for match in re.finditer(pat, js_code):
                rel_path = match.group(1).strip()
                full_url = normalize_url(rel_path, script_url)
                if not is_same_host(full_url, self.raw_target_url):
                    continue

                parsed = urllib.parse.urlparse(full_url)
                is_graphql = "graphql" in rel_path.lower()
                asset_type = "GRAPHQL" if is_graphql else "API"

                dup_key = generate_duplicate_key(asset_type, full_url, "GET")
                asset = DiscoveredAsset(
                    asset_type=asset_type,
                    url=full_url,
                    normalized_url=full_url,
                    hostname=parsed.hostname or self.target_hostname,
                    path=parsed.path or "/",
                    query_parameters=extract_query_param_names(full_url),
                    http_method="GET",
                    content_type="application/json" if not is_graphql else None,
                    status_code=None,
                    discovered_from="JAVASCRIPT",
                    source_url=script_url,
                    evidence={"source": "javascript", "pattern": "api_path_string", "observed_value": rel_path},
                    confidence="Medium",
                    evidence_status="INFERRED",
                    in_scope=True,
                    external=False,
                    duplicate_key=dup_key
                )
                if self._add_asset(asset) and not is_graphql:
                    # Enqueue candidate API for safe GET verification
                    self._enqueue(CrawlCandidate(priority=4, url=full_url, depth=1, source_url=script_url, discovery_reason="JS_API_CANDIDATE"))

        # 2. fetch() and axios calls
        fetch_axios_pattern = r'(?:fetch|axios(?:\.[a-zA-Z]+)?)\s*\(\s*["\']([^"\'\s]+)["\']'
        for match in re.finditer(fetch_axios_pattern, js_code):
            endpoint_str = match.group(1).strip()
            if endpoint_str.startswith(("http://", "https://", "/")):
                full_url = normalize_url(endpoint_str, script_url)
                same_host = is_same_host(full_url, self.raw_target_url)
                parsed = urllib.parse.urlparse(full_url)

                dup_key = generate_duplicate_key("ENDPOINT", full_url, "GET")
                asset = DiscoveredAsset(
                    asset_type="ENDPOINT",
                    url=full_url,
                    normalized_url=full_url,
                    hostname=parsed.hostname or self.target_hostname,
                    path=parsed.path or "/",
                    query_parameters=extract_query_param_names(full_url),
                    http_method="GET",
                    content_type=None,
                    status_code=None,
                    discovered_from="JAVASCRIPT",
                    source_url=script_url,
                    evidence={"source": "javascript", "pattern": "fetch_or_axios", "observed_value": endpoint_str},
                    confidence="Medium",
                    evidence_status="INFERRED",
                    in_scope=same_host,
                    external=not same_host,
                    duplicate_key=dup_key
                )
                if self._add_asset(asset) and same_host:
                    self._enqueue(CrawlCandidate(priority=4, url=full_url, depth=1, source_url=script_url, discovery_reason="JS_ENDPOINT_CANDIDATE"))

        # 3. WebSocket references (ws:// or wss:// or new WebSocket(...))
        ws_pattern = r'(?:new\s+WebSocket\s*\(\s*|["\'])(wss?://[^"\'\s]+)["\']'
        for match in re.finditer(ws_pattern, js_code):
            ws_url = match.group(1).strip()
            parsed_ws = urllib.parse.urlparse(ws_url)
            same_host = is_same_host(ws_url, self.raw_target_url)

            dup_key = generate_duplicate_key("WEB_SOCKET", ws_url)
            asset = DiscoveredAsset(
                asset_type="WEB_SOCKET",
                url=ws_url,
                normalized_url=ws_url,
                hostname=parsed_ws.hostname or self.target_hostname,
                path=parsed_ws.path or "/",
                query_parameters=extract_query_param_names(ws_url),
                http_method="GET",
                content_type=None,
                status_code=None,
                discovered_from="JAVASCRIPT",
                source_url=script_url,
                evidence={"source": "javascript", "pattern": "websocket_instantiation", "observed_value": ws_url},
                confidence="High",
                evidence_status="INFERRED",
                in_scope=same_host,
                external=not same_host,
                duplicate_key=dup_key
            )
            self._add_asset(asset)

    # -------------------------------------------------------------------------
    # OpenAPI / Swagger Specification Discovery
    # -------------------------------------------------------------------------

    async def _probe_openapi_specifications(self, on_event: Optional[Callable[[str, Dict[str, Any]], Any]] = None):
        """Probe common same-origin OpenAPI / Swagger paths and parse declared endpoints."""
        spec_candidates = [
            "/openapi.json",
            "/swagger.json",
            "/api/openapi.json",
            "/api/v1/openapi.json"
        ]

        for rel_spec in spec_candidates:
            spec_url = normalize_url(rel_spec, self.target_origin)
            resp = await self._safe_fetch("GET", spec_url)
            if resp and resp.status_code == 200:
                try:
                    data = json.loads(resp.text)
                    if isinstance(data, dict) and ("paths" in data or "openapi" in data or "swagger" in data):
                        # Register the spec itself as DOCUMENT
                        self._add_asset(DiscoveredAsset(
                            asset_type="DOCUMENT",
                            url=spec_url,
                            normalized_url=spec_url,
                            hostname=self.target_hostname,
                            path=rel_spec,
                            query_parameters=[],
                            http_method="GET",
                            content_type="application/json",
                            status_code=200,
                            discovered_from="OPENAPI",
                            source_url=self.raw_target_url,
                            evidence={"source": "openapi", "version": data.get("openapi", data.get("swagger", "2.0"))},
                            confidence="High",
                            evidence_status="VERIFIED",
                            in_scope=True,
                            external=False,
                            duplicate_key=generate_duplicate_key("DOCUMENT", spec_url)
                        ))

                        # Parse declared paths
                        paths = data.get("paths", {})
                        for api_path, methods_dict in paths.items():
                            if not isinstance(methods_dict, dict):
                                continue
                            for method_name, method_info in methods_dict.items():
                                m_upper = method_name.upper()
                                if m_upper not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                                    continue

                                full_api_url = normalize_url(api_path, self.target_origin)
                                params_list = []
                                if isinstance(method_info, dict):
                                    for p in method_info.get("parameters", []):
                                        if isinstance(p, dict) and "name" in p:
                                            params_list.append(p["name"])

                                dup_key = generate_duplicate_key("API", full_api_url, m_upper)
                                asset = DiscoveredAsset(
                                    asset_type="API",
                                    url=full_api_url,
                                    normalized_url=full_api_url,
                                    hostname=self.target_hostname,
                                    path=api_path,
                                    query_parameters=params_list,
                                    http_method=m_upper,
                                    content_type="application/json",
                                    status_code=None,
                                    discovered_from="OPENAPI",
                                    source_url=spec_url,
                                    evidence={
                                        "source": "openapi_spec",
                                        "spec_url": spec_url,
                                        "summary": method_info.get("summary", ""),
                                        "operation_id": method_info.get("operationId", "")
                                    },
                                    confidence="High",
                                    evidence_status="OBSERVED",
                                    in_scope=True,
                                    external=False,
                                    duplicate_key=dup_key
                                )
                                if self._add_asset(asset) and on_event:
                                    res = on_event("API_DISCOVERED", {"url": full_api_url, "method": m_upper})
                                    if asyncio.iscoroutine(res):
                                        await res
                        break
                except Exception:
                    pass

    # -------------------------------------------------------------------------
    # Robots.txt & Sitemap Discovery
    # -------------------------------------------------------------------------

    async def _probe_metadata_files(self, on_event: Optional[Callable[[str, Dict[str, Any]], Any]] = None):
        """Inspect robots.txt and sitemap.xml for candidate paths."""
        # 1. robots.txt
        robots_url = normalize_url("/robots.txt", self.target_origin)
        r_resp = await self._safe_fetch("GET", robots_url)
        sitemaps_to_check = [normalize_url("/sitemap.xml", self.target_origin)]

        if r_resp and r_resp.status_code == 200:
            self._add_asset(DiscoveredAsset(
                asset_type="ROBOTS",
                url=robots_url,
                normalized_url=robots_url,
                hostname=self.target_hostname,
                path="/robots.txt",
                query_parameters=[],
                http_method="GET",
                content_type=r_resp.headers.get("content-type"),
                status_code=200,
                discovered_from="ROBOTS",
                source_url=self.raw_target_url,
                evidence={"source": "robots.txt", "lines_count": len(r_resp.text.splitlines())},
                confidence="High",
                evidence_status="VERIFIED",
                in_scope=True,
                external=False,
                duplicate_key=generate_duplicate_key("ROBOTS", robots_url)
            ))

            for line in r_resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith("sitemap:"):
                    sm_url = line.split(":", 1)[1].strip()
                    clean_sm = normalize_url(sm_url, self.target_origin)
                    if clean_sm not in sitemaps_to_check:
                        sitemaps_to_check.append(clean_sm)
                elif line.lower().startswith(("disallow:", "allow:")):
                    rule_path = line.split(":", 1)[1].strip()
                    if rule_path and not rule_path.startswith("*"):
                        full_rule_url = normalize_url(rule_path, self.target_origin)
                        if is_same_host(full_rule_url, self.raw_target_url):
                            parsed = urllib.parse.urlparse(full_rule_url)
                            dup_key = generate_duplicate_key("PAGE", full_rule_url)
                            asset = DiscoveredAsset(
                                asset_type="PAGE",
                                url=full_rule_url,
                                normalized_url=full_rule_url,
                                hostname=self.target_hostname,
                                path=parsed.path or "/",
                                query_parameters=extract_query_param_names(full_rule_url),
                                http_method="GET",
                                content_type=None,
                                status_code=None,
                                discovered_from="ROBOTS",
                                source_url=robots_url,
                                evidence={"source": "robots.txt", "directive": line},
                                confidence="High",
                                evidence_status="OBSERVED",
                                in_scope=True,
                                external=False,
                                duplicate_key=dup_key
                            )
                            if self._add_asset(asset):
                                self._enqueue(CrawlCandidate(priority=7, url=full_rule_url, depth=1, source_url=robots_url, discovery_reason="DISCOVERED_FROM_ROBOTS"))

        # 2. Sitemaps
        for sm_url in sitemaps_to_check:
            if not is_same_host(sm_url, self.raw_target_url):
                continue
            sm_resp = await self._safe_fetch("GET", sm_url)
            if sm_resp and sm_resp.status_code == 200:
                self._add_asset(DiscoveredAsset(
                    asset_type="SITEMAP",
                    url=sm_url,
                    normalized_url=sm_url,
                    hostname=self.target_hostname,
                    path=urllib.parse.urlparse(sm_url).path or "/sitemap.xml",
                    query_parameters=[],
                    http_method="GET",
                    content_type=sm_resp.headers.get("content-type"),
                    status_code=200,
                    discovered_from="SITEMAP",
                    source_url=self.raw_target_url,
                    evidence={"source": "sitemap.xml", "url": sm_url},
                    confidence="High",
                    evidence_status="VERIFIED",
                    in_scope=True,
                    external=False,
                    duplicate_key=generate_duplicate_key("SITEMAP", sm_url)
                ))

                loc_urls = re.findall(r"<loc>([^<]+)</loc>", sm_resp.text, re.I)
                for loc in loc_urls[:50]:  # Bound sitemap links per file
                    full_loc = normalize_url(loc, self.target_origin)
                    same_host = is_same_host(full_loc, self.raw_target_url)
                    parsed_loc = urllib.parse.urlparse(full_loc)

                    dup_key = generate_duplicate_key("PAGE", full_loc)
                    asset = DiscoveredAsset(
                        asset_type="PAGE",
                        url=full_loc,
                        normalized_url=full_loc,
                        hostname=parsed_loc.hostname or self.target_hostname,
                        path=parsed_loc.path or "/",
                        query_parameters=extract_query_param_names(full_loc),
                        http_method="GET",
                        content_type=None,
                        status_code=None,
                        discovered_from="SITEMAP",
                        source_url=sm_url,
                        evidence={"source": "sitemap.xml", "loc": loc},
                        confidence="High",
                        evidence_status="OBSERVED",
                        in_scope=same_host,
                        external=not same_host,
                        duplicate_key=dup_key
                    )
                    if self._add_asset(asset) and same_host:
                        self._enqueue(CrawlCandidate(priority=6, url=full_loc, depth=1, source_url=sm_url, discovery_reason="DISCOVERED_FROM_SITEMAP"))

                if on_event:
                    res = on_event("SITEMAP_EXPANDED", {"sitemap_url": sm_url, "url_count": len(loc_urls)})
                    if asyncio.iscoroutine(res):
                        await res

    # -------------------------------------------------------------------------
    # Main Crawl Loop
    # -------------------------------------------------------------------------

    async def execute_discovery(
        self,
        is_cancelled: Optional[Callable[[], bool]] = None,
        on_event: Optional[Callable[[str, Dict[str, Any]], Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute bounded crawl frontier and static attack surface discovery.
        """
        async def emit(event_name: str, payload: Dict[str, Any]):
            if on_event:
                try:
                    res = on_event(event_name, payload)
                    if asyncio.iscoroutine(res):
                        await res
                except Exception:
                    pass

        await emit("ATTACK_SURFACE_STARTED", {"target_url": self.raw_target_url})

        # Seed root URL into frontier
        self._enqueue(CrawlCandidate(priority=1, url=self.normalized_target, depth=0, source_url=None, discovery_reason="TARGET_ROOT"))

        # Expand robots.txt and sitemap.xml concurrently
        await self._probe_metadata_files(on_event=emit)

        # Probe OpenAPI specifications concurrently
        await self._probe_openapi_specifications(on_event=emit)

        # Crawl Frontier Loop
        while self.frontier:
            if is_cancelled and is_cancelled():
                await emit("ATTACK_SURFACE_CANCELLED", {"reason": "Cancelled by operator"})
                break

            if len(self.assets) >= self.max_urls:
                if "MAX_DISCOVERED_URLS" not in self.limits_reached:
                    self.limits_reached.append("MAX_DISCOVERED_URLS")
                await emit("CRAWL_LIMIT_REACHED", {"limit": "MAX_DISCOVERED_URLS", "count": len(self.assets)})
                break

            if self.requests_total >= self.max_requests:
                if "MAX_REQUESTS_PER_SCAN" not in self.limits_reached:
                    self.limits_reached.append("MAX_REQUESTS_PER_SCAN")
                await emit("CRAWL_LIMIT_REACHED", {"limit": "MAX_REQUESTS_PER_SCAN", "count": self.requests_total})
                break

            candidate = heapq.heappop(self.frontier)
            norm_url = normalize_url(candidate.url)

            if norm_url in self.visited_urls:
                continue
            self.visited_urls.add(norm_url)

            # Issue safe HTTP GET
            resp = await self._safe_fetch("GET", norm_url)
            if not resp:
                continue

            # Update/Register terminal response asset
            parsed = urllib.parse.urlparse(resp.final_url)
            same_host = is_same_host(resp.final_url, self.raw_target_url)
            content_type = resp.headers.get("content-type", "").lower()

            asset_type = "PAGE"
            if "javascript" in content_type:
                asset_type = "SCRIPT"
            elif "json" in content_type:
                asset_type = "API"

            dup_key = generate_duplicate_key(asset_type, resp.final_url, candidate.method)
            asset = DiscoveredAsset(
                asset_type=asset_type,
                url=resp.final_url,
                normalized_url=normalize_url(resp.final_url),
                hostname=parsed.hostname or self.target_hostname,
                path=parsed.path or "/",
                query_parameters=extract_query_param_names(resp.final_url),
                http_method=candidate.method,
                content_type=resp.headers.get("content-type"),
                status_code=resp.status_code,
                discovered_from=candidate.discovery_reason,
                source_url=candidate.source_url,
                evidence={
                    "status_code": resp.status_code,
                    "content_length": len(resp.content_bytes),
                    "http_version": resp.http_version,
                    "elapsed_seconds": resp.elapsed_seconds,
                    "is_truncated": resp.is_truncated
                },
                confidence="High",
                evidence_status="VERIFIED",
                in_scope=same_host,
                external=not same_host,
                duplicate_key=dup_key
            )
            self._add_asset(asset)
            self.crawl_urls_verified += 1

            await emit("CRAWL_URL_VERIFIED", {
                "url": resp.final_url,
                "status_code": resp.status_code,
                "asset_type": asset_type
            })

            # If HTML and within depth, parse links and forms
            if "html" in content_type:
                self._parse_html_assets(resp.final_url, resp.text, candidate.depth)

            # If JavaScript, perform static analysis
            elif "javascript" in content_type:
                self._analyze_javascript_content(resp.final_url, resp.text)
                await emit("SCRIPT_ANALYZED", {"url": resp.final_url})

        # Summary assembly
        await emit("ATTACK_SURFACE_COMPLETED", {
            "total_assets": len(self.assets),
            "requests_made": self.requests_total,
            "bytes_received": self.bytes_received,
            "limits_reached": self.limits_reached
        })

        assets_list = list(self.assets.values())
        return {
            "scan_target": self.raw_target_url,
            "total_assets": len(assets_list),
            "requests_total": self.requests_total,
            "bytes_received": self.bytes_received,
            "crawl_urls_verified": self.crawl_urls_verified,
            "limits_reached": self.limits_reached,
            "assets": [
                {
                    "asset_type": a.asset_type,
                    "url": a.url,
                    "normalized_url": a.normalized_url,
                    "hostname": a.hostname,
                    "path": a.path,
                    "query_parameters": a.query_parameters,
                    "http_method": a.http_method,
                    "content_type": a.content_type,
                    "status_code": a.status_code,
                    "discovered_from": a.discovered_from,
                    "source_url": a.source_url,
                    "evidence": a.evidence,
                    "confidence": a.confidence,
                    "evidence_status": a.evidence_status,
                    "in_scope": a.in_scope,
                    "external": a.external,
                    "duplicate_key": a.duplicate_key
                }
                for a in assets_list
            ]
        }
