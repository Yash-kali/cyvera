import asyncio
import io
import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient

# Add backend to sys.path
sys.path.insert(0, "backend")

from app.main import app
from app.database import AsyncSessionLocal
from app.models import Scan, User, AttackSurfaceAsset
from app.services.safe_client import SafeHttpClient, SafeHttpResponse
from app.services.url_normalizer import (
    normalize_url,
    is_same_origin,
    is_same_host,
    extract_query_param_names,
    generate_duplicate_key
)
from app.services.discovery_engine import DiscoveryEngine, CrawlCandidate, DiscoveredAsset


class TestPhase7DAttackSurface(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        # Login Yash
        login_res = cls.client.post("/api/v1/auth/login", json={"email_or_username": "Yash", "password": "Password123!"})
        if login_res.status_code != 200:
            login_res = cls.client.post("/api/v1/auth/login", json={"email_or_username": "Yash", "password": "Yash@4050"})
        assert login_res.status_code == 200, f"Failed to login: {login_res.text}"
        cls.token = login_res.json()["access_token"]
        cls.headers = {"Authorization": f"Bearer {cls.token}"}

    # 1. URL Normalization: Fragments
    def test_01_url_normalization_strips_fragments(self):
        url1 = normalize_url("https://example.com/dashboard#section1")
        url2 = normalize_url("https://example.com/dashboard#")
        url3 = normalize_url("https://example.com/dashboard")
        self.assertEqual(url1, "https://example.com/dashboard")
        self.assertEqual(url1, url2)
        self.assertEqual(url2, url3)

    # 2. URL Normalization: Trailing slashes
    def test_02_url_normalization_trailing_slashes(self):
        url_slash = normalize_url("https://example.com/api/v1/")
        url_no_slash = normalize_url("https://example.com/api/v1")
        url_root = normalize_url("https://example.com/")
        self.assertEqual(url_slash, "https://example.com/api/v1")
        self.assertEqual(url_slash, url_no_slash)
        self.assertEqual(url_root, "https://example.com/")

    # 3. URL Normalization: Sorted query parameters
    def test_03_url_normalization_sorts_query_parameters(self):
        url_a = normalize_url("https://example.com/search?b=2&a=1&c=3")
        url_b = normalize_url("https://example.com/search?c=3&a=1&b=2")
        self.assertEqual(url_a, "https://example.com/search?a=1&b=2&c=3")
        self.assertEqual(url_a, url_b)

    # 4. URL Normalization: Duplicate keys
    def test_04_duplicate_key_generation(self):
        key1 = generate_duplicate_key("PAGE", "https://example.com/about#team")
        key2 = generate_duplicate_key("PAGE", "https://example.com/about")
        self.assertEqual(key1, "PAGE:https://example.com/about")
        self.assertEqual(key1, key2)

        form_key1 = generate_duplicate_key("FORM", "https://example.com/login", "POST", "email,password")
        form_key2 = generate_duplicate_key("FORM", "https://example.com/login#frag", "POST", "email,password")
        self.assertEqual(form_key1, form_key2)

    # 5. Crawl Frontier: Depth limit
    def test_05_crawl_frontier_respects_max_depth(self):
        engine = DiscoveryEngine("https://example.com", max_depth=2, max_urls=100)
        # Depth 1 candidate
        c1 = CrawlCandidate(priority=2, url="https://example.com/d1", depth=1)
        engine._enqueue(c1)
        self.assertEqual(len(engine.frontier), 1)

        # Depth 2 candidate
        c2 = CrawlCandidate(priority=2, url="https://example.com/d2", depth=2)
        engine._enqueue(c2)
        self.assertEqual(len(engine.frontier), 2)

        # Depth 3 candidate (exceeds max_depth=2) -> MUST NOT be enqueued
        c3 = CrawlCandidate(priority=2, url="https://example.com/d3", depth=3)
        engine._enqueue(c3)
        self.assertEqual(len(engine.frontier), 2)

    # 6. Crawl Frontier: Max URL budget
    def test_06_crawl_frontier_respects_max_discovered_urls(self):
        engine = DiscoveryEngine("https://example.com", max_urls=5)
        for i in range(10):
            asset = DiscoveredAsset(
                asset_type="PAGE",
                url=f"https://example.com/page{i}",
                normalized_url=f"https://example.com/page{i}",
                hostname="example.com",
                path=f"/page{i}",
                query_parameters=[],
                http_method="GET",
                content_type="text/html",
                status_code=200,
                discovered_from="HTML",
                source_url="https://example.com",
                evidence={},
                confidence="High",
                evidence_status="OBSERVED",
                in_scope=True,
                external=False,
                duplicate_key=f"PAGE:https://example.com/page{i}"
            )
            engine._add_asset(asset)

        self.assertEqual(len(engine.assets), 5)
        self.assertIn("MAX_DISCOVERED_URLS", engine.limits_reached)

    # 7. Crawl Frontier: Max requests budget
    def test_07_crawl_frontier_respects_max_requests_per_scan(self):
        engine = DiscoveryEngine("https://example.com", max_requests=3)
        mock_client = AsyncMock()
        mock_client.get.return_value = SafeHttpResponse(
            status_code=200, headers={}, text="OK", content_bytes=b"OK", final_url="https://example.com"
        )
        engine.client = mock_client

        async def run_fetches():
            res1 = await engine._safe_fetch("GET", "https://example.com/1")
            res2 = await engine._safe_fetch("GET", "https://example.com/2")
            res3 = await engine._safe_fetch("GET", "https://example.com/3")
            res4 = await engine._safe_fetch("GET", "https://example.com/4")
            return res1, res2, res3, res4

        r1, r2, r3, r4 = asyncio.run(run_fetches())
        self.assertIsNotNone(r1)
        self.assertIsNotNone(r2)
        self.assertIsNotNone(r3)
        self.assertIsNone(r4, "Request beyond max_requests must return None")
        self.assertEqual(engine.requests_total, 3)
        self.assertIn("MAX_REQUESTS_PER_SCAN", engine.limits_reached)

    # 8. Crawl Concurrency: Bounded by semaphore
    def test_08_concurrency_bounded_by_semaphore(self):
        engine = DiscoveryEngine("https://example.com", max_concurrency=2)
        self.assertEqual(engine.semaphore._value, 2)

    # 9. Response Size: Bounded by SafeHttpClient
    def test_09_response_size_bounded_by_safe_http_client(self):
        engine = DiscoveryEngine("https://example.com")
        self.assertEqual(engine.client.config.max_response_bytes, 2 * 1024 * 1024)

    # 10. Timeout Controls
    def test_10_timeout_controls_configured(self):
        engine = DiscoveryEngine("https://example.com")
        self.assertGreater(engine.client.config.request_timeout_seconds, 0)
        self.assertGreater(engine.client.config.connect_timeout_seconds, 0)

    # 11. Cancellation: Halts crawl immediately
    def test_11_cancellation_halts_discovery(self):
        engine = DiscoveryEngine("https://example.com")
        cancelled = True
        is_cancelled = lambda: cancelled

        events = []
        def on_event(ev, payload):
            events.append(ev)

        res = asyncio.run(engine.execute_discovery(is_cancelled=is_cancelled, on_event=on_event))
        self.assertIn("ATTACK_SURFACE_CANCELLED", events)

    # 12. HTML Link Extraction
    def test_12_html_link_extraction(self):
        engine = DiscoveryEngine("https://example.com")
        html = """
        <html>
            <head><title>Test App</title></head>
            <body>
                <a href="/about">About Us</a>
                <a href="/products?category=security">Products</a>
                <a href="https://external-domain.org/help">Help</a>
                <link rel="stylesheet" href="/assets/style.css">
                <script src="/static/bundle.js"></script>
            </body>
        </html>
        """
        engine._parse_html_assets("https://example.com", html, current_depth=0)

        # In-scope page
        self.assertIn("PAGE:https://example.com/about", engine.assets)
        # In-scope page with query
        self.assertIn("PAGE:https://example.com/products?category=security", engine.assets)
        # External resource
        self.assertIn("PAGE:https://external-domain.org/help", engine.assets)
        self.assertTrue(engine.assets["PAGE:https://external-domain.org/help"].external)
        # Script
        self.assertIn("SCRIPT:https://example.com/static/bundle.js", engine.assets)
        # Resource link
        self.assertIn("RESOURCE:https://example.com/assets/style.css", engine.assets)

    # 13. Form Extraction: Action, method, fields without submission
    def test_13_form_extraction_without_submission(self):
        engine = DiscoveryEngine("https://example.com")
        html = """
        <form action="/auth/login" method="POST">
            <input type="text" name="username" required>
            <input type="password" name="password" required>
            <input type="hidden" name="csrf_token" value="secret123">
            <button type="submit">Sign In</button>
        </form>
        """
        engine._parse_html_assets("https://example.com", html, current_depth=0)

        form_key = generate_duplicate_key("FORM", "https://example.com/auth/login", "POST", "csrf_token,password,username")
        self.assertIn(form_key, engine.assets)
        asset = engine.assets[form_key]
        self.assertEqual(asset.asset_type, "FORM")
        self.assertEqual(asset.http_method, "POST")
        self.assertEqual(asset.evidence["fields_count"], 3)
        # Confirm field names recorded
        field_names = [f["name"] for f in asset.evidence["fields"]]
        self.assertIn("username", field_names)
        self.assertIn("password", field_names)
        self.assertIn("csrf_token", field_names)

    # 14. Query Parameters Discovery
    def test_14_query_parameter_discovery(self):
        params = extract_query_param_names("https://example.com/search?q=cyber&sort=desc&page=1")
        self.assertEqual(params, ["page", "q", "sort"])

    # 15. JavaScript Static Analysis: API candidates
    def test_15_javascript_static_analysis_api_candidates(self):
        engine = DiscoveryEngine("https://example.com")
        js_code = """
        function loadUsers() {
            fetch('/api/v1/users?active=true').then(r => r.json());
            axios.get('/api/v1/billing');
        }
        """
        engine._analyze_javascript_content("https://example.com/bundle.js", js_code)

        self.assertIn("API:GET:https://example.com/api/v1/users?active=true", engine.assets)
        self.assertIn("API:GET:https://example.com/api/v1/billing", engine.assets)
        self.assertEqual(engine.assets["API:GET:https://example.com/api/v1/users?active=true"].evidence_status, "INFERRED")

    # 16. JavaScript Static Analysis: Zero JS execution
    def test_16_javascript_static_analysis_does_not_execute_code(self):
        engine = DiscoveryEngine("https://example.com")
        # Malicious JS trying to write a file or mutate environment
        malicious_js = """
        eval("throw new Error('Executed!')");
        window.location = "http://bad.org";
        """
        # Should not raise exception
        engine._analyze_javascript_content("https://example.com/script.js", malicious_js)

    # 17. OpenAPI Specification Parsing
    def test_17_openapi_specification_parsing(self):
        engine = DiscoveryEngine("https://example.com")
        openapi_doc = json.dumps({
            "openapi": "3.0.0",
            "paths": {
                "/api/v1/scans": {
                    "get": {"summary": "List Scans", "operationId": "listScans"},
                    "post": {"summary": "Create Scan", "operationId": "createScan"}
                }
            }
        })

        mock_resp = SafeHttpResponse(
            status_code=200,
            headers={"content-type": "application/json"},
            text=openapi_doc,
            content_bytes=openapi_doc.encode(),
            final_url="https://example.com/openapi.json"
        )
        engine._safe_fetch = AsyncMock(return_value=mock_resp)

        asyncio.run(engine._probe_openapi_specifications())

        self.assertIn("DOCUMENT:https://example.com/openapi.json", engine.assets)
        self.assertIn("API:GET:https://example.com/api/v1/scans", engine.assets)
        self.assertIn("API:POST:https://example.com/api/v1/scans", engine.assets)
        self.assertEqual(engine.assets["API:GET:https://example.com/api/v1/scans"].discovered_from, "OPENAPI")
        self.assertEqual(engine.assets["API:GET:https://example.com/api/v1/scans"].evidence_status, "OBSERVED")

    # 18. GraphQL Candidate Detection
    def test_18_graphql_candidate_detection(self):
        engine = DiscoveryEngine("https://example.com")
        js_code = 'const endpoint = "/graphql"; fetch(endpoint, { method: "POST" });'
        engine._analyze_javascript_content("https://example.com/app.js", js_code)

        self.assertIn("GRAPHQL:https://example.com/graphql", engine.assets)
        self.assertEqual(engine.assets["GRAPHQL:https://example.com/graphql"].asset_type, "GRAPHQL")
        self.assertEqual(engine.assets["GRAPHQL:https://example.com/graphql"].evidence_status, "INFERRED")

    # 19. WebSocket Candidate Detection
    def test_19_websocket_candidate_detection(self):
        engine = DiscoveryEngine("https://example.com")
        js_code = 'const socket = new WebSocket("wss://example.com/ws/live-feed");'
        engine._analyze_javascript_content("https://example.com/feed.js", js_code)

        self.assertIn("WEB_SOCKET:wss://example.com/ws/live-feed", engine.assets)
        self.assertEqual(engine.assets["WEB_SOCKET:wss://example.com/ws/live-feed"].asset_type, "WEB_SOCKET")
        self.assertEqual(engine.assets["WEB_SOCKET:wss://example.com/ws/live-feed"].evidence_status, "INFERRED")

    # 20. Sitemap XML Expansion
    def test_20_sitemap_xml_expansion(self):
        engine = DiscoveryEngine("https://example.com")
        sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>https://example.com/docs</loc></url>
            <url><loc>https://example.com/pricing</loc></url>
        </urlset>
        """
        mock_resp = SafeHttpResponse(
            status_code=200,
            headers={"content-type": "application/xml"},
            text=sitemap_xml,
            content_bytes=sitemap_xml.encode(),
            final_url="https://example.com/sitemap.xml"
        )

        def mock_fetch(method, url):
            if "sitemap.xml" in url:
                return mock_resp
            return None

        engine._safe_fetch = AsyncMock(side_effect=mock_fetch)
        asyncio.run(engine._probe_metadata_files())

        self.assertIn("SITEMAP:https://example.com/sitemap.xml", engine.assets)
        self.assertIn("PAGE:https://example.com/docs", engine.assets)
        self.assertIn("PAGE:https://example.com/pricing", engine.assets)

    # 21. Robots.txt Not Marked as Vulnerability
    def test_21_robots_txt_disallow_as_discovery_only(self):
        engine = DiscoveryEngine("https://example.com")
        robots_txt = "User-agent: *\nDisallow: /admin\nDisallow: /internal-portal\n"
        mock_resp = SafeHttpResponse(
            status_code=200,
            headers={"content-type": "text/plain"},
            text=robots_txt,
            content_bytes=robots_txt.encode(),
            final_url="https://example.com/robots.txt"
        )
        engine._safe_fetch = AsyncMock(return_value=mock_resp)

        asyncio.run(engine._probe_metadata_files())

        self.assertIn("ROBOTS:https://example.com/robots.txt", engine.assets)
        self.assertIn("PAGE:https://example.com/admin", engine.assets)
        self.assertEqual(engine.assets["PAGE:https://example.com/admin"].discovered_from, "ROBOTS")
        self.assertEqual(engine.assets["PAGE:https://example.com/admin"].evidence_status, "OBSERVED")

    # 22. External Domains Never Crawled
    def test_22_external_domain_not_crawled(self):
        engine = DiscoveryEngine("https://example.com")
        html = '<a href="https://thirdparty-cdn.com/account/login">External Login</a>'
        engine._parse_html_assets("https://example.com", html, current_depth=0)

        # Asset recorded as external
        key = "PAGE:https://thirdparty-cdn.com/account/login"
        self.assertIn(key, engine.assets)
        self.assertTrue(engine.assets[key].external)
        self.assertFalse(engine.assets[key].in_scope)

        # Frontier must NOT contain external URL
        for candidate in engine.frontier:
            self.assertFalse("thirdparty-cdn.com" in candidate.url)

    # 23. Safe Verification: Non-destructive methods only
    def test_23_safe_verification_non_destructive_only(self):
        engine = DiscoveryEngine("https://example.com")
        methods_called = []

        async def mock_fetch(method, url):
            methods_called.append(method.upper())
            return SafeHttpResponse(
                status_code=200,
                headers={"content-type": "text/html"},
                text="<html><body>Hello</body></html>",
                content_bytes=b"<html><body>Hello</body></html>",
                final_url=url
            )

        engine._safe_fetch = AsyncMock(side_effect=mock_fetch)
        asyncio.run(engine.execute_discovery())

        # Assert no state-changing methods were called
        for m in methods_called:
            self.assertIn(m, ("GET", "HEAD", "OPTIONS"))
            self.assertNotIn(m, ("POST", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT"))

    # 24. Tenant Isolation: Scan ownership required
    def test_24_tenant_isolation_on_attack_surface_api(self):
        # Scan 999999 does not exist / access denied
        res = self.client.get("/api/v1/attack-surface/999999", headers=self.headers)
        self.assertEqual(res.status_code, 404)

        res_sum = self.client.get("/api/v1/attack-surface/999999/summary", headers=self.headers)
        self.assertEqual(res_sum.status_code, 404)

    # 25. Zero Synthetic Vulnerabilities
    def test_25_zero_synthetic_vulnerabilities_in_discovery(self):
        engine = DiscoveryEngine("https://example.com")
        # Ensure discovery assets are NOT findings
        self.assertTrue(issubclass(DiscoveredAsset, object))
        self.assertFalse(hasattr(DiscoveredAsset, "cvss_score"))
        self.assertFalse(hasattr(DiscoveredAsset, "cve_id"))

    # 26. WebSocket Telemetry Events
    def test_26_websocket_telemetry_events_emitted(self):
        engine = DiscoveryEngine("https://example.com")
        events_emitted = []

        def on_event(ev_name, payload):
            events_emitted.append(ev_name)

        engine._safe_fetch = AsyncMock(return_value=SafeHttpResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            text="<html><a href='/contact'>Contact</a></html>",
            content_bytes=b"<html><a href='/contact'>Contact</a></html>",
            final_url="https://example.com"
        ))

        asyncio.run(engine.execute_discovery(on_event=on_event))

        self.assertIn("ATTACK_SURFACE_STARTED", events_emitted)
        self.assertIn("CRAWL_URL_VERIFIED", events_emitted)
        self.assertIn("ATTACK_SURFACE_COMPLETED", events_emitted)

    # 27. Attack Surface API: Success and Serialization for Authenticated Owner
    def test_27_attack_surface_api_success_and_serialization(self):
        scans_res = self.client.get("/api/v1/scans/", headers=self.headers)
        self.assertEqual(scans_res.status_code, 200)
        scans = scans_res.json()
        if not scans:
            return
        scan_id = scans[0]["id"]

        # Insert test asset via AsyncSession
        async def insert_asset():
            async with AsyncSessionLocal() as session:
                asset = AttackSurfaceAsset(
                    scan_id=scan_id,
                    user_id=1,
                    asset_type="PAGE",
                    url="https://scanme.nmap.org/test-page",
                    normalized_url="https://scanme.nmap.org/test-page",
                    hostname="scanme.nmap.org",
                    path="/test-page",
                    query_parameters=["page"],
                    http_method="GET",
                    content_type="text/html",
                    status_code=200,
                    discovered_from="HTML",
                    source_url="https://scanme.nmap.org",
                    evidence={"test": "data"},
                    confidence="High",
                    evidence_status="VERIFIED",
                    in_scope=True,
                    external=False,
                    duplicate_key=f"PAGE:https://scanme.nmap.org/test-page"
                )
                session.add(asset)
                await session.commit()

        asyncio.run(insert_asset())

        # Test list endpoint
        res = self.client.get(f"/api/v1/attack-surface/{scan_id}", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        assets = res.json()
        self.assertIsInstance(assets, list)
        self.assertGreater(len(assets), 0)
        test_item = next((a for a in assets if a["path"] == "/test-page"), None)
        self.assertIsNotNone(test_item)
        self.assertEqual(test_item["asset_type"], "PAGE")
        self.assertEqual(test_item["evidence_status"], "VERIFIED")

        # Test summary endpoint
        res_sum = self.client.get(f"/api/v1/attack-surface/{scan_id}/summary", headers=self.headers)
        self.assertEqual(res_sum.status_code, 200)
        sum_data = res_sum.json()
        self.assertGreater(sum_data["total_assets"], 0)
        self.assertIn("PAGE", sum_data["asset_types"])


if __name__ == "__main__":
    unittest.main()

