from dataclasses import dataclass


@dataclass
class ScanSafetyConfig:
    # Network Timeouts & Connection Limits
    request_timeout_seconds: float = 5.0
    connect_timeout_seconds: float = 3.0
    max_redirects: int = 5
    
    # Request Budgeting
    max_requests_per_scan: int = 150
    max_concurrent_requests: int = 4
    server_max_concurrency_ceiling: int = 10
    
    # Response Limits
    max_response_bytes: int = 2 * 1024 * 1024  # 2MB maximum response body
    max_crawl_depth: int = 3
    max_discovered_urls: int = 100
    
    # Execution Duration
    max_scan_duration_seconds: int = 600  # 10 minutes maximum duration
    
    # Rate Limiting (Token Bucket per target domain)
    rate_limit_rps: float = 5.0  # 5 requests per second default
    
    # Stale Worker Heartbeat Threshold
    stale_heartbeat_seconds: int = 60  # Mark jobs crashed if no heartbeat for 60s


DEFAULT_SAFETY_CONFIG = ScanSafetyConfig()
