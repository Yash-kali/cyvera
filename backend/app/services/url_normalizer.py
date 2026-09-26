import re
import urllib.parse
from typing import Optional, List, Tuple


DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443
}


def normalize_url(url: str, base_url: Optional[str] = None) -> str:
    """
    Deterministic URL normalizer for attack surface discovery.
    Rules:
    1. Resolve relative URLs against base_url if provided.
    2. Lowercase scheme and hostname.
    3. Strip default ports (:80 for http/ws, :443 for https/wss).
    4. Strip URL fragments (#...) completely.
    5. Deduplicate duplicate path slashes (e.g., //page -> /page).
    6. Normalize trailing slashes (strip trailing slash unless path is root '/').
    7. Sort query parameters deterministically by key while preserving input parameters.
    """
    raw_url = str(url).strip()
    if not raw_url:
        return ""

    # Resolve against base_url if relative
    if base_url:
        raw_url = urllib.parse.urljoin(base_url, raw_url)

    # If scheme missing completely, default to https
    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    try:
        parsed = urllib.parse.urlparse(raw_url)
    except Exception:
        return raw_url

    scheme = (parsed.scheme or "http").lower()
    hostname = (parsed.hostname or "").lower().strip()

    # Port normalization
    port = parsed.port
    if port and DEFAULT_PORTS.get(scheme) == port:
        port = None

    netloc = hostname
    if port:
        netloc = f"{hostname}:{port}"

    # Path normalization
    path = parsed.path or "/"
    # Deduplicate consecutive slashes in path
    path = re.sub(r"/+", "/", path)
    # Strip trailing slash unless root path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    # Query normalization
    query_parts = []
    if parsed.query:
        # Parse query params and sort deterministically
        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        # Sort by key, then value
        sorted_params = sorted(params, key=lambda kv: (kv[0], kv[1]))
        query_parts = urllib.parse.urlencode(sorted_params)

    # Reconstruct clean URL (fragment explicitly omitted)
    return urllib.parse.urlunparse((
        scheme,
        netloc,
        path,
        parsed.params,
        query_parts,
        ""  # Strip fragment
    ))


def is_same_origin(url_a: str, url_b: str) -> bool:
    """
    Check if two URLs share the exact same origin (scheme, host, and port).
    """
    try:
        p_a = urllib.parse.urlparse(url_a.strip().lower())
        p_b = urllib.parse.urlparse(url_b.strip().lower())

        scheme_a = p_a.scheme or "http"
        scheme_b = p_b.scheme or "http"

        port_a = p_a.port or DEFAULT_PORTS.get(scheme_a, 80)
        port_b = p_b.port or DEFAULT_PORTS.get(scheme_b, 80)

        host_a = p_a.hostname or ""
        host_b = p_b.hostname or ""

        return (scheme_a == scheme_b) and (host_a == host_b) and (port_a == port_b)
    except Exception:
        return False


def is_same_host(url_a: str, url_b: str) -> bool:
    """
    Check if two URLs share the same hostname (regardless of scheme/port).
    """
    try:
        p_a = urllib.parse.urlparse(url_a.strip().lower())
        p_b = urllib.parse.urlparse(url_b.strip().lower())
        return (p_a.hostname or "") == (p_b.hostname or "")
    except Exception:
        return False


def extract_query_param_names(url: str) -> List[str]:
    """
    Extract sorted list of unique query parameter names from a URL.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return []
        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        param_names = sorted(list(set(p[0] for p in params if p[0])))
        return param_names
    except Exception:
        return []


def generate_duplicate_key(
    asset_type: str,
    url: str,
    method: str = "GET",
    extra: Optional[str] = None
) -> str:
    """
    Generate deterministic deduplication key for an attack surface asset.
    Examples:
    PAGE -> PAGE:https://example.com/about
    ENDPOINT -> ENDPOINT:GET:https://example.com/api/users
    FORM -> FORM:POST:https://example.com/login:username,password
    SCRIPT -> SCRIPT:https://example.com/static/bundle.js
    """
    norm_url = normalize_url(url)
    clean_type = asset_type.upper().strip()
    clean_method = method.upper().strip()

    if clean_type in ("PAGE", "SCRIPT", "RESOURCE", "DOCUMENT", "ROBOTS", "SITEMAP", "WEB_SOCKET", "GRAPHQL"):
        return f"{clean_type}:{norm_url}"
    elif clean_type in ("ENDPOINT", "API"):
        return f"{clean_type}:{clean_method}:{norm_url}"
    elif clean_type == "FORM":
        fields_str = (extra or "").strip()
        return f"FORM:{clean_method}:{norm_url}:{fields_str}"
    else:
        extra_str = f":{extra}" if extra else ""
        return f"{clean_type}:{clean_method}:{norm_url}{extra_str}"
