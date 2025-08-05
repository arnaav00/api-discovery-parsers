import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import json


def extract_base_url(url: str) -> str:
    """
    Extract the base URL (scheme + netloc) from a full URL.
    
    Args:
        url: The full URL to extract base from
        
    Returns:
        The base URL (e.g., "https://api.example.com")
    """
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        return ""


def extract_path_from_url(url: str) -> str:
    """
    Extract the path from a URL, including query parameters.
    
    Args:
        url: The full URL to extract path from
        
    Returns:
        The path with query parameters (e.g., "/api/v1/users?page=1")
    """
    try:
        parsed = urlparse(url)
        path = parsed.path
        if parsed.query:
            path += f"?{parsed.query}"
        return path
    except Exception:
        return ""


def normalize_url(url: str) -> str:
    """
    Normalize a URL by removing default ports and trailing slashes.
    
    Args:
        url: The URL to normalize
        
    Returns:
        The normalized URL
    """
    try:
        parsed = urlparse(url)
        
        # Remove default ports
        if parsed.port:
            if (parsed.scheme == 'http' and parsed.port == 80) or \
               (parsed.scheme == 'https' and parsed.port == 443):
                netloc = parsed.hostname
            else:
                netloc = f"{parsed.hostname}:{parsed.port}"
        else:
            netloc = parsed.hostname
        
        # Remove trailing slash from path (except for root)
        path = parsed.path
        if path != '/' and path.endswith('/'):
            path = path[:-1]
        
        return urlunparse((
            parsed.scheme,
            netloc,
            path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
    except Exception:
        return url


def is_api_endpoint(url: str, method: str = "GET") -> bool:
    """
    Determine if a URL likely represents an API endpoint.
    
    Args:
        url: The URL to check
        method: The HTTP method
        
    Returns:
        True if the URL appears to be an API endpoint
    """
    # Common API path patterns
    api_patterns = [
        r'/api/',
        r'/v\d+/',
        r'/rest/',
        r'/graphql',
        r'/swagger',
        r'/openapi',
        r'/docs',
        r'/endpoint',
        r'/service',
        r'/ws/',
        r'/socket',
        r'/webhook',
        r'/callback',
        r'/auth',
        r'/oauth',
        r'/token',
        r'/login',
        r'/logout',
        r'/register',
        r'/user',
        r'/users',
        r'/data',
        r'/json',
        r'/xml',
        r'/rpc',
        r'/soap',
        r'/rss',
        r'/feed',
        r'/status',
        r'/health',
        r'/ping',
        r'/metrics',
        r'/admin',
        r'/dashboard',
        r'/console',
        r'/management',
        r'/config',
        r'/settings'
    ]
    
    # Check for API patterns in the path
    path = extract_path_from_url(url).lower()
    for pattern in api_patterns:
        if re.search(pattern, path):
            return True
    
    # Check for JSON/XML content types in URL
    if any(ext in url.lower() for ext in ['.json', '.xml', '.rss', '.atom']):
        return True
    
    # Check for common API file extensions
    if any(ext in url.lower() for ext in ['.api', '.rest', '.service']):
        return True
    
    # Check if it's a POST/PUT/DELETE request (more likely to be API)
    if method.upper() in ['POST', 'PUT', 'DELETE', 'PATCH']:
        return True
    
    return False


def extract_query_parameters(url: str) -> List[Dict[str, str]]:
    """
    Extract query parameters from a URL.
    
    Args:
        url: The URL to extract parameters from
        
    Returns:
        List of parameter dictionaries with 'name' and 'value' keys
    """
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        params = []
        for name, values in query_params.items():
            for value in values:
                params.append({
                    'name': name,
                    'value': value
                })
        
        return params
    except Exception:
        return []


def extract_path_parameters(path: str) -> List[str]:
    """
    Extract potential path parameters from a URL path.
    
    Args:
        path: The URL path to analyze
        
    Returns:
        List of potential path parameter names
    """
    # Common path parameter patterns
    param_patterns = [
        r'/{([^/]+)}',  # {param}
        r'/:([^/]+)',   # :param
        r'/\$([^/]+)',  # $param
        r'/\*([^/]*)',  # *param
    ]
    
    params = []
    for pattern in param_patterns:
        matches = re.findall(pattern, path)
        params.extend(matches)
    
    # Also look for numeric segments that might be IDs
    numeric_segments = re.findall(r'/(\d+)', path)
    if numeric_segments:
        params.extend(['id'] * len(numeric_segments))
    
    # Look for UUID-like segments
    uuid_pattern = r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
    uuid_matches = re.findall(uuid_pattern, path, re.IGNORECASE)
    if uuid_matches:
        params.extend(['uuid'] * len(uuid_matches))
    
    return list(set(params))  # Remove duplicates


def build_url_with_params(base_url: str, path: str, params: Dict[str, str] = None) -> str:
    """
    Build a URL with query parameters.
    
    Args:
        base_url: The base URL
        path: The path
        params: Query parameters to add
        
    Returns:
        The complete URL with parameters
    """
    try:
        if not path.startswith('/'):
            path = '/' + path
        
        url = base_url + path
        
        if params:
            query_string = urlencode(params)
            url += f"?{query_string}"
        
        return url
    except Exception:
        return base_url + path


def extract_domain_from_url(url: str) -> str:
    """
    Extract the domain from a URL.
    
    Args:
        url: The URL to extract domain from
        
    Returns:
        The domain name
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return ""


def is_https(url: str) -> bool:
    """
    Check if a URL uses HTTPS.
    
    Args:
        url: The URL to check
        
    Returns:
        True if the URL uses HTTPS
    """
    try:
        parsed = urlparse(url)
        return parsed.scheme.lower() == 'https'
    except Exception:
        return False


def get_url_depth(url: str) -> int:
    """
    Get the depth (number of path segments) of a URL.
    
    Args:
        url: The URL to analyze
        
    Returns:
        The number of path segments
    """
    try:
        parsed = urlparse(url)
        path = parsed.path.strip('/')
        if not path:
            return 0
        return len(path.split('/'))
    except Exception:
        return 0


def extract_api_version_from_url(url: str) -> Optional[str]:
    """
    Extract API version from URL patterns like /v1/, /api/v2/, etc.
    
    Args:
        url: The URL to extract version from
        
    Returns:
        The API version if found, None otherwise
    """
    patterns = [
        r'/v(\d+(?:\.\d+)?)/',
        r'/api/v(\d+(?:\.\d+)?)/',
        r'/version/(\d+(?:\.\d+)?)/',
        r'/api/version/(\d+(?:\.\d+)?)/'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, url, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return None


def sanitize_url_for_logging(url: str) -> str:
    """
    Sanitize a URL for logging by removing sensitive parameters.
    
    Args:
        url: The URL to sanitize
        
    Returns:
        The sanitized URL
    """
    sensitive_params = [
        'password', 'token', 'key', 'secret', 'auth', 'authorization',
        'api_key', 'apikey', 'access_token', 'refresh_token', 'session',
        'credential', 'private', 'signature'
    ]
    
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Remove sensitive parameters
        for param in sensitive_params:
            if param in query_params:
                query_params[param] = ['***']
        
        # Rebuild query string
        new_query = urlencode(query_params, doseq=True)
        
        # Rebuild URL
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
    except Exception:
        return url 