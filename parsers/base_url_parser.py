import json
import re
import time
import random
from typing import List, Dict, Any, Optional, Union, Set
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from .base_parser import BaseParser
from models import (
    APIEndpoint, Parameter, Header, AuthInfo, SSLInfo,
    ParameterType, ParameterLocation, AuthType, AuthLocation
)
from utils import (
    extract_base_url, normalize_url, extract_path_from_url,
    normalize_content_type, extract_schema_from_json,
    infer_parameter_types, validate_json_content
)


class BaseURLParser(BaseParser):
    """
    Parser for discovering API endpoints from a base URL.
    
    This parser performs intelligent endpoint enumeration, discovers API patterns,
    detects authentication flows, and infers API structure from discovered endpoints.
    """
    
    def __init__(self):
        """Initialize the Base URL parser."""
        super().__init__()
        self.base_url = None
        self.discovered_endpoints = []
        self.api_patterns = {}
        self.auth_endpoints = []
        self.rate_limits = {}
        self.ssl_info = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'API-Discovery-Parser/1.0',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Common endpoint patterns to test
        self.common_paths = [
            # API versioning
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/v1', '/v2', '/v3', '/v1.0', '/v2.0', 'v3.0',
            
            # Authentication
            '/auth', '/auth/login', '/auth/logout', '/auth/register',
            '/login', '/logout', '/register', '/signup', '/signin',
            '/token', '/oauth', '/oauth/token', '/oauth/authorize',
            '/jwt', '/saml', '/openid',
            
            # Health and status
            '/health', '/status', '/ping', '/ready', '/live',
            '/healthz', '/statusz', '/metrics', '/info',
            
            # Documentation
            '/docs', '/documentation', '/api-docs', '/swagger',
            '/openapi', '/redoc', '/api.json', '/swagger.json',
            
            # Common resources
            '/users', '/user', '/users/me', '/profile',
            '/products', '/items', '/orders', '/customers',
            '/files', '/upload', '/download', '/media',
            '/search', '/query', '/filter',
            
            # Admin and management
            '/admin', '/admin/users', '/admin/settings',
            '/management', '/config', '/settings',
            
            # Webhooks and integrations
            '/webhooks', '/hooks', '/integrations',
            '/callback', '/notifications', '/events',
            
            # Version info
            '/version', '/versions', '/changelog',
            
            # Root endpoints
            '/', '/index', '/home'
        ]
        
        # HTTP methods to test
        self.http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        
        # Rate limiting patterns
        self.rate_limit_headers = [
            'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset',
            'RateLimit-Limit', 'RateLimit-Remaining', 'RateLimit-Reset',
            'X-Rate-Limit', 'Retry-After'
        ]
        
        # Authentication patterns
        self.auth_patterns = {
            'bearer': r'bearer\s+[a-zA-Z0-9\-._~+/]+=*',
            'basic': r'basic\s+[a-zA-Z0-9+/]+=*',
            'api_key': r'[a-zA-Z0-9\-._~+/]{20,}',
            'jwt': r'eyJ[a-zA-Z0-9\-._~+/]+=*'
        }
        
    def can_parse(self, data: Any) -> bool:
        """
        Check if this parser can handle the given data.
        
        Args:
            data: The data to check (can be string, dict, or file path)
            
        Returns:
            True if the parser can handle this data type, False otherwise
        """
        if isinstance(data, str):
            # Check if it's a valid URL
            try:
                parsed = urlparse(data)
                return parsed.scheme in ['http', 'https'] and parsed.netloc
            except Exception:
                return False
        return False
    
    def parse(self, data: Any) -> List[APIEndpoint]:
        """
        Discover API endpoints from a base URL.
        
        Args:
            data: Base URL as string
            
        Returns:
            List of discovered API endpoints
            
        Raises:
            ValueError: If the data is invalid or cannot be parsed
        """
        self.clear_results()
        
        try:
            # Validate and normalize base URL
            self.base_url = self._normalize_base_url(data)
            
            # Discover endpoints
            self._discover_endpoints()
            
            # Analyze patterns
            self._analyze_patterns()
            
            # Update final statistics
            self._update_final_stats()
            
            return self.parsed_endpoints
            
        except Exception as e:
            self.add_error(f"Failed to discover API endpoints: {str(e)}")
            raise ValueError(f"Base URL parsing failed: {str(e)}")
    
    def _normalize_base_url(self, url: str) -> str:
        """
        Normalize the base URL.
        
        Args:
            url: Input URL
            
        Returns:
            Normalized base URL
        """
        # Remove trailing slash
        url = url.rstrip('/')
        
        # Ensure scheme is present
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Validate URL
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError("Invalid URL: no hostname found")
        
        return url
    
    def _discover_endpoints(self):
        """Discover API endpoints from the base URL."""
        # Starting endpoint discovery
        
        # Test common paths
        discovered_endpoints = []
        
        # Use ThreadPoolExecutor for concurrent requests
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Submit all path tests
            future_to_path = {
                executor.submit(self._test_endpoint, path): path 
                for path in self.common_paths
            }
            
            # Collect results
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    endpoint = future.result()
                    if endpoint:
                        discovered_endpoints.append(endpoint)
                        self.add_endpoint(endpoint)
                except Exception as e:
                    self.add_warning(f"Failed to test path {path}: {str(e)}")
        
        # Discover additional endpoints through pattern inference
        self._discover_pattern_based_endpoints(discovered_endpoints)
        
        self.update_stats('discovered_endpoints', len(discovered_endpoints))
    
    def _test_endpoint(self, path: str) -> Optional[APIEndpoint]:
        """
        Test a specific endpoint path.
        
        Args:
            path: Path to test
            
        Returns:
            APIEndpoint if discovered, None otherwise
        """
        url = urljoin(self.base_url, path)
        
        # Test different HTTP methods
        for method in self.http_methods:
            try:
                response = self._make_request(method, url)
                if response and self._is_valid_api_response(response):
                    return self._create_endpoint_from_response(method, path, url, response)
            except Exception as e:
                # Continue with other methods
                continue
        
        return None
    
    def _make_request(self, method: str, url: str, timeout: int = 10) -> Optional[requests.Response]:
        """
        Make an HTTP request with proper error handling.
        
        Args:
            method: HTTP method
            url: URL to request
            timeout: Request timeout
            
        Returns:
            Response object or None if failed
        """
        try:
            # Add random delay to avoid rate limiting
            time.sleep(random.uniform(0.1, 0.5))
            
            response = self.session.request(
                method=method,
                url=url,
                timeout=timeout,
                allow_redirects=True,
                verify=True
            )
            
            return response
            
        except requests.exceptions.RequestException as e:
            # Log but don't fail
            return None
    
    def _is_valid_api_response(self, response: requests.Response) -> bool:
        """
        Check if a response indicates a valid API endpoint.
        
        Args:
            response: HTTP response
            
        Returns:
            True if valid API response
        """
        # Check status code
        if response.status_code >= 400:
            return False
        
        # Check content type
        content_type = response.headers.get('content-type', '').lower()
        if 'application/json' in content_type:
            return True
        if 'text/html' in content_type and response.status_code == 200:
            # Could be API documentation
            return True
        
        # Check for API indicators in headers
        api_headers = ['x-api-version', 'x-rate-limit', 'x-total-count']
        if any(header in response.headers for header in api_headers):
            return True
        
        # Check for API indicators in response body
        try:
            if response.text and len(response.text) < 10000:  # Reasonable size
                # Look for JSON structure
                if response.text.strip().startswith('{') or response.text.strip().startswith('['):
                    return True
                # Look for API documentation indicators
                if any(indicator in response.text.lower() for indicator in ['api', 'swagger', 'openapi', 'endpoint']):
                    return True
        except Exception:
            pass
        
        return False
    
    def _create_endpoint_from_response(self, method: str, path: str, url: str, response: requests.Response) -> APIEndpoint:
        """
        Create an APIEndpoint from HTTP response.
        
        Args:
            method: HTTP method
            path: API path
            url: Full URL
            response: HTTP response
            
        Returns:
            Created APIEndpoint
        """
        # Parse URL components
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Create endpoint
        endpoint = APIEndpoint(
            method=method,
            path=path,
            full_url=url,
            base_url=base_url,
            timestamp=datetime.now().isoformat(),
            har_entry_index=len(self.parsed_endpoints)
        )
        
        # Process headers
        self._process_response_headers(endpoint, response)
        
        # Process response body
        self._process_response_body(endpoint, response)
        
        # Process SSL information
        self._process_ssl_info(endpoint, response)
        
        # Process authentication
        self._process_authentication(endpoint, response)
        
        # Process rate limiting
        self._process_rate_limiting(endpoint, response)
        
        return endpoint
    
    def _process_response_headers(self, endpoint: APIEndpoint, response: requests.Response):
        """
        Process response headers.
        
        Args:
            endpoint: The API endpoint to update
            response: HTTP response
        """
        for header_name, header_value in response.headers.items():
            header = Header(
                name=header_name,
                value=header_value,
                description=''
            )
            endpoint.add_response_header(header)
            
            # Set content type
            if header_name.lower() == 'content-type':
                endpoint.content_type = normalize_content_type(header_value)
    
    def _process_response_body(self, endpoint: APIEndpoint, response: requests.Response):
        """
        Process response body.
        
        Args:
            endpoint: The API endpoint to update
            response: HTTP response
        """
        try:
            content_type = response.headers.get('content-type', '').lower()
            
            if 'application/json' in content_type:
                # Parse JSON response
                json_data = response.json()
                endpoint.response_body = json_data
                
                # Infer schema
                try:
                    schema = extract_schema_from_json(json_data)
                    endpoint.response_body_schema = schema
                except Exception:
                    pass
            else:
                # Store as text
                endpoint.response_body = response.text #[:1000]  # Limit size
                
        except Exception as e:
            # Store error information
            endpoint.response_body = f"Error parsing response: {str(e)}"
    
    def _process_ssl_info(self, endpoint: APIEndpoint, response: requests.Response):
        """
        Process SSL information.
        
        Args:
            endpoint: The API endpoint to update
            response: HTTP response
        """
        if response.url.startswith('https://'):
            # Extract SSL info from response
            ssl_info = SSLInfo(
                is_valid=True,
                protocol_version='TLS',
                cipher_suite='unknown'
            )
            
            # Try to get certificate info
            try:
                cert = response.raw.connection.sock.getpeercert()
                if cert:
                    ssl_info.subject = cert.get('subject', '')
                    ssl_info.issuer = cert.get('issuer', '')
                    ssl_info.serial_number = cert.get('serialNumber', '')
            except Exception:
                pass
            
            endpoint.ssl_info = ssl_info
    
    def _process_authentication(self, endpoint: APIEndpoint, response: requests.Response):
        """
        Process authentication information.
        
        Args:
            endpoint: The API endpoint to update
            response: HTTP response
        """
        # Check for authentication headers
        auth_headers = {
            'authorization': response.headers.get('authorization', ''),
            'x-api-key': response.headers.get('x-api-key', ''),
            'x-auth-token': response.headers.get('x-auth-token', ''),
        }
        
        # Create auth info
        auth_info = self._create_auth_info_from_headers(auth_headers)
        if auth_info:
            endpoint.auth_info = auth_info
        
        # Check if this is an auth endpoint
        if self._is_auth_endpoint(endpoint.path):
            self.auth_endpoints.append(endpoint)
    
    def _is_auth_endpoint(self, path: str) -> bool:
        """
        Check if path is an authentication endpoint.
        
        Args:
            path: API path
            
        Returns:
            True if auth endpoint
        """
        auth_indicators = ['auth', 'login', 'logout', 'register', 'token', 'oauth', 'jwt']
        return any(indicator in path.lower() for indicator in auth_indicators)
    
    def _create_auth_info_from_headers(self, auth_headers: Dict[str, str]) -> Optional[AuthInfo]:
        """
        Create AuthInfo from authentication headers.
        
        Args:
            auth_headers: Authentication headers
            
        Returns:
            The created AuthInfo or None
        """
        auth_info = AuthInfo()
        
        # Check for Bearer token
        auth_header = auth_headers.get('authorization', '')
        if auth_header.lower().startswith('bearer '):
            auth_info.auth_type = AuthType.BEARER
            auth_info.location = AuthLocation.HEADER
            auth_info.token = auth_header[7:]  # Remove 'Bearer ' prefix
        
        # Check for API key
        elif auth_headers.get('x-api-key'):
            auth_info.auth_type = AuthType.API_KEY
            auth_info.location = AuthLocation.HEADER
            auth_info.api_key = 'X-API-Key'
            auth_info.token = auth_headers['x-api-key']
        
        # Check for custom auth token
        elif auth_headers.get('x-auth-token'):
            auth_info.auth_type = AuthType.CUSTOM
            auth_info.location = AuthLocation.HEADER
            auth_info.token = auth_headers['x-auth-token']
        
        else:
            return None
        
        return auth_info
    
    def _process_rate_limiting(self, endpoint: APIEndpoint, response: requests.Response):
        """
        Process rate limiting information.
        
        Args:
            endpoint: The API endpoint to update
            response: HTTP response
        """
        rate_limit_info = {}
        
        for header in self.rate_limit_headers:
            if header in response.headers:
                rate_limit_info[header] = response.headers[header]
        
        if rate_limit_info:
            self.rate_limits[endpoint.path] = rate_limit_info
    
    def _discover_pattern_based_endpoints(self, discovered_endpoints: List[APIEndpoint]):
        """
        Discover additional endpoints based on patterns from discovered endpoints.
        
        Args:
            discovered_endpoints: List of already discovered endpoints
        """
        # Extract patterns from discovered endpoints
        patterns = self._extract_patterns(discovered_endpoints)
        
        # Generate additional paths based on patterns
        additional_paths = self._generate_paths_from_patterns(patterns)
        
        # Test additional paths
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_path = {
                executor.submit(self._test_endpoint, path): path 
                for path in additional_paths
            }
            
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    endpoint = future.result()
                    if endpoint:
                        self.add_endpoint(endpoint)
                except Exception as e:
                    self.add_warning(f"Failed to test pattern-based path {path}: {str(e)}")
    
    def _extract_patterns(self, endpoints: List[APIEndpoint]) -> Dict[str, Any]:
        """
        Extract patterns from discovered endpoints.
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            Dictionary of patterns
        """
        patterns = {
            'resource_patterns': set(),
            'id_patterns': set(),
            'action_patterns': set(),
            'version_patterns': set()
        }
        
        for endpoint in endpoints:
            path = endpoint.path
            
            # Extract resource patterns (e.g., /users, /products)
            resource_match = re.match(r'^/([a-zA-Z]+)', path)
            if resource_match:
                patterns['resource_patterns'].add(resource_match.group(1))
            
            # Extract ID patterns (e.g., /users/{id})
            if re.search(r'/\d+$', path):
                patterns['id_patterns'].add('numeric_id')
            elif re.search(r'/[a-f0-9]{8,}', path):
                patterns['id_patterns'].add('uuid')
            
            # Extract action patterns (e.g., /users/login, /products/search)
            action_match = re.search(r'/([a-zA-Z]+)$', path)
            if action_match:
                patterns['action_patterns'].add(action_match.group(1))
            
            # Extract version patterns
            version_match = re.search(r'/v(\d+)', path)
            if version_match:
                patterns['version_patterns'].add(version_match.group(1))
        
        return patterns
    
    def _generate_paths_from_patterns(self, patterns: Dict[str, Any]) -> List[str]:
        """
        Generate additional paths based on extracted patterns.
        
        Args:
            patterns: Extracted patterns
            
        Returns:
            List of additional paths to test
        """
        additional_paths = []
        
        # Generate resource-based paths
        for resource in patterns.get('resource_patterns', []):
            additional_paths.extend([
                f'/{resource}/me',
                f'/{resource}/search',
                f'/{resource}/count',
                f'/{resource}/stats',
                f'/{resource}/export',
                f'/{resource}/import'
            ])
        
        # Generate version-based paths
        for version in patterns.get('version_patterns', []):
            additional_paths.extend([
                f'/v{version}/users',
                f'/v{version}/products',
                f'/v{version}/auth',
                f'/v{version}/health'
            ])
        
        # Generate common API patterns
        additional_paths.extend([
            '/api/v1/users',
            '/api/v2/users',
            '/api/v1/products',
            '/api/v2/products',
            '/api/v1/auth',
            '/api/v2/auth'
        ])
        
        return additional_paths
    
    def _analyze_patterns(self):
        """Analyze patterns in discovered endpoints."""
        # Group endpoints by path pattern
        path_patterns = {}
        for endpoint in self.parsed_endpoints:
            # Create a pattern by replacing IDs with placeholders
            pattern = re.sub(r'/\d+', '/{id}', endpoint.path)
            pattern = re.sub(r'/[a-f0-9]{8,}', '/{uuid}', pattern)
            
            if pattern not in path_patterns:
                path_patterns[pattern] = []
            path_patterns[pattern].append(endpoint)
        
        # Store patterns
        self.api_patterns = path_patterns
        
        # Update statistics
        self.update_stats('unique_path_patterns', len(path_patterns))
        
        # Find most common patterns
        common_patterns = sorted(path_patterns.items(), key=lambda x: len(x[1]), reverse=True)[:5]
        self.update_stats('most_common_patterns', [pattern for pattern, _ in common_patterns])
    
    def _update_final_stats(self):
        """Update final parser statistics."""
        self.update_stats('endpoints_found', len(self.parsed_endpoints))
        self.update_stats('success_rate', 100.0)
        
        # Count different types of endpoints
        methods = self.get_unique_methods()
        self.update_stats('unique_methods', methods)
        self.update_stats('unique_methods_count', len(methods))
        
        base_urls = self.get_unique_base_urls()
        self.update_stats('unique_base_urls', base_urls)
        self.update_stats('unique_base_urls_count', len(base_urls))
        
        # Count authenticated endpoints
        auth_endpoints = self.get_authenticated_endpoints()
        self.update_stats('authenticated_endpoints', len(auth_endpoints))
        
        # Count endpoints with request/response bodies
        req_body_endpoints = self.get_endpoints_with_request_body()
        resp_body_endpoints = self.get_endpoints_with_response_body()
        self.update_stats('endpoints_with_request_body', len(req_body_endpoints))
        self.update_stats('endpoints_with_response_body', len(resp_body_endpoints))
        
        # SSL statistics
        ssl_endpoints = [ep for ep in self.parsed_endpoints if ep.ssl_info]
        self.update_stats('ssl_endpoints', len(ssl_endpoints))
        
        # Auth endpoint statistics
        self.update_stats('auth_endpoints_found', len(self.auth_endpoints))
        
        # Rate limiting statistics
        self.update_stats('rate_limited_endpoints', len(self.rate_limits))
    
    def get_api_patterns(self) -> Dict[str, List[APIEndpoint]]:
        """Get the discovered API patterns."""
        return self.api_patterns.copy()
    
    def get_auth_endpoints(self) -> List[APIEndpoint]:
        """Get the discovered authentication endpoints."""
        return self.auth_endpoints.copy()
    
    def get_rate_limits(self) -> Dict[str, Dict[str, str]]:
        """Get the discovered rate limiting information."""
        return self.rate_limits.copy()


if __name__ == "__main__":
    import sys
    import os
    
    def main():
        """Main function to run Base URL parser from command line."""
        if len(sys.argv) != 2:
            print("Usage: python base_url_parser.py <base_url>")
            print("\nExamples:")
            print("  python base_url_parser.py https://api.example.com")
            print("  python base_url_parser.py api.example.com")
            return
        
        base_url = sys.argv[1]
        
        # Initialize parser
        parser = BaseURLParser()
        
        try:
            # Discover API endpoints
            endpoints = parser.parse(base_url)
            
            # Display results
            print(f"\n{'='*60}")
            print(f"Base URL Parser Results for: {base_url}")
            print(f"{'='*60}")
            
            if endpoints:
                print(f"\nFound {len(endpoints)} API endpoint(s):")
                print("-" * 40)
                
                for i, endpoint in enumerate(endpoints, 1):
                    print(f"\n{i}. {endpoint.method} {endpoint.full_url}")
                    print(f"   Path: {endpoint.path}")
                    print(f"   Timestamp: {endpoint.timestamp}")
                    
                    if endpoint.response_headers:
                        print(f"   Response Headers ({len(endpoint.response_headers)}):")
                        for header in endpoint.response_headers[:5]:  # Show first 5
                            print(f"     - {header.name}: {header.value}")
                    
                    if endpoint.auth_info:
                        auth_str = endpoint.auth_info.get_auth_string()
                        print(f"   Authentication: {endpoint.auth_info.auth_type.value}")
                        if auth_str:
                            print(f"     Auth Details: {auth_str}")
                    
                    if endpoint.ssl_info:
                        print(f"   SSL: {endpoint.ssl_info.subject}")
                    
                    if endpoint.response_body:
                        print(f"   Response Body: {str(endpoint.response_body)[:200]}...")
                    
                    print("-" * 60)
            else:
                print("\nNo API endpoints found for this base URL.")
                print("This might be because:")
                print("- The URL is not accessible")
                print("- The server doesn't expose common API endpoints")
                print("- Network connectivity issues")
                print("- Rate limiting or blocking")
            
            # Show authentication endpoints
            auth_endpoints = parser.get_auth_endpoints()
            if auth_endpoints:
                print(f"\n{'='*60}")
                print("Authentication Endpoints:")
                print(f"{'='*60}")
                for endpoint in auth_endpoints:
                    print(f"  {endpoint.method} {endpoint.path}")
                print()
            
            # Show rate limiting information
            rate_limits = parser.get_rate_limits()
            if rate_limits:
                print(f"\n{'='*60}")
                print("Rate Limiting Information:")
                print(f"{'='*60}")
                for path, limits in rate_limits.items():
                    print(f"Path: {path}")
                    for header, value in limits.items():
                        print(f"  {header}: {value}")
                    print()
            
            # Show API patterns
            api_patterns = parser.get_api_patterns()
            if api_patterns:
                print(f"\n{'='*60}")
                print("API Patterns:")
                print(f"{'='*60}")
                for pattern, endpoints in api_patterns.items():
                    print(f"Pattern: {pattern}")
                    print(f"  Count: {len(endpoints)}")
                    print(f"  Methods: {list(set(ep.method for ep in endpoints))}")
                    print()
            
            # Show statistics
            stats = parser.get_stats()
            if stats:
                print(f"\n{'='*60}")
                print("Parser Statistics:")
                print(f"{'='*60}")
                for key, value in stats.items():
                    print(f"{key}: {value}")
            
            # Show errors/warnings
            if parser.errors:
                print(f"\n{'='*60}")
                print("Errors:")
                print(f"{'='*60}")
                for error in parser.errors:
                    print(f"❌ {error}")
            
            if parser.warnings:
                print(f"\n{'='*60}")
                print("Warnings:")
                print(f"{'='*60}")
                for warning in parser.warnings:
                    print(f"⚠️  {warning}")
                    
        except Exception as e:
            print(f"Error discovering API endpoints: {e}")
    
    main() 