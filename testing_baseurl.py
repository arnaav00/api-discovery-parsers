import requests
import time
import random
import re
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class DiscoveredEndpoint:
    """Represents a discovered API endpoint."""
    method: str
    path: str
    full_url: str
    status_code: int
    content_type: str
    content_length: int
    response_time: float
    is_api: bool
    api_indicators: List[str]
    timestamp: str

class IntelligentAPICrawler:
    """
    Intelligent API crawler that uses response analysis to discover real API endpoints.
    """
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'API-Discovery-Crawler/1.0',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Common API paths to test
        self.common_paths = [
            # Authentication endpoints
            '/login', '/signup', '/register', '/auth', '/logout',
            '/signin', '/signout', '/token', '/oauth', '/jwt',
            
            # API versioning
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/v1', '/v2', '/v3',
            
            # Health and status
            '/health', '/status', '/ping', '/ready', '/live',
            
            # Documentation
            '/docs', '/swagger', '/openapi', '/redoc',
            
            # Common resources
            '/users', '/user', '/profile', '/products', '/items',
            '/orders', '/customers', '/files', '/media',
            
            # Admin and management
            '/admin', '/dashboard', '/management', '/settings',
            
            # Webhooks and integrations
            '/webhooks', '/hooks', '/callback', '/notifications',
            
            # Root endpoints
            '/', '/index', '/home',
            
            # Additional API-specific paths
            '/api/users', '/api/products', '/api/orders', '/api/auth',
            '/api/health', '/api/status', '/api/docs', '/api/swagger',
            '/rest', '/rest/users', '/rest/products', '/rest/auth',
            '/graphql', '/graphql/users', '/graphql/products',
            '/json', '/json/users', '/json/products',
            '/data', '/data/users', '/data/products',
            '/services', '/services/users', '/services/products',
            '/endpoints', '/endpoints/users', '/endpoints/products'
        ]
        
        # HTTP methods to test
        self.http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD']
        
        # API indicators in responses
        self.api_indicators = [
            # JSON responses
            'application/json',
            
            # API documentation
            'swagger', 'openapi', 'api documentation', 'rest api',
            'graphql', 'endpoint', 'api reference', 'api docs',
            
            # Authentication
            'login', 'signup', 'register', 'auth', 'token',
            'bearer', 'oauth', 'jwt', 'session',
            
            # Common API patterns
            'success', 'error', 'status', 'data', 'result',
            'message', 'code', 'response', 'request',
            
            # Form elements (login/signup pages)
            'form', 'input', 'button', 'submit',
            
            # API-specific headers
            'x-api-version', 'x-rate-limit', 'x-total-count',
            'x-powered-by', 'x-request-id', 'x-correlation-id'
        ]
        
        # Generic page indicators (to avoid false positives)
        self.generic_indicators = [
            'page not found', '404 not found', 'not found',
            'nginx', 'apache', 'server error', 'internal server error',
            'welcome to nginx', 'welcome to apache', 'default page',
            'it works!', 'index of /', 'directory listing'
        ]
        
        self.discovered_endpoints = []
        self.root_page_content = None
        self.root_page_hash = None
        
    def crawl(self, base_url: str) -> List[DiscoveredEndpoint]:
        """
        Crawl the base URL and discover API endpoints.
        
        Args:
            base_url: The base URL to crawl
            
        Returns:
            List of discovered endpoints
        """
        print(f"🔍 Starting intelligent API crawl of: {base_url}")
        print("=" * 60)
        
        # Normalize base URL
        if not base_url.startswith(('http://', 'https://')):
            base_url = 'http://' + base_url
        
        # Get root page for comparison
        self._get_root_page(base_url)
        
        # Test common paths
        self._test_common_paths(base_url)
        
        # Test additional paths based on discovered patterns
        self._test_pattern_based_paths(base_url)
        
        # Filter and return only real API endpoints
        real_endpoints = self._filter_real_endpoints()
        
        print(f"\n✅ Crawl completed!")
        print(f"📊 Total responses tested: {len(self.discovered_endpoints)}")
        print(f"🎯 Real API endpoints found: {len(real_endpoints)}")
        
        return real_endpoints
    
    def _get_root_page(self, base_url: str):
        """Get the root page content for comparison."""
        try:
            response = self.session.get(base_url, timeout=10)
            if response.status_code == 200:
                self.root_page_content = response.text.lower()
                self.root_page_hash = hash(self.root_page_content)
                print(f"📄 Root page loaded ({len(self.root_page_content)} chars)")
        except Exception as e:
            print(f"⚠️  Could not load root page: {e}")
    
    def _test_common_paths(self, base_url: str):
        """Test common API paths."""
        print(f"\n🔍 Testing {len(self.common_paths)} common paths...")
        
        for i, path in enumerate(self.common_paths, 1):
            print(f"  [{i:2d}/{len(self.common_paths)}] Testing: {path}")
            
            # Test different HTTP methods
            for method in self.http_methods:
                endpoint = self._test_endpoint(base_url, path, method)
                if endpoint:
                    self.discovered_endpoints.append(endpoint)
            
            # Small delay to be respectful
            time.sleep(random.uniform(0.1, 0.3))
    
    def _test_pattern_based_paths(self, base_url: str):
        """Test additional paths based on discovered patterns."""
        print(f"\n🔍 Testing pattern-based paths...")
        
        # Extract patterns from discovered endpoints
        patterns = self._extract_patterns()
        
        # Generate additional paths
        additional_paths = self._generate_paths_from_patterns(patterns)
        
        for i, path in enumerate(additional_paths, 1):
            print(f"  [{i:2d}/{len(additional_paths)}] Testing pattern: {path}")
            
            # Test GET method for pattern-based paths
            endpoint = self._test_endpoint(base_url, path, 'GET')
            if endpoint:
                self.discovered_endpoints.append(endpoint)
            
            time.sleep(random.uniform(0.1, 0.2))
        
        # Test embedded API endpoints found in HTML
        self._test_embedded_endpoints(base_url)
    
    def _test_embedded_endpoints(self, base_url: str):
        """Test API endpoints that might be embedded in the HTML content."""
        print(f"\n🔍 Testing embedded API endpoints...")
        
        if not self.root_page_content:
            return
        
        # Extract potential API endpoints from HTML
        embedded_endpoints = self._extract_embedded_endpoints()
        
        if not embedded_endpoints:
            print("  No embedded endpoints found in HTML")
            return
        
        print(f"  Found {len(embedded_endpoints)} potential embedded endpoints")
        
        for i, path in enumerate(embedded_endpoints, 1):
            print(f"  [{i:2d}/{len(embedded_endpoints)}] Testing embedded: {path}")
            
            # Test GET method for embedded endpoints
            endpoint = self._test_endpoint(base_url, path, 'GET')
            if endpoint:
                self.discovered_endpoints.append(endpoint)
            
            time.sleep(random.uniform(0.1, 0.2))
    
    def _test_endpoint(self, base_url: str, path: str, method: str) -> Optional[DiscoveredEndpoint]:
        """
        Test a specific endpoint.
        
        Args:
            base_url: Base URL
            path: Path to test
            method: HTTP method
            
        Returns:
            DiscoveredEndpoint if found, None otherwise
        """
        url = urljoin(base_url, path)
        
        try:
            start_time = time.time()
            response = self.session.request(
                method=method,
                url=url,
                timeout=10,
                allow_redirects=True
            )
            response_time = time.time() - start_time
            
            # Analyze the response
            is_api, indicators = self._analyze_response(response)
            
            if is_api:
                endpoint = DiscoveredEndpoint(
                    method=method,
                    path=path,
                    full_url=url,
                    status_code=response.status_code,
                    content_type=response.headers.get('content-type', ''),
                    content_length=len(response.text),
                    response_time=response_time,
                    is_api=is_api,
                    api_indicators=indicators,
                    timestamp=datetime.now().isoformat()
                )
                
                print(f"    ✅ {method} {path} - {response.status_code} ({len(indicators)} indicators)")
                return endpoint
            else:
                print(f"    ❌ {method} {path} - {response.status_code} (not API)")
                return None
                
        except Exception as e:
            print(f"    ⚠️  {method} {path} - Error: {str(e)[:50]}")
            return None
    
    def _analyze_response(self, response: requests.Response) -> tuple[bool, List[str]]:
        """
        Analyze a response to determine if it's an API endpoint.
        
        Args:
            response: HTTP response
            
        Returns:
            Tuple of (is_api, indicators)
        """
        indicators = []
        
        # Check status code
        if response.status_code >= 400:
            return False, []
        
        # Check content type
        content_type = response.headers.get('content-type', '').lower()
        
        # JSON responses are definitely APIs
        if 'application/json' in content_type:
            indicators.append('application/json')
            return True, indicators
        
        # XML responses are likely APIs
        if 'application/xml' in content_type or 'text/xml' in content_type:
            indicators.append('xml')
            return True, indicators
        
        # Check response text for API indicators
        text = response.text.lower()
        
        # Check for API documentation indicators
        for indicator in self.api_indicators:
            if indicator in text:
                indicators.append(indicator)
        
        # Check for API-specific headers
        for header in response.headers:
            if any(api_header in header.lower() for api_header in ['x-api', 'x-rate', 'x-total', 'x-powered']):
                indicators.append(f'header:{header}')
        
        # Check if it's a generic page (to avoid false positives)
        generic_count = sum(1 for indicator in self.generic_indicators if indicator in text)
        if generic_count >= 2:
            return False, []
        
        # Check if it's the same as root page (likely a catch-all)
        if self.root_page_content and text == self.root_page_content:
            return False, []
        
        # Check for form elements (login/signup pages)
        if 'form' in text and any(action in text for action in ['login', 'signup', 'register', 'auth']):
            indicators.append('form')
        
        # Check for React/Vue/Angular (SPAs)
        if any(framework in text for framework in ['react', 'vue', 'angular']):
            indicators.append('spa')
        
        # Check for specific API-related content in the HTML
        api_content_indicators = [
            'login', 'signup', 'dashboard', 'shop', 'api', 'endpoint',
            'user', 'product', 'order', 'admin', 'management'
        ]
        
        for indicator in api_content_indicators:
            if indicator in text:
                indicators.append(f'content:{indicator}')
        
        # Check for embedded API endpoints in HTML
        embedded_api_patterns = [
            r'api/[a-zA-Z0-9/_-]+',
            r'v[0-9]+/[a-zA-Z0-9/_-]+',
            r'/[a-zA-Z]+/[a-zA-Z0-9/_-]+',
            r'endpoint[s]?/[a-zA-Z0-9/_-]+',
            r'data/[a-zA-Z0-9/_-]+',
            r'json/[a-zA-Z0-9/_-]+'
        ]
        
        for pattern in embedded_api_patterns:
            matches = re.findall(pattern, text)
            if matches:
                indicators.append(f'embedded_api:{pattern}')
        
        # Determine if it's an API based on indicators
        is_api = len(indicators) >= 2 or any(key_indicator in indicators for key_indicator in [
            'application/json', 'xml', 'swagger', 'openapi', 'form'
        ])
        
        # Special case: If it's a SPA with API-related content, consider it an API endpoint
        if 'spa' in indicators and len([i for i in indicators if i.startswith('content:')]) >= 2:
            is_api = True
        
        # Special case: If it contains embedded API patterns, consider it an API endpoint
        if any(i.startswith('embedded_api:') for i in indicators):
            is_api = True
        
        return is_api, indicators
    
    def _extract_patterns(self) -> Dict[str, Set[str]]:
        """Extract patterns from discovered endpoints."""
        patterns = {
            'resources': set(),
            'actions': set(),
            'versions': set()
        }
        
        for endpoint in self.discovered_endpoints:
            if not endpoint.is_api:
                continue
                
            path = endpoint.path
            
            # Extract resource patterns (e.g., /users, /products)
            resource_match = re.match(r'^/([a-zA-Z]+)', path)
            if resource_match:
                patterns['resources'].add(resource_match.group(1))
            
            # Extract action patterns (e.g., /users/login, /products/search)
            action_match = re.search(r'/([a-zA-Z]+)$', path)
            if action_match:
                patterns['actions'].add(action_match.group(1))
            
            # Extract version patterns
            version_match = re.search(r'/v(\d+)', path)
            if version_match:
                patterns['versions'].add(version_match.group(1))
        
        return patterns
    
    def _generate_paths_from_patterns(self, patterns: Dict[str, Set[str]]) -> List[str]:
        """Generate additional paths based on patterns."""
        additional_paths = []
        
        # Generate resource-based paths
        for resource in patterns.get('resources', []):
            additional_paths.extend([
                f'/{resource}/me',
                f'/{resource}/search',
                f'/{resource}/count',
                f'/{resource}/stats',
                f'/{resource}/export',
                f'/{resource}/import'
            ])
        
        # Generate version-based paths
        for version in patterns.get('versions', []):
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
    
    def _extract_embedded_endpoints(self) -> List[str]:
        """Extract potential API endpoints from the HTML content."""
        endpoints = set()
        
        if not self.root_page_content:
            return list(endpoints)
        
        # Look for API patterns in the HTML
        api_patterns = [
            r'api/[a-zA-Z0-9/_-]+',
            r'v[0-9]+/[a-zA-Z0-9/_-]+',
            r'/[a-zA-Z]+/[a-zA-Z0-9/_-]+',
            r'endpoint[s]?/[a-zA-Z0-9/_-]+',
            r'data/[a-zA-Z0-9/_-]+',
            r'json/[a-zA-Z0-9/_-]+',
            r'rest/[a-zA-Z0-9/_-]+',
            r'graphql/[a-zA-Z0-9/_-]+',
            r'services/[a-zA-Z0-9/_-]+'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, self.root_page_content)
            for match in matches:
                # Clean up the match
                clean_match = match.strip('/')
                if clean_match and len(clean_match) > 2:
                    endpoints.add(f'/{clean_match}')
        
        # Also look for common API endpoint patterns
        common_api_endpoints = [
            '/api/users', '/api/products', '/api/orders', '/api/auth',
            '/api/health', '/api/status', '/api/docs', '/api/swagger',
            '/rest/users', '/rest/products', '/rest/auth',
            '/graphql/users', '/graphql/products',
            '/json/users', '/json/products',
            '/data/users', '/data/products',
            '/services/users', '/services/products',
            '/endpoints/users', '/endpoints/products'
        ]
        
        for endpoint in common_api_endpoints:
            if endpoint.replace('/', '') in self.root_page_content:
                endpoints.add(endpoint)
        
        return list(endpoints)
    
    def _filter_real_endpoints(self) -> List[DiscoveredEndpoint]:
        """Filter and return only real API endpoints."""
        real_endpoints = []
        
        for endpoint in self.discovered_endpoints:
            if endpoint.is_api:
                real_endpoints.append(endpoint)
        
        return real_endpoints
    
    def print_results(self, endpoints: List[DiscoveredEndpoint]):
        """Print the crawl results."""
        if not endpoints:
            print("\n❌ No API endpoints found!")
            return
        
        print(f"\n🎯 Found {len(endpoints)} API endpoints:")
        print("=" * 60)
        
        # Group by method
        by_method = {}
        for endpoint in endpoints:
            if endpoint.method not in by_method:
                by_method[endpoint.method] = []
            by_method[endpoint.method].append(endpoint)
        
        for method in sorted(by_method.keys()):
            print(f"\n📋 {method} Endpoints ({len(by_method[method])}):")
            print("-" * 40)
            
            for endpoint in sorted(by_method[method], key=lambda x: x.path):
                print(f"  {endpoint.path}")
                print(f"    URL: {endpoint.full_url}")
                print(f"    Status: {endpoint.status_code}")
                print(f"    Content-Type: {endpoint.content_type}")
                print(f"    Size: {endpoint.content_length} chars")
                print(f"    Response Time: {endpoint.response_time:.2f}s")
                print(f"    Indicators: {', '.join(endpoint.api_indicators)}")
                print()
        
        # Summary statistics
        print("📊 Summary Statistics:")
        print("-" * 40)
        print(f"Total API Endpoints: {len(endpoints)}")
        print(f"Methods Found: {list(by_method.keys())}")
        print(f"Average Response Time: {sum(e.response_time for e in endpoints) / len(endpoints):.2f}s")
        print(f"Most Common Indicators: {self._get_most_common_indicators(endpoints)}")
    
    def _get_most_common_indicators(self, endpoints: List[DiscoveredEndpoint]) -> List[str]:
        """Get the most common API indicators."""
        indicator_counts = {}
        for endpoint in endpoints:
            for indicator in endpoint.api_indicators:
                indicator_counts[indicator] = indicator_counts.get(indicator, 0) + 1
        
        # Return top 5 most common indicators
        sorted_indicators = sorted(indicator_counts.items(), key=lambda x: x[1], reverse=True)
        return [indicator for indicator, count in sorted_indicators[:5]]

def main():
    """Main function to run the intelligent API crawler."""
    crawler = IntelligentAPICrawler()
    
    # Crawl the target URL
    base_url = "http://crapi2.apisec.ai"
    endpoints = crawler.crawl(base_url)
    
    # Print results
    crawler.print_results(endpoints)

if __name__ == "__main__":
    main()
