"""
Comprehensive unit tests for MITM Parser.

Tests cover:
- Valid input parsing
- Invalid input handling  
- Edge cases and error conditions
- Performance benchmarks
- Memory usage tests
"""

import unittest
import json
import tempfile
import os
import time
import psutil
import sys
from unittest.mock import patch, mock_open
from io import StringIO

# Add parent directory to path to import parsers
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from parsers.mitm_parser import MITMParser
from models import APIEndpoint, Parameter, Header, AuthInfo, SSLInfo
from models import ParameterType, ParameterLocation, AuthType, AuthLocation


class TestMITMParser(unittest.TestCase):
    """Test cases for MITM Parser."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.parser = MITMParser()
        
        # Sample valid MITM log data (JSON format)
        self.valid_mitm_json_data = [
            {
                "timestamp": "2024-03-15 10:24:12.478",
                "method": "GET",
                "url": "https://api.example.com/v1/users/123?page=1&limit=10",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/v1/users/123",
                "query": "page=1&limit=10",
                "request_headers": {
                    "User-Agent": "Test/1.0",
                    "Authorization": "Bearer token123",
                    "Content-Type": "application/json"
                },
                "request_body": None,
                "response_timestamp": "2024-03-15 10:24:12.523",
                "response_status": 200,
                "response_status_text": "OK",
                "response_headers": {
                    "Content-Type": "application/json",
                    "X-RateLimit-Limit": "100"
                },
                "response_body": '{"users": [{"id": 1, "name": "John"}]}',
                "ssl_info": {
                    "subject": "CN=api.example.com",
                    "issuer": "CN=Let's Encrypt Authority X3",
                    "serial": "1234567890"
                }
            },
            {
                "timestamp": "2024-03-15 10:24:15.789",
                "method": "POST",
                "url": "https://api.example.com/v2/orders",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/v2/orders",
                "query": "",
                "request_headers": {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer token123"
                },
                "request_body": '{"name": "Jane", "email": "jane@example.com"}',
                "response_timestamp": "2024-03-15 10:24:15.845",
                "response_status": 201,
                "response_status_text": "Created",
                "response_headers": {
                    "Content-Type": "application/json",
                    "Location": "/users/2"
                },
                "response_body": '{"id": 2, "name": "Jane", "email": "jane@example.com"}',
                "ssl_info": {
                    "subject": "CN=api.example.com",
                    "issuer": "CN=Let's Encrypt Authority X3",
                    "serial": "1234567890"
                }
            }
        ]
        
        # Sample valid MITM log data (text format - mitmproxy format)
        self.valid_mitm_text_data = """
2024-03-15 10:24:12.478 [REQUEST] GET https://api.example.com/v1/users/123?page=1&limit=10
Host: api.example.com
User-Agent: Test/1.0
Authorization: Bearer token123
Content-Type: application/json

2024-03-15 10:24:12.523 [RESPONSE] 200 OK
Content-Type: application/json
X-RateLimit-Limit: 100

{"users": [{"id": 1, "name": "John"}]}

2024-03-15 10:24:15.789 [REQUEST] POST https://api.example.com/v2/orders
Host: api.example.com
Content-Type: application/json
Authorization: Bearer token123

{"name": "Jane", "email": "jane@example.com"}

2024-03-15 10:24:15.845 [RESPONSE] 201 Created
Content-Type: application/json
Location: /users/2

{"id": 2, "name": "Jane", "email": "jane@example.com"}
"""
        
        # Sample invalid MITM data
        self.invalid_mitm_data = {
            "invalid": "structure",
            "missing": "required_fields"
        }
        
        # Sample MITM data with edge cases
        self.edge_case_mitm_data = [
            {
                "timestamp": "2024-03-15 10:24:12.478",
                "method": "OPTIONS",
                "url": "https://api.example.com/cors",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/cors",
                "query": "",
                "request_headers": {},
                "request_body": None,
                "response_timestamp": "2024-03-15 10:24:12.523",
                "response_status": 204,
                "response_status_text": "No Content",
                "response_headers": {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE"
                },
                "response_body": "",
                "ssl_info": None
            }
        ]
    
    def test_can_parse_valid_mitm_json(self):
        """Test that parser can identify valid MITM JSON data."""
        # Test with list of dictionaries - should pass validation
        self.assertTrue(self.parser.can_parse(self.valid_mitm_json_data))
        
        # Test with single dictionary - should pass validation
        self.assertTrue(self.parser.can_parse(self.valid_mitm_json_data[0]))
        
        # Test with JSON string - should pass validation
        mitm_json = json.dumps(self.valid_mitm_json_data)
        self.assertTrue(self.parser.can_parse(mitm_json))
    
    def test_can_parse_valid_mitm_text(self):
        """Test that parser can identify valid MITM text data."""
        # Test with text string
        self.assertTrue(self.parser.can_parse(self.valid_mitm_text_data))
        
        # Test with file path
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(self.valid_mitm_text_data)
            temp_file = f.name
        
        try:
            self.assertTrue(self.parser.can_parse(temp_file))
        finally:
            os.unlink(temp_file)
    
    def test_can_parse_invalid_data(self):
        """Test that parser correctly rejects invalid data."""
        # Test with invalid structure
        self.assertFalse(self.parser.can_parse(self.invalid_mitm_data))
        
        # Test with invalid JSON
        self.assertFalse(self.parser.can_parse("invalid json"))
        
        # Test with None
        self.assertFalse(self.parser.can_parse(None))
        
        # Test with empty string
        self.assertFalse(self.parser.can_parse(""))
        
        # Test with non-existent file
        self.assertFalse(self.parser.can_parse("nonexistent.log"))
    
    def test_parse_valid_mitm_json(self):
        """Test parsing valid MITM JSON data."""
        endpoints = self.parser.parse(self.valid_mitm_json_data)
        
        # Should find 2 endpoints
        self.assertEqual(len(endpoints), 2)
        
        # Test first endpoint (GET request)
        endpoint1 = endpoints[0]
        self.assertEqual(endpoint1.method, "GET")
        self.assertEqual(endpoint1.path, "/v1/users/123")
        self.assertEqual(endpoint1.full_url, "https://api.example.com/v1/users/123?page=1&limit=10")
        self.assertEqual(endpoint1.base_url, "https://api.example.com")
        self.assertEqual(endpoint1.response_status, 200)
        
        # Test parameters
        self.assertEqual(len(endpoint1.parameters), 2)
        page_param = next(p for p in endpoint1.parameters if p.name == "page")
        self.assertEqual(page_param.value, "1")
        self.assertEqual(page_param.location, ParameterLocation.QUERY)
        
        # Test headers
        self.assertEqual(len(endpoint1.headers), 3)
        auth_header = next(h for h in endpoint1.headers if h.name == "Authorization")
        self.assertEqual(auth_header.value, "Bearer token123")
        
        # Test authentication - check if auth_info exists
        if endpoint1.auth_info:
            self.assertEqual(endpoint1.auth_info.auth_type, AuthType.BEARER)
            self.assertEqual(endpoint1.auth_info.token, "token123")
        
        # Test SSL info
        self.assertIsNotNone(endpoint1.ssl_info)
        self.assertEqual(endpoint1.ssl_info.subject, "CN=api.example.com")
        
        # Test second endpoint (POST request)
        endpoint2 = endpoints[1]
        self.assertEqual(endpoint2.method, "POST")
        self.assertEqual(endpoint2.path, "/v2/orders")
        self.assertEqual(endpoint2.response_status, 201)
        
        # Test request body
        self.assertIsNotNone(endpoint2.request_body)
        self.assertIn("name", endpoint2.request_body)
        self.assertIn("email", endpoint2.request_body)
    
    def test_parse_valid_mitm_text(self):
        """Test parsing valid MITM text data."""
        endpoints = self.parser.parse(self.valid_mitm_text_data)
        
        # Should find 2 endpoints
        self.assertEqual(len(endpoints), 2)
        
        # Test GET endpoint
        get_endpoint = next(ep for ep in endpoints if ep.method == "GET")
        self.assertEqual(get_endpoint.path, "/v1/users/123")
        self.assertEqual(get_endpoint.response_status, 200)
        
        # Test POST endpoint
        post_endpoint = next(ep for ep in endpoints if ep.method == "POST")
        self.assertEqual(post_endpoint.path, "/v2/orders")
        self.assertEqual(post_endpoint.response_status, 201)
    
    def test_parse_edge_cases(self):
        """Test parsing MITM data with edge cases."""
        endpoints = self.parser.parse(self.edge_case_mitm_data)
        
        # Should find 1 endpoint
        self.assertEqual(len(endpoints), 1)
        
        endpoint = endpoints[0]
        self.assertEqual(endpoint.method, "OPTIONS")
        self.assertEqual(endpoint.path, "/cors")
        self.assertEqual(endpoint.response_status, 204)
    
    def test_parse_empty_log(self):
        """Test parsing MITM log with no entries."""
        empty_log = []
        
        # Should raise ValueError for empty log
        with self.assertRaises(ValueError):
            self.parser.parse(empty_log)
    
    def test_parse_malformed_entries(self):
        """Test parsing MITM with malformed entries."""
        # Create minimal valid entry
        minimal_entry = {
            "method": "GET",
            "url": "https://api.example.com/api/test"
        }
        
        # Should handle gracefully and not crash
        endpoints = self.parser.parse([minimal_entry])
        self.assertEqual(len(endpoints), 1)
    
    def test_parse_large_log(self):
        """Test parsing large MITM log."""
        # Create large log with many entries
        large_log = []
        
        # Add 1000 entries
        for i in range(1000):
            entry = {
                "timestamp": f"2024-03-15 10:{i:02d}:00.000",
                "method": "GET",
                "url": f"https://api.example.com/api/users/{i}",
                "scheme": "https",
                "host": "api.example.com",
                "path": f"/api/users/{i}",
                "query": "",
                "request_headers": {
                    "User-Agent": "Test/1.0"
                },
                "request_body": None,
                "response_timestamp": f"2024-03-15 10:{i:02d}:00.100",
                "response_status": 200,
                "response_status_text": "OK",
                "response_headers": {
                    "Content-Type": "application/json"
                },
                "response_body": f'{{"id": {i}, "name": "User{i}"}}',
                "ssl_info": None
            }
            large_log.append(entry)
        
        # Test parsing performance
        start_time = time.time()
        endpoints = self.parser.parse(large_log)
        end_time = time.time()
        
        # Should find all endpoints
        self.assertEqual(len(endpoints), 1000)
        
        # Should complete within reasonable time (less than 5 seconds)
        self.assertLess(end_time - start_time, 5.0)
    
    def test_memory_usage(self):
        """Test memory usage during parsing."""
        # Get initial memory usage
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        # Parse large log
        large_log = []
        
        # Add 100 entries
        for i in range(100):
            entry = {
                "timestamp": f"2024-03-15 10:{i:02d}:00.000",
                "method": "GET",
                "url": f"https://api.example.com/api/users/{i}",
                "scheme": "https",
                "host": "api.example.com",
                "path": f"/api/users/{i}",
                "query": "",
                "request_headers": {
                    "User-Agent": "Test/1.0"
                },
                "request_body": None,
                "response_timestamp": f"2024-03-15 10:{i:02d}:00.100",
                "response_status": 200,
                "response_status_text": "OK",
                "response_headers": {
                    "Content-Type": "application/json"
                },
                "response_body": f'{{"id": {i}, "name": "User{i}"}}',
                "ssl_info": None
            }
            large_log.append(entry)
        
        # Parse and measure memory
        endpoints = self.parser.parse(large_log)
        final_memory = process.memory_info().rss
        
        # Memory increase should be reasonable (less than 50MB)
        memory_increase = final_memory - initial_memory
        self.assertLess(memory_increase, 50 * 1024 * 1024)  # 50MB
        
        # Should find all endpoints
        self.assertEqual(len(endpoints), 100)
    
    def test_error_handling(self):
        """Test error handling for various error conditions."""
        # Test with missing required fields
        invalid_log = [
            {
                "method": "GET"
                # Missing URL
            }
        ]
        
        # Should handle gracefully and return empty list (no valid entries)
        endpoints = self.parser.parse(invalid_log)
        self.assertEqual(len(endpoints), 0)
        
        # Test with invalid JSON
        with self.assertRaises(ValueError):
            self.parser.parse("invalid json string")
        
        # Test with file that doesn't exist
        with self.assertRaises(ValueError):
            self.parser.parse("nonexistent.log")
    
    def test_parameter_extraction(self):
        """Test parameter extraction from various sources."""
        mitm_with_params = [
            {
                "timestamp": "2024-03-15 10:24:12.478",
                "method": "GET",
                "url": "https://api.example.com/api/users/123/posts?page=1&limit=10&sort=desc",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/api/users/123/posts",
                "query": "page=1&limit=10&sort=desc",
                "request_headers": {
                    "X-Custom-Header": "custom_value"
                },
                "request_body": None,
                "response_timestamp": "2024-03-15 10:24:12.523",
                "response_status": 200,
                "response_status_text": "OK",
                "response_headers": {},
                "response_body": "{}",
                "ssl_info": None
            }
        ]
        
        endpoints = self.parser.parse(mitm_with_params)
        self.assertEqual(len(endpoints), 1)
        
        endpoint = endpoints[0]
        
        # Test query parameters
        query_params = [p for p in endpoint.parameters if p.location == ParameterLocation.QUERY]
        self.assertEqual(len(query_params), 3)
        
        # Verify parameter values
        page_param = next(p for p in query_params if p.name == "page")
        self.assertEqual(page_param.value, "1")
        self.assertIn(page_param.param_type, [ParameterType.STRING, ParameterType.INTEGER])
        
        # Test headers
        self.assertEqual(len(endpoint.headers), 1)
        custom_header = endpoint.headers[0]
        self.assertEqual(custom_header.name, "X-Custom-Header")
        self.assertEqual(custom_header.value, "custom_value")
    
    def test_content_type_handling(self):
        """Test handling of different content types."""
        mitm_with_content_types = [
            {
                "timestamp": "2024-03-15 10:24:12.478",
                "method": "POST",
                "url": "https://api.example.com/api/users",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/api/users",
                "query": "",
                "request_headers": {
                    "Content-Type": "application/json"
                },
                "request_body": '{"name": "John", "age": 30}',
                "response_timestamp": "2024-03-15 10:24:12.523",
                "response_status": 201,
                "response_status_text": "Created",
                "response_headers": {
                    "Content-Type": "application/json"
                },
                "response_body": '{"id": 1, "name": "John", "age": 30}',
                "ssl_info": None
            },
            {
                "timestamp": "2024-03-15 10:24:15.789",
                "method": "POST",
                "url": "https://api.example.com/api/upload",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/api/upload",
                "query": "",
                "request_headers": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary"
                },
                "request_body": "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\nContent-Type: text/plain\r\n\r\nHello World\r\n------WebKitFormBoundary--",
                "response_timestamp": "2024-03-15 10:24:15.845",
                "response_status": 200,
                "response_status_text": "OK",
                "response_headers": {
                    "Content-Type": "application/json"
                },
                "response_body": '{"success": true, "filename": "test.txt"}',
                "ssl_info": None
            }
        ]
        
        endpoints = self.parser.parse(mitm_with_content_types)
        self.assertEqual(len(endpoints), 2)
        
        # Test JSON content
        json_endpoint = endpoints[0]
        self.assertEqual(json_endpoint.content_type, "application/json")
        self.assertIsNotNone(json_endpoint.request_body)
        self.assertIn("name", json_endpoint.request_body)
        
        # Test multipart content
        multipart_endpoint = endpoints[1]
        self.assertIn("multipart/form-data", multipart_endpoint.content_type)
        self.assertIsNotNone(multipart_endpoint.request_body)
    
    def test_ssl_info_extraction(self):
        """Test SSL information extraction."""
        mitm_with_ssl = [
            {
                "timestamp": "2024-03-15 10:24:12.478",
                "method": "GET",
                "url": "https://api.example.com/api/secure",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/api/secure",
                "query": "",
                "request_headers": {},
                "request_body": None,
                "response_timestamp": "2024-03-15 10:24:12.523",
                "response_status": 200,
                "response_status_text": "OK",
                "response_headers": {},
                "response_body": "{}",
                "ssl_info": {
                    "subject": "CN=api.example.com",
                    "issuer": "CN=Let's Encrypt Authority X3",
                    "serial": "1234567890",
                    "protocol": "TLSv1.2",
                    "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384"
                }
            }
        ]
        
        endpoints = self.parser.parse(mitm_with_ssl)
        self.assertEqual(len(endpoints), 1)
        
        endpoint = endpoints[0]
        self.assertIsNotNone(endpoint.ssl_info)
        self.assertEqual(endpoint.ssl_info.subject, "CN=api.example.com")
        self.assertEqual(endpoint.ssl_info.issuer, "CN=Let's Encrypt Authority X3")
        self.assertEqual(endpoint.ssl_info.protocol_version, "TLSv1.2")
        self.assertEqual(endpoint.ssl_info.cipher_suite, "ECDHE-RSA-AES256-GCM-SHA384")
    
    def test_authentication_extraction(self):
        """Test authentication extraction from various methods."""
        mitm_with_auth = [
            {
                "timestamp": "2024-03-15 10:24:12.478",
                "method": "GET",
                "url": "https://api.example.com/api/secure",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/api/secure",
                "query": "",
                "request_headers": {
                    "Authorization": "Bearer token123"
                },
                "request_body": None,
                "response_timestamp": "2024-03-15 10:24:12.523",
                "response_status": 200,
                "response_status_text": "OK",
                "response_headers": {},
                "response_body": "{}",
                "ssl_info": None
            },
            {
                "timestamp": "2024-03-15 10:24:15.789",
                "method": "POST",
                "url": "https://api.example.com/api/login",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/api/login",
                "query": "",
                "request_headers": {
                    "Authorization": "Basic dXNlcjpwYXNz"
                },
                "request_body": '{"username": "user", "password": "pass"}',
                "response_timestamp": "2024-03-15 10:24:15.845",
                "response_status": 200,
                "response_status_text": "OK",
                "response_headers": {},
                "response_body": '{"token": "new_token_123"}',
                "ssl_info": None
            },
            {
                "timestamp": "2024-03-15 10:24:18.234",
                "method": "GET",
                "url": "https://api.example.com/api/data",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/api/data",
                "query": "",
                "request_headers": {
                    "X-API-Key": "api_key_456"
                },
                "request_body": None,
                "response_timestamp": "2024-03-15 10:24:18.312",
                "response_status": 200,
                "response_status_text": "OK",
                "response_headers": {},
                "response_body": "{}",
                "ssl_info": None
            }
        ]
        
        endpoints = self.parser.parse(mitm_with_auth)
        self.assertEqual(len(endpoints), 3)
        
        # Test Bearer token
        bearer_endpoints = [ep for ep in endpoints if ep.auth_info and ep.auth_info.auth_type == AuthType.BEARER]
        if bearer_endpoints:
            self.assertEqual(bearer_endpoints[0].auth_info.token, "token123")
        
        # Test Basic auth
        basic_endpoints = [ep for ep in endpoints if ep.auth_info and ep.auth_info.auth_type == AuthType.BASIC]
        if basic_endpoints:
            self.assertEqual(basic_endpoints[0].auth_info.token, "dXNlcjpwYXNz")
        
        # Test API key
        api_key_endpoints = [ep for ep in endpoints if ep.auth_info and ep.auth_info.auth_type == AuthType.API_KEY]
        if api_key_endpoints:
            self.assertEqual(api_key_endpoints[0].auth_info.token, "api_key_456")
    
    def test_statistics(self):
        """Test parser statistics."""
        endpoints = self.parser.parse(self.valid_mitm_json_data)
        
        stats = self.parser.get_stats()
        
        # Check key statistics
        self.assertIsNotNone(stats)
        self.assertGreater(len(stats), 0)
        
        # Check specific stats if available
        if 'endpoints_found' in stats:
            self.assertEqual(stats.get('endpoints_found'), 2)
        
        if 'total_log_entries' in stats:
            self.assertEqual(stats.get('total_log_entries'), 2)
    
    def test_clear_results(self):
        """Test clearing parser results."""
        # Parse some data
        endpoints = self.parser.parse(self.valid_mitm_json_data)
        self.assertEqual(len(endpoints), 2)
        
        # Clear results
        self.parser.clear_results()
        
        # Check that results are cleared
        self.assertEqual(len(self.parser.parsed_endpoints), 0)
        self.assertEqual(len(self.parser.errors), 0)
        self.assertEqual(len(self.parser.warnings), 0)
    
    def test_filter_endpoints(self):
        """Test endpoint filtering functionality."""
        endpoints = self.parser.parse(self.valid_mitm_json_data)
        
        # Filter by method
        get_endpoints = self.parser.filter_endpoints(method="GET")
        self.assertEqual(len(get_endpoints), 1)
        self.assertEqual(get_endpoints[0].method, "GET")
        
        # Filter by status code
        success_endpoints = self.parser.filter_endpoints(response_status=200)
        self.assertEqual(len(success_endpoints), 1)
        self.assertEqual(success_endpoints[0].response_status, 200)
        
        # Filter by authenticated endpoints
        auth_endpoints = self.parser.get_authenticated_endpoints()
        self.assertEqual(len(auth_endpoints), 2)
    
    def test_unique_extraction(self):
        """Test unique data extraction methods."""
        endpoints = self.parser.parse(self.valid_mitm_json_data)
        
        # Test unique methods
        unique_methods = self.parser.get_unique_methods()
        self.assertEqual(set(unique_methods), {"GET", "POST"})
        
        # Test unique base URLs
        unique_base_urls = self.parser.get_unique_base_urls()
        self.assertEqual(unique_base_urls, ["https://api.example.com"])
    
    def test_api_patterns(self):
        """Test API pattern detection."""
        mitm_with_patterns = [
            {
                "timestamp": "2024-03-15 10:24:12.478",
                "method": "GET",
                "url": "https://api.example.com/users/123",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/users/123",
                "query": "",
                "request_headers": {},
                "request_body": None,
                "response_timestamp": "2024-03-15 10:24:12.523",
                "response_status": 200,
                "response_status_text": "OK",
                "response_headers": {},
                "response_body": "{}",
                "ssl_info": None
            },
            {
                "timestamp": "2024-03-15 10:24:15.789",
                "method": "GET",
                "url": "https://api.example.com/users/456",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/users/456",
                "query": "",
                "request_headers": {},
                "request_body": None,
                "response_timestamp": "2024-03-15 10:24:15.845",
                "response_status": 200,
                "response_status_text": "OK",
                "response_headers": {},
                "response_body": "{}",
                "ssl_info": None
            },
            {
                "timestamp": "2024-03-15 10:24:18.234",
                "method": "POST",
                "url": "https://api.example.com/users",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/users",
                "query": "",
                "request_headers": {},
                "request_body": "{}",
                "response_timestamp": "2024-03-15 10:24:18.312",
                "response_status": 201,
                "response_status_text": "Created",
                "response_headers": {},
                "response_body": "{}",
                "ssl_info": None
            }
        ]
        
        endpoints = self.parser.parse(mitm_with_patterns)
        self.assertEqual(len(endpoints), 3)
        
        # Test API patterns
        api_patterns = self.parser.get_api_patterns()
        self.assertIsNotNone(api_patterns)
        self.assertGreater(len(api_patterns), 0)
        
        # Check for user pattern
        user_pattern = "/users/{id}"
        if user_pattern in api_patterns:
            self.assertEqual(len(api_patterns[user_pattern]), 2)
    
    def test_ssl_certificates(self):
        """Test SSL certificate extraction."""
        mitm_with_ssl = [
            {
                "timestamp": "2024-03-15 10:24:12.478",
                "method": "GET",
                "url": "https://api.example.com/api/secure",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/api/secure",
                "query": "",
                "request_headers": {},
                "request_body": None,
                "response_timestamp": "2024-03-15 10:24:12.523",
                "response_status": 200,
                "response_status_text": "OK",
                "response_headers": {},
                "response_body": "{}",
                "ssl_info": {
                    "subject": "CN=api.example.com",
                    "issuer": "CN=Let's Encrypt Authority X3",
                    "serial": "1234567890"
                }
            }
        ]
        
        endpoints = self.parser.parse(mitm_with_ssl)
        self.assertEqual(len(endpoints), 1)
        
        # Test SSL certificates
        ssl_certs = self.parser.get_ssl_certificates()
        self.assertIsNotNone(ssl_certs)
        self.assertGreater(len(ssl_certs), 0)
        
        # Check for api.example.com certificate
        if "api.example.com" in ssl_certs:
            cert_info = ssl_certs["api.example.com"]
            self.assertEqual(cert_info["subject"], "CN=api.example.com")
            self.assertEqual(cert_info["issuer"], "CN=Let's Encrypt Authority X3")
    
    def test_response_body_extraction(self):
        """Test response body extraction and parsing."""
        mitm_with_responses = [
            {
                "timestamp": "2024-03-15 10:24:12.478",
                "method": "GET",
                "url": "https://api.example.com/api/users/123",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/api/users/123",
                "query": "",
                "request_headers": {},
                "request_body": None,
                "response_timestamp": "2024-03-15 10:24:12.523",
                "response_status": 200,
                "response_status_text": "OK",
                "response_headers": {
                    "Content-Type": "application/json"
                },
                "response_body": '{"id": 123, "name": "John Doe", "email": "john@example.com", "profile": {"firstName": "John", "lastName": "Doe", "avatar": "https://cdn.example.com/avatars/123.jpg"}, "created_at": "2023-01-15T10:30:00Z", "last_login": "2024-03-15T09:15:22Z", "permissions": ["read", "write", "admin"]}',
                "ssl_info": None
            }
        ]
        
        endpoints = self.parser.parse(mitm_with_responses)
        self.assertEqual(len(endpoints), 1)
        
        endpoint = endpoints[0]
        self.assertIsNotNone(endpoint.response_body)
        self.assertIn("id", endpoint.response_body)
        self.assertIn("name", endpoint.response_body)
        self.assertIn("profile", endpoint.response_body)
        self.assertIn("permissions", endpoint.response_body)
        
        # Test response body schema extraction
        if hasattr(endpoint, 'response_body_schema') and endpoint.response_body_schema:
            self.assertIsNotNone(endpoint.response_body_schema)
    
    def test_request_body_extraction(self):
        """Test request body extraction and parsing."""
        mitm_with_requests = [
            {
                "timestamp": "2024-03-15 10:24:15.789",
                "method": "POST",
                "url": "https://api.example.com/v2/orders",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/v2/orders",
                "query": "",
                "request_headers": {
                    "Content-Type": "application/json"
                },
                "request_body": '{"customer_id": 456, "items": [{"product_id": "prod_123", "quantity": 2, "price": 29.99}, {"product_id": "prod_456", "quantity": 1, "price": 149.99}], "shipping_address": {"street": "123 Main St", "city": "Anytown", "state": "CA", "zip": "90210"}, "payment_method": "card_1234567890"}',
                "response_timestamp": "2024-03-15 10:24:15.845",
                "response_status": 201,
                "response_status_text": "Created",
                "response_headers": {
                    "Content-Type": "application/json"
                },
                "response_body": '{"order_id": "ord_789abc123", "status": "pending", "total_amount": 209.97, "estimated_delivery": "2024-03-20", "tracking_number": null, "created_at": "2024-03-15T10:24:15.845Z"}',
                "ssl_info": None
            }
        ]
        
        endpoints = self.parser.parse(mitm_with_requests)
        self.assertEqual(len(endpoints), 1)
        
        endpoint = endpoints[0]
        self.assertIsNotNone(endpoint.request_body)
        self.assertIn("customer_id", endpoint.request_body)
        self.assertIn("items", endpoint.request_body)
        self.assertIn("shipping_address", endpoint.request_body)
        self.assertIn("payment_method", endpoint.request_body)
        
        # Test request body schema extraction
        if hasattr(endpoint, 'request_body_schema') and endpoint.request_body_schema:
            self.assertIsNotNone(endpoint.request_body_schema)
    
    def test_url_parameter_extraction(self):
        """Test URL parameter extraction from query strings."""
        mitm_with_url_params = [
            {
                "timestamp": "2024-03-15 10:24:12.478",
                "method": "GET",
                "url": "https://api.example.com/api/search?q=test&page=1&limit=20&sort=desc&filter=active&include=profile,settings",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/api/search",
                "query": "q=test&page=1&limit=20&sort=desc&filter=active&include=profile,settings",
                "request_headers": {},
                "request_body": None,
                "response_timestamp": "2024-03-15 10:24:12.523",
                "response_status": 200,
                "response_status_text": "OK",
                "response_headers": {},
                "response_body": "{}",
                "ssl_info": None
            }
        ]
        
        endpoints = self.parser.parse(mitm_with_url_params)
        self.assertEqual(len(endpoints), 1)
        
        endpoint = endpoints[0]
        
        # Test query parameters
        query_params = [p for p in endpoint.parameters if p.location == ParameterLocation.QUERY]
        self.assertEqual(len(query_params), 6)
        
        # Verify specific parameters
        q_param = next(p for p in query_params if p.name == "q")
        self.assertEqual(q_param.value, "test")
        
        page_param = next(p for p in query_params if p.name == "page")
        self.assertEqual(page_param.value, "1")
        
        limit_param = next(p for p in query_params if p.name == "limit")
        self.assertEqual(limit_param.value, "20")
        
        sort_param = next(p for p in query_params if p.name == "sort")
        self.assertEqual(sort_param.value, "desc")
        
        filter_param = next(p for p in query_params if p.name == "filter")
        self.assertEqual(filter_param.value, "active")
        
        include_param = next(p for p in query_params if p.name == "include")
        self.assertEqual(include_param.value, "profile,settings")
    
    def test_header_extraction(self):
        """Test header extraction from requests and responses."""
        mitm_with_headers = [
            {
                "timestamp": "2024-03-15 10:24:12.478",
                "method": "GET",
                "url": "https://api.example.com/api/users/123",
                "scheme": "https",
                "host": "api.example.com",
                "path": "/api/users/123",
                "query": "",
                "request_headers": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                    "X-API-Key": "sk_live_51Hn8ZFGKyGz9Vx12345",
                    "X-Request-ID": "req_1a2b3c4d5e6f",
                    "Connection": "keep-alive",
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "same-origin"
                },
                "request_body": None,
                "response_timestamp": "2024-03-15 10:24:12.523",
                "response_status": 200,
                "response_status_text": "OK",
                "response_headers": {
                    "Content-Type": "application/json; charset=utf-8",
                    "Content-Length": "342",
                    "X-RateLimit-Limit": "1000",
                    "X-RateLimit-Remaining": "999",
                    "X-RateLimit-Reset": "1710501852",
                    "X-Response-Time": "45ms",
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Server": "nginx/1.18.0",
                    "Date": "Fri, 15 Mar 2024 10:24:12 GMT",
                    "Connection": "keep-alive"
                },
                "response_body": "{}",
                "ssl_info": None
            }
        ]
        
        endpoints = self.parser.parse(mitm_with_headers)
        self.assertEqual(len(endpoints), 1)
        
        endpoint = endpoints[0]
        
        # Test request headers
        self.assertGreaterEqual(len(endpoint.headers), 10)
        
        # Verify specific request headers
        auth_header = next(h for h in endpoint.headers if h.name == "Authorization")
        self.assertTrue(auth_header.value.startswith("Bearer "))
        
        api_key_header = next(h for h in endpoint.headers if h.name == "X-API-Key")
        self.assertEqual(api_key_header.value, "sk_live_51Hn8ZFGKyGz9Vx12345")
        
        user_agent_header = next(h for h in endpoint.headers if h.name == "User-Agent")
        self.assertIn("Mozilla/5.0", user_agent_header.value)
        
        # Test response headers
        self.assertEqual(len(endpoint.response_headers), 10)
        
        # Verify specific response headers
        content_type_header = next(h for h in endpoint.response_headers if h.name == "Content-Type")
        self.assertEqual(content_type_header.value, "application/json; charset=utf-8")
        
        rate_limit_header = next(h for h in endpoint.response_headers if h.name == "X-RateLimit-Limit")
        self.assertEqual(rate_limit_header.value, "1000")
        
        server_header = next(h for h in endpoint.response_headers if h.name == "Server")
        self.assertEqual(server_header.value, "nginx/1.18.0")


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2) 