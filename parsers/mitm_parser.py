import json
import re
import base64
import gzip
import zlib
from typing import List, Dict, Any, Optional, Union
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime
import ssl
import socket

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


class MITMParser(BaseParser):
    """
    Parser for MITM proxy log files.
    
    This parser extracts API endpoints, SSL certificates, authentication,
    and request/response patterns from MITM proxy logs. It supports various
    log formats and can infer API patterns from repeated requests.
    """
    
    def __init__(self):
        """Initialize the MITM parser."""
        super().__init__()
        self.log_entries = []
        self.ssl_certificates = {}
        self.api_patterns = {}
        self.request_patterns = {}
        self.response_patterns = {}
        
    def can_parse(self, data: Any) -> bool:
        """
        Check if this parser can handle the given data.
        
        Args:
            data: The data to check (can be string, dict, or file path)
            
        Returns:
            True if the parser can handle this data type, False otherwise
        """
        try:
            if isinstance(data, str):
                # Try to parse as JSON first
                try:
                    log_data = json.loads(data)
                    return self._validate_mitm_log(log_data)
                except json.JSONDecodeError:
                    # Try to parse as line-by-line log format
                    lines = data.strip().split('\n')
                    return len(lines) > 0 and any(self._is_mitm_log_line(line) for line in lines[:5])
            elif isinstance(data, dict):
                return self._validate_mitm_log(data)
            else:
                return False
        except Exception:
            return False
    
    def parse(self, data: Any) -> List[APIEndpoint]:
        """
        Parse MITM proxy logs and extract API endpoints.
        
        Args:
            data: MITM proxy logs as string, dict, or file path
            
        Returns:
            List of discovered API endpoints
            
        Raises:
            ValueError: If the data is invalid or cannot be parsed
        """
        self.clear_results()
        
        try:
            # Parse input data
            self.log_entries = self._parse_input(data)
            
            # Validate log structure
            if not self.log_entries:
                raise ValueError("No valid MITM log entries found")
            
            # Extract SSL certificates
            self._extract_ssl_certificates()
            
            # Process log entries and extract endpoints
            self._process_log_entries()
            
            # Analyze patterns
            self._analyze_patterns()
            
            # Update final statistics
            self._update_final_stats()
            
            return self.parsed_endpoints
            
        except Exception as e:
            self.add_error(f"Failed to parse MITM logs: {str(e)}")
            raise ValueError(f"MITM parsing failed: {str(e)}")
    
    def _parse_input(self, data: Any) -> List[Dict[str, Any]]:
        """
        Parse input data into MITM log format.
        
        Args:
            data: Input data (string, dict, or file path)
            
        Returns:
            List of parsed log entries
        """
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            return [data]
        elif isinstance(data, str):
            # Check if it's a file path
            if data.endswith(('.json', '.log', '.txt')):
                try:
                    with open(data, 'r', encoding='utf-8') as f:
                        content = f.read()
                except FileNotFoundError:
                    # Treat as log string
                    content = data
            else:
                content = data
            
            # Try to parse as JSON first
            try:
                json_data = json.loads(content)
                if isinstance(json_data, list):
                    return json_data
                else:
                    return [json_data]
            except json.JSONDecodeError:
                # Parse as line-by-line log format
                return self._parse_line_by_line(content)
        else:
            raise ValueError(f"Unsupported data type: {type(data)}")
    
    def _parse_line_by_line(self, content: str) -> List[Dict[str, Any]]:
        """
        Parse line-by-line log format.
        
        Args:
            content: Log content as string
            
        Returns:
            List of parsed log entries
        """
        entries = []
        lines = content.strip().split('\n')
        
        current_entry = None
        in_headers = False
        in_body = False
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Check if this is a new request entry
            if self._is_request_start(line):
                if current_entry:
                    entries.append(current_entry)
                current_entry = self._parse_request_line(line)
                in_headers = False
                in_body = False
            elif current_entry and self._is_response_start(line):
                current_entry.update(self._parse_response_line(line))
                in_headers = False
                in_body = False
            elif current_entry and self._is_ssl_info(line):
                current_entry.update(self._parse_ssl_line(line))
            elif current_entry and in_headers and ':' in line:
                # Parse header line
                if ':' in line:
                    header_name, header_value = line.split(':', 1)
                    current_entry['headers'][header_name.strip()] = header_value.strip()
            elif current_entry and in_headers and line == '':
                # Empty line after headers, body might follow
                in_headers = False
                in_body = True
            elif current_entry and in_body:
                # Parse body data
                if not current_entry.get('body'):
                    current_entry['body'] = ''
                current_entry['body'] += line + '\n'
            elif current_entry and not in_headers and not in_body and any(method in line for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']):
                # This is the HTTP request line (method, URL, version)
                self._parse_http_request_line(current_entry, line)
                in_headers = True
            elif current_entry and not in_headers and not in_body and line.startswith('HTTP/'):
                # This is the HTTP response line
                self._parse_http_response_line(current_entry, line)
                in_headers = True
        
        # Add the last entry
        if current_entry:
            entries.append(current_entry)
        
        return entries
    
    def _is_mitm_log_line(self, line: str) -> bool:
        """
        Check if a line looks like MITM log data.
        
        Args:
            line: Log line
            
        Returns:
            True if it looks like MITM log data
        """
        # Common MITM log patterns
        patterns = [
            r'^\d{4}-\d{2}-\d{2}',  # Date format
            r'GET|POST|PUT|DELETE|PATCH',  # HTTP methods
            r'https?://',  # URLs
            r'HTTP/\d\.\d',  # HTTP version
            r'SSL|TLS',  # SSL/TLS indicators
            r'Certificate',  # Certificate indicators
        ]
        
        return any(re.search(pattern, line, re.IGNORECASE) for pattern in patterns)
    
    def _is_request_start(self, line: str) -> bool:
        """Check if line starts a new request."""
        return bool(re.match(r'^\[\d{4}-\d{2}-\d{2}', line) and 'REQUEST' in line and '->' in line)
    
    def _is_response_start(self, line: str) -> bool:
        """Check if line starts a response."""
        return bool(re.match(r'^\[\d{4}-\d{2}-\d{2}', line) and 'RESPONSE' in line and '<-' in line)
    
    def _is_ssl_info(self, line: str) -> bool:
        """Check if line contains SSL information."""
        return any(ssl_term in line.lower() for ssl_term in ['ssl', 'tls', 'certificate', 'subject', 'issuer'])
    
    def _is_body_data(self, line: str) -> bool:
        """Check if line contains body data."""
        return line.startswith('{') or line.startswith('[') or '=' in line or '&' in line
    
    def _parse_request_line(self, line: str) -> Dict[str, Any]:
        """
        Parse a request line.
        
        Args:
            line: Request line
            
        Returns:
            Parsed request data
        """
        # Example: [2023-07-15 10:30:22.123] REQUEST 192.168.1.117:56780 -> grpc.example.com:443
        # Followed by: POST https://grpc.example.com/api.UserService/GetUser HTTP/2
        match = re.match(r'\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\]\s+REQUEST\s+([^:]+:\d+)\s+->\s+([^:]+:\d+)', line)
        
        if match:
            timestamp, client_info, server_info = match.groups()
            client_ip, client_port = client_info.split(':')
            server_host, server_port = server_info.split(':')
            
            return {
                'timestamp': timestamp,
                'client_ip': client_ip,
                'client_port': int(client_port),
                'server_host': server_host,
                'server_port': int(server_port),
                'method': None,  # Will be filled from next line
                'url': None,     # Will be filled from next line
                'http_version': None,  # Will be filled from next line
                'headers': {},
                'body': None,
                'ssl_info': None
            }
        
        return {}
    
    def _parse_response_line(self, line: str) -> Dict[str, Any]:
        """
        Parse a response line.
        
        Args:
            line: Response line
            
        Returns:
            Parsed response data
        """
        # Example: HTTP/1.1 200 OK
        match = re.match(r'(HTTP/\d\.\d)\s+(\d+)\s+(.+)', line)
        
        if match:
            http_version, status_code, status_text = match.groups()
            return {
                'response_status': int(status_code),
                'response_status_text': status_text,
                'response_http_version': http_version,
                'response_headers': {},
                'response_body': None
            }
        
        return {}
    
    def _parse_ssl_line(self, line: str) -> Dict[str, Any]:
        """
        Parse SSL information line.
        
        Args:
            line: SSL information line
            
        Returns:
            Parsed SSL data
        """
        ssl_info = {}
        
        # Extract certificate information
        if 'subject=' in line:
            subject_match = re.search(r'subject=([^,\s]+)', line)
            if subject_match:
                ssl_info['subject'] = subject_match.group(1)
        
        if 'issuer=' in line:
            issuer_match = re.search(r'issuer=([^,\s]+)', line)
            if issuer_match:
                ssl_info['issuer'] = issuer_match.group(1)
        
        if 'serial=' in line:
            serial_match = re.search(r'serial=([^,\s]+)', line)
            if serial_match:
                ssl_info['serial'] = serial_match.group(1)
        
        return {'ssl_info': ssl_info} if ssl_info else {}
    
    def _parse_body_line(self, line: str) -> Dict[str, Any]:
        """
        Parse body data line.
        
        Args:
            line: Body data line
            
        Returns:
            Parsed body data
        """
        # Try to parse as JSON
        try:
            json_data = json.loads(line)
            return {'body': json_data}
        except json.JSONDecodeError:
            # Try to parse as form data
            if '=' in line and '&' in line:
                form_data = {}
                for pair in line.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        form_data[unquote(key)] = unquote(value)
                return {'body': form_data}
            
            # Return as raw text
            return {'body': line}
    
    def _validate_mitm_log(self, log_data: Any) -> bool:
        """
        Validate MITM log structure.
        
        Args:
            log_data: The MITM log data
            
        Returns:
            True if valid, False otherwise
        """
        if isinstance(log_data, list):
            return len(log_data) > 0
        elif isinstance(log_data, dict):
            # Check for common MITM log fields
            required_fields = ['method', 'url', 'timestamp']
            return any(field in log_data for field in required_fields)
        else:
            return False
    
    def _extract_ssl_certificates(self):
        """Extract SSL certificate information from log entries."""
        for entry in self.log_entries:
            if 'ssl_info' in entry and entry['ssl_info']:
                host = entry.get('host', 'unknown')
                self.ssl_certificates[host] = entry['ssl_info']
    
    def _process_log_entries(self):
        """Process all log entries and extract endpoints."""
        for entry in self.log_entries:
            self._process_log_entry(entry)
        
        self.update_stats('total_log_entries', len(self.log_entries))
        self.update_stats('ssl_certificates_found', len(self.ssl_certificates))
    
    def _process_log_entry(self, entry: Dict[str, Any]):
        """
        Process a single log entry and create an endpoint.
        
        Args:
            entry: Log entry data
        """
        if not entry.get('method') or not entry.get('url'):
            return
        
        # Create endpoint
        endpoint = self._create_endpoint(entry)
        
        # Process URL parameters
        self._process_url_parameters(endpoint, entry)
        
        # Process headers
        self._process_headers(endpoint, entry)
        
        # Process request body
        self._process_request_body(endpoint, entry)
        
        # Process response
        self._process_response(endpoint, entry)
        
        # Process SSL information
        self._process_ssl_info(endpoint, entry)
        
        # Process authentication
        self._process_authentication(endpoint, entry)
        
        # Add the endpoint
        self.add_endpoint(endpoint)
    
    def _create_endpoint(self, entry: Dict[str, Any]) -> APIEndpoint:
        """
        Create an APIEndpoint from log entry.
        
        Args:
            entry: Log entry data
            
        Returns:
            The created APIEndpoint
        """
        method = entry.get('method', 'GET')
        url = entry.get('url', '')
        timestamp = entry.get('timestamp', datetime.now().isoformat())
        
        # Parse URL
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        path = parsed_url.path
        
        # Create endpoint
        endpoint = APIEndpoint(
            method=method,
            path=path,
            full_url=url,
            base_url=base_url,
            timestamp=timestamp,
            har_entry_index=len(self.parsed_endpoints)
        )
        
        return endpoint
    
    def _process_url_parameters(self, endpoint: APIEndpoint, entry: Dict[str, Any]):
        """
        Process URL parameters from log entry.
        
        Args:
            endpoint: The API endpoint to update
            entry: Log entry data
        """
        query = entry.get('query', '')
        if not query:
            return
        
        # Parse query parameters
        query_params = parse_qs(query)
        
        for param_name, param_values in query_params.items():
            param_value = param_values[0] if param_values else ''
            
            # Infer parameter type
            param_type = self._infer_parameter_type_from_value(param_value)
            
            param = Parameter(
                name=param_name,
                location=ParameterLocation.QUERY,
                value=param_value,
                param_type=param_type,
                required=False
            )
            
            endpoint.add_parameter(param)
    
    def _process_headers(self, endpoint: APIEndpoint, entry: Dict[str, Any]):
        """
        Process headers from log entry.
        
        Args:
            endpoint: The API endpoint to update
            entry: Log entry data
        """
        headers = entry.get('headers', {})
        
        for header_name, header_value in headers.items():
            header = Header(
                name=header_name,
                value=str(header_value),
                description=''
            )
            endpoint.add_header(header)
            
            # Set content type from headers
            if header_name.lower() == 'content-type':
                endpoint.content_type = normalize_content_type(header_value)
    
    def _process_request_body(self, endpoint: APIEndpoint, entry: Dict[str, Any]):
        """
        Process request body from log entry.
        
        Args:
            endpoint: The API endpoint to update
            entry: Log entry data
        """
        body = entry.get('body')
        if not body:
            return
        
        # Handle different body formats
        if isinstance(body, dict):
            endpoint.request_body = body
            # Try to infer schema
            try:
                schema = extract_schema_from_json(body)
                endpoint.request_body_schema = schema
            except Exception:
                pass
        elif isinstance(body, str):
            # Try to parse as JSON
            try:
                json_body = json.loads(body)
                endpoint.request_body = json_body
                schema = extract_schema_from_json(json_body)
                endpoint.request_body_schema = schema
            except json.JSONDecodeError:
                # Keep as raw string
                endpoint.request_body = body
    
    def _process_response(self, endpoint: APIEndpoint, entry: Dict[str, Any]):
        """
        Process response from log entry.
        
        Args:
            endpoint: The API endpoint to update
            entry: Log entry data
        """
        # Response status
        if 'response_status' in entry:
            endpoint.response_status = entry['response_status']
        
        # Response headers
        response_headers = entry.get('response_headers', {})
        for header_name, header_value in response_headers.items():
            header = Header(
                name=header_name,
                value=str(header_value),
                description=''
            )
            endpoint.add_response_header(header)
        
        # Response body
        response_body = entry.get('response_body')
        if response_body:
            endpoint.response_body = response_body
            
            # Try to infer schema from JSON response
            if isinstance(response_body, dict):
                try:
                    schema = extract_schema_from_json(response_body)
                    endpoint.response_body_schema = schema
                except Exception:
                    pass
    
    def _process_ssl_info(self, endpoint: APIEndpoint, entry: Dict[str, Any]):
        """
        Process SSL information from log entry.
        
        Args:
            endpoint: The API endpoint to update
            entry: Log entry data
        """
        ssl_info = entry.get('ssl_info')
        if not ssl_info:
            return
        
        # Create SSL info object
        ssl_obj = SSLInfo(
            subject=ssl_info.get('subject', ''),
            issuer=ssl_info.get('issuer', ''),
            serial_number=ssl_info.get('serial', ''),
            protocol_version=ssl_info.get('protocol', 'TLS'),
            cipher_suite=ssl_info.get('cipher_suite', 'unknown'),
            is_valid=True
        )
        
        endpoint.ssl_info = ssl_obj
    
    def _process_authentication(self, endpoint: APIEndpoint, entry: Dict[str, Any]):
        """
        Process authentication from log entry.
        
        Args:
            endpoint: The API endpoint to update
            entry: Log entry data
        """
        headers = entry.get('headers', {})
        
        # Check for authentication headers
        auth_headers = {
            'authorization': headers.get('authorization', ''),
            'x-api-key': headers.get('x-api-key', ''),
            'x-auth-token': headers.get('x-auth-token', ''),
            'cookie': headers.get('cookie', '')
        }
        
        # Create auth info based on headers
        auth_info = self._create_auth_info_from_headers(auth_headers)
        if auth_info:
            endpoint.auth_info = auth_info
    
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
        
        # Check for Basic auth
        elif auth_header.lower().startswith('basic '):
            auth_info.auth_type = AuthType.BASIC
            auth_info.location = AuthLocation.HEADER
            auth_info.token = auth_header[6:]  # Remove 'Basic ' prefix
        
        else:
            return None
        
        return auth_info
    
    def _infer_parameter_type_from_value(self, value: Any) -> ParameterType:
        """
        Infer parameter type from value.
        
        Args:
            value: Parameter value
            
        Returns:
            Inferred parameter type
        """
        if value is None:
            return ParameterType.STRING
        
        if isinstance(value, bool):
            return ParameterType.BOOLEAN
        elif isinstance(value, int):
            return ParameterType.INTEGER
        elif isinstance(value, float):
            return ParameterType.NUMBER
        elif isinstance(value, list):
            return ParameterType.ARRAY
        elif isinstance(value, dict):
            return ParameterType.OBJECT
        else:
            # Check if it's a number string
            str_value = str(value)
            try:
                int(str_value)
                return ParameterType.INTEGER
            except ValueError:
                try:
                    float(str_value)
                    return ParameterType.NUMBER
                except ValueError:
                    return ParameterType.STRING
    
    def _analyze_patterns(self):
        """Analyze patterns in the log entries."""
        # Group endpoints by path pattern
        path_patterns = {}
        for endpoint in self.parsed_endpoints:
            # Create a pattern by replacing IDs with placeholders
            pattern = re.sub(r'/\d+', '/{id}', endpoint.path)   #/users/123/profile	/users/{id}/profile
            pattern = re.sub(r'/[a-f0-9]{8,}', '/{uuid}', pattern)  #/users/abc123ef4567890a/comments	/users/{uuid}/comments
            
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
    
    def get_ssl_certificates(self) -> Dict[str, Any]:
        """Get the SSL certificates information."""
        return self.ssl_certificates.copy()
    
    def get_api_patterns(self) -> Dict[str, List[APIEndpoint]]:
        """Get the discovered API patterns."""
        return self.api_patterns.copy()

    def _parse_http_request_line(self, entry: Dict[str, Any], line: str):
        """
        Parse HTTP request line (method, URL, version).
        
        Args:
            entry: Current log entry
            line: HTTP request line
        """
        # Example: POST https://grpc.example.com/api.UserService/GetUser HTTP/2
        match = re.match(r'(\w+)\s+(https?://[^\s]+)\s+(HTTP/\d\.\d)', line)
        if match:
            method, url, http_version = match.groups()
            entry['method'] = method.upper()
            entry['url'] = url
            entry['http_version'] = http_version
            
            # Parse URL components
            parsed_url = urlparse(url)
            entry['scheme'] = parsed_url.scheme
            entry['host'] = parsed_url.netloc
            entry['path'] = parsed_url.path
            entry['query'] = parsed_url.query
    
    def _parse_http_response_line(self, entry: Dict[str, Any], line: str):
        """
        Parse HTTP response line (version, status, text).
        
        Args:
            entry: Current log entry
            line: HTTP response line
        """
        # Example: HTTP/1.1 200 OK
        match = re.match(r'(HTTP/\d\.\d)\s+(\d+)\s+(.+)', line)
        if match:
            http_version, status_code, status_text = match.groups()
            entry['response_http_version'] = http_version
            entry['response_status'] = int(status_code)
            entry['response_status_text'] = status_text


if __name__ == "__main__":
    import sys
    import os
    
    def main():
        """Main function to run MITM parser from command line."""
        if len(sys.argv) != 2:
            print("Usage: python mitm_parser.py <path_to_mitm_log_file>")
            print("\nExamples:")
            print("  python mitm_parser.py ../samples/mitm_log.json")
            print("  python mitm_parser.py proxy_log.txt")
            return
        
        log_file_path = sys.argv[1]
        
        # Check if file exists
        if not os.path.exists(log_file_path):
            print(f"Error: File '{log_file_path}' not found.")
            return
        
        # Initialize parser
        parser = MITMParser()
        
        try:
            # Load and parse MITM log file
            with open(log_file_path, 'r', encoding='utf-8') as f:
                log_data = f.read()
            
            # Parse the data
            endpoints = parser.parse(log_data)
            
            # Display results
            print(f"\n{'='*60}")
            print(f"MITM Parser Results for: {log_file_path}")
            print(f"{'='*60}")
            
            if endpoints:
                print(f"\nFound {len(endpoints)} API endpoint(s):")
                print("-" * 40)
                
                for i, endpoint in enumerate(endpoints, 1):
                    print(f"\n{i}. {endpoint.method} {endpoint.full_url}")
                    print(f"   Path: {endpoint.path}")
                    print(f"   Timestamp: {endpoint.timestamp}")
                    
                    if endpoint.parameters:
                        print(f"   Parameters ({len(endpoint.parameters)}):")
                        for param in endpoint.parameters:
                            value_display = f" = {param.value}" if param.value else ""
                            print(f"     - {param.name} ({param.param_type.value}) in {param.location.value}{value_display}")
                    
                    if endpoint.headers:
                        print(f"   Headers ({len(endpoint.headers)}):")
                        for header in endpoint.headers:
                            print(f"     - {header.name}: {header.value}")
                    
                    if endpoint.auth_info:
                        auth_str = endpoint.auth_info.get_auth_string()
                        print(f"   Authentication: {endpoint.auth_info.auth_type.value}")
                        if auth_str:
                            print(f"     Auth Details: {auth_str}")
                    
                    if endpoint.ssl_info:
                        print(f"   SSL: {endpoint.ssl_info.subject}")
                    
                    if endpoint.request_body:
                        print(f"   Request Body: {endpoint.request_body}")
                    
                    if endpoint.request_body_schema:
                        print(f"   Request Schema: {json.dumps(endpoint.request_body_schema, indent=6)}")
                    
                    if endpoint.response_body:
                        print(f"   Response Body: {endpoint.response_body}")
                    
                    if endpoint.response_status:
                        print(f"   Response Status: {endpoint.response_status}")
                    
                    print("-" * 60)
            else:
                print("\nNo API endpoints found in this MITM log.")
                print("This might be because:")
                print("- The file is not a valid MITM log format")
                print("- The log doesn't contain any HTTP requests")
                print("- The file structure is different from expected MITM format")
            
            # Show SSL certificates
            ssl_certs = parser.get_ssl_certificates()
            if ssl_certs:
                print(f"\n{'='*60}")
                print("SSL Certificates:")
                print(f"{'='*60}")
                for host, cert_info in ssl_certs.items():
                    print(f"Host: {host}")
                    for key, value in cert_info.items():
                        print(f"  {key}: {value}")
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
            print(f"Error parsing MITM log file: {e}")
    
    main() 