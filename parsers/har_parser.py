import json
import gzip
import base64
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
from datetime import datetime

from .base_parser import BaseParser
from models import (
    APIEndpoint, Parameter, Header, AuthInfo, SSLInfo,
    ParameterType, ParameterLocation, AuthType, AuthLocation
)
from utils import (
    validate_har_file, validate_json_content, extract_base_url,
    extract_path_from_url, normalize_url, is_api_endpoint,
    extract_query_parameters, extract_path_parameters,
    normalize_content_type, extract_schema_from_json,
    infer_parameter_types, sanitize_har_data
)


class HARParser(BaseParser):
    """
    Parser for HTTP Archive (HAR) files.
    
    This parser extracts API endpoints, parameters, headers, and authentication
    information from HAR files. It supports HAR 1.2 format and can handle
    various content types including JSON, XML, and form data.
    """
    
    def __init__(self):
        """Initialize the HAR parser."""
        super().__init__()
        self.har_version = None
        self.creator_info = None
        self.pages = []
        self.entries_processed = 0
        self.api_endpoints_found = 0
        self.non_api_requests = 0
        
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
                # Try to parse as JSON
                har_data = json.loads(data)
                return validate_har_file(har_data)
            elif isinstance(data, dict):
                return validate_har_file(data)
            else:
                return False
        except (json.JSONDecodeError, ValueError, TypeError):
            return False
    
    def parse(self, data: Any) -> List[APIEndpoint]:
        """
        Parse HAR data and extract API endpoints.
        
        Args:
            data: HAR data as string, dict, or file path
            
        Returns:
            List of discovered API endpoints
            
        Raises:
            ValueError: If the data is invalid or cannot be parsed
        """
        self.clear_results()
        
        try:
            # Parse input data
            har_data = self._parse_input(data)
            
            # Validate HAR structure
            if not validate_har_file(har_data):
                raise ValueError("Invalid HAR file structure")
            
            # Extract metadata
            self._extract_metadata(har_data)
            
            # Process entries
            entries = har_data.get('log', {}).get('entries', [])
            self.update_stats('total_entries', len(entries))
            
            for i, entry in enumerate(entries):
                try:
                    self._process_entry(entry, i)
                    self.entries_processed += 1
                except Exception as e:
                    self.add_error(f"Error processing entry {i}: {str(e)}")
            
            # Update final statistics
            self._update_final_stats()
            
            return self.parsed_endpoints
            
        except Exception as e:
            self.add_error(f"Failed to parse HAR data: {str(e)}")
            raise ValueError(f"HAR parsing failed: {str(e)}")
    
    def _parse_input(self, data: Any) -> Dict[str, Any]:
        """
        Parse input data into HAR format.
        
        Args:
            data: Input data (string, dict, or file path)
            
        Returns:
            Parsed HAR data as dictionary
        """
        if isinstance(data, dict):
            return data
        elif isinstance(data, str):
            # Check if it's a file path
            if data.endswith('.har') or data.endswith('.json'):
                try:
                    with open(data, 'r', encoding='utf-8') as f:
                        return json.load(f)
                except FileNotFoundError:
                    # Treat as JSON string
                    pass
            
            # Try to parse as JSON
            return json.loads(data)
        else:
            raise ValueError(f"Unsupported data type: {type(data)}")
    
    def _extract_metadata(self, har_data: Dict[str, Any]):
        """Extract metadata from HAR data."""
        log = har_data.get('log', {})
        
        self.har_version = log.get('version')
        self.creator_info = log.get('creator', {})
        self.pages = log.get('pages', [])
        
        self.update_stats('har_version', self.har_version)
        self.update_stats('creator', self.creator_info.get('name', 'Unknown'))
        self.update_stats('pages_count', len(self.pages))
    
    def _process_entry(self, entry: Dict[str, Any], index: int):
        """
        Process a single HAR entry.
        
        Args:
            entry: The HAR entry to process
            index: The entry index
        """
        request = entry.get('request', {})
        response = entry.get('response', {})
        
        # Extract basic request information
        method = request.get('method', 'GET')
        url = request.get('url', '')
        
        # Check if this looks like an API endpoint
        if not is_api_endpoint(url, method):
            self.non_api_requests += 1
            return
        
        # Create API endpoint
        endpoint = self._create_endpoint(entry, index)
        
        # Process request details
        self._process_request(endpoint, request)
        
        # Process response details
        self._process_response(endpoint, response)
        
        # Process timing information
        self._process_timing(endpoint, entry.get('timings', {}))
        
        # Add the endpoint
        self.add_endpoint(endpoint)
        self.api_endpoints_found += 1
    
    def _create_endpoint(self, entry: Dict[str, Any], index: int) -> APIEndpoint:
        """
        Create an APIEndpoint from HAR entry.
        
        Args:
            entry: The HAR entry
            index: The entry index
            
        Returns:
            The created APIEndpoint
        """
        request = entry.get('request', {})
        method = request.get('method', 'GET')
        url = request.get('url', '')
        
        # Extract URL components
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        path = parsed_url.path
        
        # Create endpoint
        endpoint = APIEndpoint(
            method=method,
            path=path,
            full_url=url,
            base_url=base_url,
            timestamp=entry.get('startedDateTime'),
            duration=entry.get('time'),
            har_entry_index=index,
            page_ref=entry.get('pageref')
        )
        
        return endpoint
    
    def _process_request(self, endpoint: APIEndpoint, request: Dict[str, Any]):
        """
        Process request information.
        
        Args:
            endpoint: The API endpoint to update
            request: The HAR request object
        """
        # Process headers
        headers = request.get('headers', [])
        for header_data in headers:
            header = Header(
                name=header_data.get('name', ''),
                value=header_data.get('value', '')
            )
            endpoint.add_header(header)
            
            # Extract content type and user agent
            if header.name.lower() == 'content-type':
                endpoint.content_type = normalize_content_type(header.value)
            elif header.name.lower() == 'user-agent':
                endpoint.user_agent = header.value
        
        # Process query parameters
        query_string = request.get('queryString', [])
        for param_data in query_string:
            param = Parameter(
                name=param_data.get('name', ''),
                location=ParameterLocation.QUERY,
                value=param_data.get('value', '')
            )
            endpoint.add_parameter(param)
        
        # Process request body
        self._process_request_body(endpoint, request)
        
        # Extract authentication information
        self._extract_auth_info(endpoint, request)
    
    def _process_request_body(self, endpoint: APIEndpoint, request: Dict[str, Any]):
        """
        Process request body and extract schema.
        
        Args:
            endpoint: The API endpoint to update
            request: The HAR request object
        """
        # Check for different body formats
        post_data = request.get('postData')
        if not post_data:
            return
        
        mime_type = post_data.get('mimeType', '')
        text = post_data.get('text', '')
        
        if not text:
            return
        
        # Handle different content types
        if 'application/json' in mime_type:
            self._process_json_body(endpoint, text, is_request=True)
        elif 'application/x-www-form-urlencoded' in mime_type:
            self._process_form_body(endpoint, text, is_request=True)
        elif 'multipart/form-data' in mime_type:
            self._process_multipart_body(endpoint, post_data, is_request=True)
        elif 'text/xml' in mime_type or 'application/xml' in mime_type:
            self._process_xml_body(endpoint, text, is_request=True)
        else:
            # Store as raw text
            endpoint.request_body = {'raw': text}
    
    def _process_response(self, endpoint: APIEndpoint, response: Dict[str, Any]):
        """
        Process response information.
        
        Args:
            endpoint: The API endpoint to update
            response: The HAR response object
        """
        # Set response status
        endpoint.response_status = response.get('status')
        
        # Process response headers
        headers = response.get('headers', [])
        for header_data in headers:
            header = Header(
                name=header_data.get('name', ''),
                value=header_data.get('value', '')
            )
            endpoint.add_response_header(header)
        
        # Process response body
        self._process_response_body(endpoint, response)
    
    def _process_response_body(self, endpoint: APIEndpoint, response: Dict[str, Any]):
        """
        Process response body and extract schema.
        
        Args:
            endpoint: The API endpoint to update
            response: The HAR response object
        """
        content = response.get('content', {})
        if not content:
            return
        
        mime_type = content.get('mimeType', '')
        text = content.get('text', '')
        
        if not text:
            return
        
        # Handle compression
        if content.get('compression', 0) > 0:
            text = self._decompress_content(text, content.get('encoding'))
        
        # Handle different content types
        if 'application/json' in mime_type:
            self._process_json_body(endpoint, text, is_request=False)
        elif 'text/xml' in mime_type or 'application/xml' in mime_type:
            self._process_xml_body(endpoint, text, is_request=False)
        else:
            # Store as raw text
            endpoint.response_body = {'raw': text}
    
    def _process_json_body(self, endpoint: APIEndpoint, text: str, is_request: bool = True):
        """
        Process JSON body and extract schema.
        
        Args:
            endpoint: The API endpoint to update
            text: The JSON text
            is_request: Whether this is a request or response body
        """
        try:
            # Parse JSON
            json_data = json.loads(text)
            
            # Store the parsed JSON
            if is_request:
                endpoint.request_body = json_data
                endpoint.request_body_schema = extract_schema_from_json(json_data)
            else:
                endpoint.response_body = json_data
                endpoint.response_body_schema = extract_schema_from_json(json_data)
            
            # Infer parameter types
            param_types = infer_parameter_types(json_data)
            endpoint.parameter_types.update(param_types)
            
        except json.JSONDecodeError as e:
            self.add_warning(f"Failed to parse JSON body: {str(e)}")
            # Store as raw text
            if is_request:
                endpoint.request_body = {'raw': text}
            else:
                endpoint.response_body = {'raw': text}
    
    def _process_form_body(self, endpoint: APIEndpoint, text: str, is_request: bool = True):
        """
        Process form-encoded body.
        
        Args:
            endpoint: The API endpoint to update
            text: The form-encoded text
            is_request: Whether this is a request or response body
        """
        try:
            # Parse form data
            form_data = parse_qs(text)
            
            # Convert to simple dict (take first value for each key)
            parsed_data = {key: values[0] if values else '' for key, values in form_data.items()}
            
            # Store the parsed data
            if is_request:
                endpoint.request_body = parsed_data
            else:
                endpoint.response_body = parsed_data
            
            # Add form parameters
            for key, value in parsed_data.items():
                param = Parameter(
                    name=key,
                    location=ParameterLocation.BODY,
                    value=value
                )
                endpoint.add_parameter(param)
                
        except Exception as e:
            self.add_warning(f"Failed to parse form body: {str(e)}")
            # Store as raw text
            if is_request:
                endpoint.request_body = {'raw': text}
            else:
                endpoint.response_body = {'raw': text}
    
    def _process_multipart_body(self, endpoint: APIEndpoint, post_data: Dict[str, Any], is_request: bool = True):
        """
        Process multipart form data.
        
        Args:
            endpoint: The API endpoint to update
            post_data: The post data object
            is_request: Whether this is a request or response body
        """
        params = post_data.get('params', [])
        parsed_data = {}
        
        for param in params:
            name = param.get('name', '')
            value = param.get('value', '')
            filename = param.get('fileName', '')
            
            if filename:
                # This is a file upload
                param_obj = Parameter(
                    name=name,
                    location=ParameterLocation.BODY,
                    value=filename,
                    param_type=ParameterType.FILE
                )
                parsed_data[name] = {'type': 'file', 'filename': filename}
            else:
                # This is a regular parameter
                param_obj = Parameter(
                    name=name,
                    location=ParameterLocation.BODY,
                    value=value
                )
                parsed_data[name] = value
            
            endpoint.add_parameter(param_obj)
        
        # Store the parsed data
        if is_request:
            endpoint.request_body = parsed_data
        else:
            endpoint.response_body = parsed_data
    
    def _process_xml_body(self, endpoint: APIEndpoint, text: str, is_request: bool = True):
        """
        Process XML body.
        
        Args:
            endpoint: The API endpoint to update
            text: The XML text
            is_request: Whether this is a request or response body
        """
        
        if is_request:
            endpoint.request_body = {'raw': text, 'type': 'xml'}
        else:
            endpoint.response_body = {'raw': text, 'type': 'xml'}
    
    def _extract_auth_info(self, endpoint: APIEndpoint, request: Dict[str, Any]):
        """
        Extract authentication information from request.
        
        Args:
            endpoint: The API endpoint to update
            request: The HAR request object
        """
        auth_info = AuthInfo()
        
        # Check headers for authentication
        headers = request.get('headers', [])
        for header_data in headers:
            name = header_data.get('name', '').lower()
            value = header_data.get('value', '')
            
            if name == 'authorization':
                auth_info.location = AuthLocation.HEADER
                auth_info.add_auth_header('authorization')
                
                if value.lower().startswith('bearer '):
                    auth_info.auth_type = AuthType.BEARER
                    auth_info.token = value[7:]  # Remove 'Bearer ' prefix
                elif value.lower().startswith('basic '):
                    auth_info.auth_type = AuthType.BASIC
                    auth_info.token = value[6:]  # Remove 'Basic ' prefix
                elif value.lower().startswith('digest '):
                    auth_info.auth_type = AuthType.DIGEST
                    auth_info.token = value[7:]  # Remove 'Digest ' prefix
                else:
                    auth_info.auth_type = AuthType.CUSTOM
                    auth_info.token = value
                    
            elif name in ['x-api-key', 'x-auth-token', 'x-access-token']:
                auth_info.location = AuthLocation.HEADER
                auth_info.auth_type = AuthType.API_KEY
                auth_info.api_key = value
                auth_info.add_auth_header(name)
                
            elif name == 'cookie':
                auth_info.location = AuthLocation.COOKIE
                auth_info.auth_type = AuthType.COOKIE
                auth_info.add_auth_header('cookie')
        
        # Check query parameters for authentication
        query_string = request.get('queryString', [])
        for param_data in query_string:
            name = param_data.get('name', '').lower()
            value = param_data.get('value', '')
            
            if name in ['token', 'key', 'api_key', 'apikey', 'auth']:
                auth_info.location = AuthLocation.QUERY
                auth_info.auth_type = AuthType.API_KEY
                auth_info.api_key = value
                auth_info.add_auth_parameter(name)
        
        # Set the auth info if any authentication was found
        if auth_info.auth_type != AuthType.UNKNOWN:
            endpoint.auth_info = auth_info
    
    def _process_timing(self, endpoint: APIEndpoint, timings: Dict[str, Any]):
        """
        Process timing information.
        
        Args:
            endpoint: The API endpoint to update
            timings: The HAR timings object
        """
        # Timing information is already stored in APIEndpoint.duration
        # Additional timing details could be extracted here if needed
        pass
    
    def _decompress_content(self, text: str, encoding: str = None) -> str:
        """
        Decompress content if it's compressed.
        
        Args:
            text: The compressed text
            encoding: The encoding type
            
        Returns:
            The decompressed text
        """
        try:
            if encoding == 'gzip':
                # Handle base64 encoded gzip
                if text:
                    compressed_data = base64.b64decode(text)
                    return gzip.decompress(compressed_data).decode('utf-8')
            elif encoding == 'deflate':
                import zlib
                if text:
                    compressed_data = base64.b64decode(text)
                    return zlib.decompress(compressed_data).decode('utf-8')
        except Exception as e:
            self.add_warning(f"Failed to decompress content: {str(e)}")
        
        return text
    
    def _update_final_stats(self):
        """Update final parser statistics."""
        self.update_stats('entries_processed', self.entries_processed)
        self.update_stats('api_endpoints_found', self.api_endpoints_found)
        self.update_stats('non_api_requests', self.non_api_requests)
        self.update_stats('success_rate', 
                         (self.api_endpoints_found / max(self.entries_processed, 1)) * 100)
        
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
    
    def get_har_version(self) -> Optional[str]:
        """Get the HAR version."""
        return self.har_version
    
    def get_creator_info(self) -> Optional[Dict[str, Any]]:
        """Get the creator information."""
        return self.creator_info
    
    def get_pages(self) -> List[Dict[str, Any]]:
        """Get the pages information."""
        return self.pages.copy()
    
    def filter_by_content_type(self, content_type: str) -> List[APIEndpoint]:
        """
        Filter endpoints by content type.
        
        Args:
            content_type: The content type to filter by
            
        Returns:
            List of endpoints with the specified content type
        """
        return [ep for ep in self.parsed_endpoints if ep.content_type == content_type]
    
    def filter_by_status_code(self, status_code: int) -> List[APIEndpoint]:
        """
        Filter endpoints by response status code.
        
        Args:
            status_code: The status code to filter by
            
        Returns:
            List of endpoints with the specified status code
        """
        return [ep for ep in self.parsed_endpoints if ep.response_status == status_code]
    
    def get_endpoints_by_method(self, method: str) -> List[APIEndpoint]:
        """
        Get endpoints by HTTP method.
        
        Args:
            method: The HTTP method
            
        Returns:
            List of endpoints with the specified method
        """
        return self.filter_endpoints(method=method.upper())
    
    def get_endpoints_by_base_url(self, base_url: str) -> List[APIEndpoint]:
        """
        Get endpoints by base URL.
        
        Args:
            base_url: The base URL
            
        Returns:
            List of endpoints with the specified base URL
        """
        return self.filter_endpoints(base_url=base_url)


if __name__ == "__main__":
    import sys
    import os
    
    def main():
        """Main function to run HAR parser from command line."""
        if len(sys.argv) != 2:
            print("Usage: python har_parser.py <path_to_har_file>")
            print("\nExamples:")
            print("  python har_parser.py ../samples/sample.har.json")
            print("  python har_parser.py my_sample.har")
            return
        
        har_file_path = sys.argv[1]
        
        # Check if file exists
        if not os.path.exists(har_file_path):
            print(f"Error: File '{har_file_path}' not found.")
            return
        
        # Initialize parser
        parser = HARParser()
        
        try:
            # Load and parse HAR file
            with open(har_file_path, 'r', encoding='utf-8') as f:
                har_data = json.load(f)
            
            # Parse the data
            endpoints = parser.parse(har_data)
            
            # Display results
            print(f"\n{'='*60}")
            print(f"HAR Parser Results for: {har_file_path}")
            print(f"{'='*60}")
            
            if endpoints:
                print(f"\nFound {len(endpoints)} API endpoint(s):")
                print("-" * 40)
                
                for i, endpoint in enumerate(endpoints, 1):
                    print(f"\n{i}. {endpoint.method} {endpoint.full_url}")
                    print(f"   Status: {endpoint.response_status}")
                    print(f"   Content Type: {endpoint.content_type}")
                    
                    if endpoint.parameters:
                        print(f"   Parameters ({len(endpoint.parameters)}):")
                        for param in endpoint.parameters:
                            value_display = f" = {param.value}" if param.value else ""
                            print(f"     - {param.name} ({param.param_type.value}) in {param.location.value}{value_display}")
                    
                    if endpoint.headers:
                        print(f"   Headers ({len(endpoint.headers)}):")
                        for header in endpoint.headers:
                            # Truncate sensitive values
                            if header.is_sensitive:
                                value_display = f" = {header.value[:20]}..." if len(header.value) > 20 else f" = {header.value}"
                            else:
                                value_display = f" = {header.value}"
                            print(f"     - {header.name}{value_display}")
                    
                    if endpoint.auth_info:
                        auth_str = endpoint.auth_info.get_auth_string()
                        print(f"   Authentication: {endpoint.auth_info.auth_type.value}")
                        if auth_str:
                            print(f"     Auth Details: {auth_str}")
                    
                    if endpoint.request_body:
                        print(f"   Request Body:")
                        if isinstance(endpoint.request_body, dict):
                            if 'raw' in endpoint.request_body:
                                print(f"     Raw: {endpoint.request_body['raw'][:100]}...")
                            else:
                                print(f"     JSON: {json.dumps(endpoint.request_body, indent=6)}")
                        else:
                            print(f"     Content: {str(endpoint.request_body)[:100]}...")
                    
                    if endpoint.response_body:
                        print(f"   Response Body:")
                        if isinstance(endpoint.response_body, dict):
                            if 'raw' in endpoint.response_body:
                                print(f"     Raw: {endpoint.response_body['raw'][:100]}...")
                            else:
                                print(f"     JSON: {json.dumps(endpoint.response_body, indent=6)}")
                        else:
                            print(f"     Content: {str(endpoint.response_body)[:100]}...")
                    
                    # Show request/response body schemas if available
                    if endpoint.request_body_schema:
                        print(f"   Request Schema: {json.dumps(endpoint.request_body_schema, indent=6)}")
                    
                    if endpoint.response_body_schema:
                        print(f"   Response Schema: {json.dumps(endpoint.response_body_schema, indent=6)}")
                    
                    print("-" * 60)
            else:
                print("\nNo API endpoints found in this HAR file.")
                print("This might be because:")
                print("- The file contains only web page requests (HTML, CSS, JS)")
                print("- The API calls don't match the parser's criteria")
                print("- The file structure is different from expected HAR format")
            
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
                    
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in HAR file: {e}")
        except Exception as e:
            print(f"Error parsing HAR file: {e}")
    
    main()