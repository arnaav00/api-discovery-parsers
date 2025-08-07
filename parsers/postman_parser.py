import json
import re
from typing import List, Dict, Any, Optional, Union
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime

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


class PostmanParser(BaseParser):
    """
    Parser for Postman Collection files.
    
    This parser extracts API endpoints, parameters, authentication, and examples
    from Postman collections. It supports Postman v2.1 format with variables,
    environments, and advanced features.
    """
    
    def __init__(self):
        """Initialize the Postman parser."""
        super().__init__()
        self.collection_data = None
        self.variables = {}
        self.environments = {}
        self.auth_configs = {}
        self.base_url = None
        self.collection_info = {}
        
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
                try:
                    spec_data = json.loads(data)
                except json.JSONDecodeError:
                    return False
                return self._validate_postman_collection(spec_data)
            elif isinstance(data, dict):
                return self._validate_postman_collection(data)
            else:
                return False
        except Exception:
            return False
    
    def parse(self, data: Any) -> List[APIEndpoint]:
        """
        Parse Postman collection and extract API endpoints.
        
        Args:
            data: Postman collection as string, dict, or file path
            
        Returns:
            List of discovered API endpoints
            
        Raises:
            ValueError: If the data is invalid or cannot be parsed
        """
        self.clear_results()
        
        try:
            # Parse input data
            self.collection_data = self._parse_input(data)
            
            # Validate Postman collection structure
            if not self._validate_postman_collection(self.collection_data):
                raise ValueError("Invalid Postman collection structure")
            
            # Extract collection metadata
            self._extract_metadata()
            
            # Extract variables and environments
            self._extract_variables()
            
            # Process items and extract endpoints
            self._process_items()
            
            # Update final statistics
            self._update_final_stats()
            
            return self.parsed_endpoints
            
        except Exception as e:
            error_msg = f"Postman parsing failed: {str(e)}"
            self.add_error(error_msg)
            
            # Print additional debugging information
            if hasattr(e, '__traceback__'):
                import traceback
                print(f"Full traceback:")
                traceback.print_exc()
            
            raise ValueError(error_msg)
    
    def _parse_input(self, data: Any) -> Dict[str, Any]:
        """
        Parse input data into Postman collection format.
        
        Args:
            data: Input data (string, dict, or file path)
            
        Returns:
            Parsed Postman collection data as dictionary
        """
        if isinstance(data, dict):
            return data
        elif isinstance(data, str):
            # Check if it's a file path
            if data.endswith('.json'):
                try:
                    with open(data, 'r', encoding='utf-8') as f:
                        content = f.read()
                except FileNotFoundError:
                    # Treat as JSON string
                    content = data
            else:
                content = data
            
            # Parse as JSON
            try:
                return json.loads(content)
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse as JSON: {str(e)}")
        else:
            raise ValueError(f"Unsupported data type: {type(data)}")
    
    def _validate_postman_collection(self, collection_data: Dict[str, Any]) -> bool:
        """
        Validate Postman collection structure.
        
        Args:
            collection_data: The Postman collection data
            
        Returns:
            True if valid, False otherwise
        """
        if not isinstance(collection_data, dict):
            return False
        
        # Check for required fields
        if 'info' not in collection_data:
            return False
        
        # Check for items (requests)
        if 'item' not in collection_data:
            return False
        
        return True
    
    def _extract_metadata(self):
        """Extract metadata from Postman collection."""
        self.collection_data = self.collection_data or {}
        
        # Extract collection info
        info = self.collection_data.get('info', {})
        
        # Handle version field - it can be a string or an object
        version_info = info.get('version', {})
        if isinstance(version_info, dict):
            version = version_info.get('major', 0)
        elif isinstance(version_info, str):
            # Try to extract major version from string like "2.1.0"
            try:
                version = int(version_info.split('.')[0])
            except (ValueError, IndexError):
                version = 0
        else:
            version = 0
        
        self.collection_info = {
            'name': info.get('name', 'Unknown Collection'),
            'description': info.get('description', ''),
            'version': version,
            'schema': info.get('schema', ''),
            'exported_at': info.get('exportedAt', ''),
            'exported_by': info.get('exportedBy', '')
        }
        
        # Extract variables
        variables = self.collection_data.get('variable', [])
        for var in variables:
            if isinstance(var, dict) and 'key' in var and 'value' in var:
                self.variables[var['key']] = var['value']
        
        # Extract auth if present
        auth = self.collection_data.get('auth', {})
        if auth:
            self.auth_configs['collection'] = auth
        
        # Update statistics
        self.update_stats('collection_name', self.collection_info['name'])
        self.update_stats('collection_version', self.collection_info['version'])
        self.update_stats('variables_count', len(self.variables))
        self.update_stats('schema', self.collection_info['schema'])
    
    def _extract_variables(self):
        """Extract variables from the collection."""
        # Collection-level variables are already extracted in _extract_metadata
        # This method can be extended for environment-specific variables
        pass
    
    def _process_items(self):
        """Process all items in the collection."""
        items = self.collection_data.get('item', [])
        
        for item in items:
            self._process_item(item)
        
        self.update_stats('total_items', len(items))
    
    def _process_item(self, item: Dict[str, Any], parent_auth: Optional[Dict[str, Any]] = None):
        """
        Process a single item (folder or request).
        
        Args:
            item: The item to process
            parent_auth: Authentication from parent folder
        """
        try:
            if not isinstance(item, dict):
                return
                
            # Check if this is a folder (has sub-items)
            if 'item' in item:
                # This is a folder, process its items
                sub_items = item.get('item', [])
                if isinstance(sub_items, list):
                    for sub_item in sub_items:
                        self._process_item(sub_item, parent_auth)
            
            # Check if this is a request (has request object)
            elif 'request' in item:
                # This is a request, process it
                self._process_request(item, parent_auth)
                
        except Exception as e:
            self.add_error(f"Error processing item: {str(e)}")
            # Continue processing other items
    
    def _process_request(self, request: Dict[str, Any], parent_auth: Optional[Dict[str, Any]] = None):
        """
        Process a single request and create an endpoint.
        
        Args:
            request: The request object
            parent_auth: Authentication from parent folder
        """
        try:
            # Extract request info
            request_info = request.get('request', {})
            if not request_info:
                return
            
            # Get method and URL
            method = request_info.get('method', 'GET').upper()
            url_info = request_info.get('url', {})
            
            if not url_info:
                return
            
            # Build URL
            full_url = self._build_url(url_info)
            if not full_url:
                return
            
            # Create endpoint
            endpoint = self._create_endpoint(method, full_url, request)
            
            # Process URL parameters
            self._process_url_parameters(endpoint, url_info)
            
            # Process headers
            self._process_headers(endpoint, request_info)
            
            # Process request body
            self._process_request_body(endpoint, request_info)
            
            # Process authentication
            self._process_authentication(endpoint, request_info, parent_auth)
            
            # Process scripts
            self._process_scripts(endpoint, request)
            
            # Process response examples
            self._process_response_examples(endpoint, request)
            
            # Add the endpoint
            self.add_endpoint(endpoint)
            
        except Exception as e:
            self.add_error(f"Error processing request: {str(e)}")
            # Continue processing other requests
    
    def _build_url(self, url_info: Dict[str, Any]) -> Optional[str]:
        """
        Build the full URL from URL info.
        
        Args:
            url_info: URL information from Postman request
            
        Returns:
            The full URL or None if invalid
        """
        if isinstance(url_info, str):
            return self._resolve_variables(url_info)
        
        # Handle structured URL
        raw_url = url_info.get('raw', '')
        if raw_url:
            return self._resolve_variables(raw_url)
        
        # Build from components
        protocol = url_info.get('protocol', 'https')
        host = url_info.get('host', [])
        port = url_info.get('port', '')
        path = url_info.get('path', [])
        query = url_info.get('query', [])
        
        if not host:
            return None
        
        # Build host string
        if isinstance(host, list):
            host_str = '.'.join(host)
        elif isinstance(host, str):
            host_str = host
        else:
            host_str = str(host)
        
        # Build path string
        if isinstance(path, list):
            path_str = '/'.join(path)
        elif isinstance(path, str):
            path_str = path
        else:
            path_str = str(path)
        if path_str and not path_str.startswith('/'):
            path_str = '/' + path_str
        
        # Build query string
        query_params = []
        for param in query:
            if isinstance(param, dict):
                key = param.get('key', '')
                value = param.get('value', '')
                if key:
                    query_params.append(f"{key}={value}")
        
        query_str = '&'.join(query_params) if query_params else ''
        
        # Construct URL
        url_parts = [protocol, host_str]
        if port:
            url_parts.append(f":{port}")
        url_parts.append(path_str)
        if query_str:
            url_parts.append(f"?{query_str}")
        
        full_url = ''.join(url_parts)
        return self._resolve_variables(full_url)
    
    def _resolve_variables(self, text: str) -> str:
        """
        Resolve Postman variables in text.
        
        Args:
            text: Text containing variables
            
        Returns:
            Text with variables resolved
        """
        if not text:
            return text
        
        # Replace {{variable}} with actual values
        # "https://api.example.com/v1/users"    api.example.com and v1 are subbed in
        for var_name, var_value in self.variables.items():
            pattern = r'\{\{' + re.escape(var_name) + r'\}}'
            text = re.sub(pattern, str(var_value), text)
        
        return text
    
    def _create_endpoint(self, method: str, full_url: str, request: Dict[str, Any]) -> APIEndpoint:
        """
        Create an APIEndpoint from Postman request.
        
        Args:
            method: HTTP method
            full_url: Full URL
            request: Request object
            
        Returns:
            The created APIEndpoint
        """
        # Extract URL components
        parsed_url = urlparse(full_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        path = parsed_url.path
        
        # Create endpoint
        endpoint = APIEndpoint(
            method=method,
            path=path,
            full_url=full_url,
            base_url=base_url,
            timestamp=datetime.now().isoformat(),
            har_entry_index=len(self.parsed_endpoints)
        )
        
        # Set request metadata
        request_info = request.get('request', {})
        endpoint.content_type = self._get_content_type(request_info)
        
        # Add request name as description
        name = request.get('name', '')
        if name:
            endpoint.description = name
        
        return endpoint
    
    def _process_url_parameters(self, endpoint: APIEndpoint, url_info: Dict[str, Any]):
        """
        Process URL parameters from Postman request.
        
        Args:
            endpoint: The API endpoint to update
            url_info: URL information
        """
        # Process query parameters
        query_params = url_info.get('query', [])
        for param in query_params:
            if isinstance(param, dict):
                param_obj = self._create_parameter_from_postman(param, ParameterLocation.QUERY)
                if param_obj:
                    endpoint.add_parameter(param_obj)
            elif isinstance(param, str):
                # Handle string query parameters (key=value format)
                if '=' in param:
                    key, value = param.split('=', 1)
                    param_obj = Parameter(
                        name=key,
                        location=ParameterLocation.QUERY,
                        value=value,
                        param_type=ParameterType.STRING,
                        required=False
                    )
                    endpoint.add_parameter(param_obj)
        
        # Process path parameters (extract from URL path)
        path_params = self._extract_path_parameters(endpoint.path)
        for param_name in path_params:
            param_obj = Parameter(
                name=param_name,
                location=ParameterLocation.PATH,
                param_type=ParameterType.STRING,
                required=True
            )
            endpoint.add_parameter(param_obj)
    
    def _extract_path_parameters(self, path: str) -> List[str]:
        """
        Extract path parameters from URL path.
        
        Args:
            path: URL path
            
        Returns:
            List of path parameter names
        """
        # Find parameters like :param or {param}
        path_params = []
        
        # Match :param pattern
        colon_params = re.findall(r':([^/]+)', path)
        path_params.extend(colon_params)
        
        # Match {param} pattern
        brace_params = re.findall(r'\{([^}]+)\}', path)
        path_params.extend(brace_params)
        
        return path_params
    
    def _process_headers(self, endpoint: APIEndpoint, request_info: Dict[str, Any]):
        """
        Process headers from Postman request.
        
        Args:
            endpoint: The API endpoint to update
            request_info: Request information
        """
        headers = request_info.get('header', [])
        for header in headers:
            if isinstance(header, dict):
                header_obj = Header(
                    name=header.get('key', ''),
                    value=header.get('value', ''),
                    description=header.get('description', '')
                )
                endpoint.add_header(header_obj)
    
    def _process_request_body(self, endpoint: APIEndpoint, request_info: Dict[str, Any]):
        """
        Process request body from Postman request.
        
        Args:
            endpoint: The API endpoint to update
            request_info: Request information
        """
        body = request_info.get('body', {})
        if not body or not isinstance(body, dict):
            return
        
        mode = body.get('mode', '')
        
        if mode == 'raw':
            # Raw body (JSON, XML, etc.)
            raw_data = body.get('raw', '')
            if raw_data:
                endpoint.request_body = raw_data
                
                # Try to infer schema from JSON
                try:
                    json_data = json.loads(raw_data)
                    schema = extract_schema_from_json(json_data)
                    endpoint.request_body_schema = schema
                except json.JSONDecodeError:
                    # Not JSON, keep as raw text
                    pass
        
        elif mode == 'urlencoded':
            # Form data
            urlencoded_data = body.get('urlencoded', [])
            form_data = {}
            for item in urlencoded_data:
                if isinstance(item, dict):
                    key = item.get('key', '')
                    value = item.get('value', '')
                    if key:
                        form_data[key] = value
            
            if form_data:
                endpoint.request_body = form_data
                endpoint.content_type = 'application/x-www-form-urlencoded'
        
        elif mode == 'formdata':
            # Multipart form data
            formdata = body.get('formdata', [])
            form_data = {}
            for item in formdata:
                if isinstance(item, dict):
                    key = item.get('key', '')
                    value = item.get('value', '')
                    if key:
                        form_data[key] = value
            
            if form_data:
                endpoint.request_body = form_data
                endpoint.content_type = 'multipart/form-data'
        
        elif mode == 'file':
            # File upload
            file_info = body.get('file', {})
            if file_info:
                endpoint.request_body = file_info
                endpoint.content_type = 'application/octet-stream'
    
    def _process_authentication(self, endpoint: APIEndpoint, request_info: Dict[str, Any], parent_auth: Optional[Dict[str, Any]] = None):
        """
        Process authentication from Postman request.
        
        Args:
            endpoint: The API endpoint to update
            request_info: Request information
            parent_auth: Authentication from parent folder
        """
        # Check request-level auth first
        auth = request_info.get('auth', parent_auth)
        if not auth or not isinstance(auth, dict):
            return
        
        auth_info = self._create_auth_info_from_postman(auth)
        if auth_info:
            endpoint.auth_info = auth_info
    
    def _create_auth_info_from_postman(self, auth: Dict[str, Any]) -> Optional[AuthInfo]:
        """
        Create AuthInfo from Postman authentication.
        
        Args:
            auth: Authentication object from Postman
            
        Returns:
            The created AuthInfo or None
        """
        if not isinstance(auth, dict):
            return None
            
        auth_type = auth.get('type', '').lower()
        auth_info = AuthInfo()
        
        if auth_type == 'bearer':
            auth_info.auth_type = AuthType.BEARER
            auth_info.location = AuthLocation.HEADER
            
            bearer_config = auth.get('bearer', [])
            if isinstance(bearer_config, list):
                for token_config in bearer_config:
                    if isinstance(token_config, dict):
                        key = token_config.get('key', '')
                        value = token_config.get('value', '')
                        if key == 'token':
                            auth_info.token = value
                            break
            elif isinstance(bearer_config, dict):
                auth_info.token = bearer_config.get('token', '')
        
        elif auth_type == 'apikey':
            auth_info.auth_type = AuthType.API_KEY
            auth_info.location = AuthLocation.HEADER
            
            apikey_config = auth.get('apikey', [])
            if isinstance(apikey_config, list):
                for key_config in apikey_config:
                    if isinstance(key_config, dict):
                        key = key_config.get('key', '')
                        value = key_config.get('value', '')
                        if key == 'key':
                            auth_info.api_key = value
                        elif key == 'value':
                            auth_info.token = value
            elif isinstance(apikey_config, dict):
                auth_info.api_key = apikey_config.get('key', '')
                auth_info.token = apikey_config.get('value', '')
        
        elif auth_type == 'basic':
            auth_info.auth_type = AuthType.BASIC
            auth_info.location = AuthLocation.HEADER
            
            basic_config = auth.get('basic', [])
            if isinstance(basic_config, list):
                for cred_config in basic_config:
                    if isinstance(cred_config, dict):
                        key = cred_config.get('key', '')
                        value = cred_config.get('value', '')
                        if key == 'username':
                            auth_info.username = value
                        elif key == 'password':
                            auth_info.password = value
            elif isinstance(basic_config, dict):
                auth_info.username = basic_config.get('username', '')
                auth_info.password = basic_config.get('password', '')
        
        elif auth_type == 'oauth2':
            auth_info.auth_type = AuthType.OAUTH2
            auth_info.location = AuthLocation.HEADER
            
            oauth_config = auth.get('oauth2', [])
            if isinstance(oauth_config, list):
                for token_config in oauth_config:
                    if isinstance(token_config, dict):
                        key = token_config.get('key', '')
                        value = token_config.get('value', '')
                        if key == 'accessToken':
                            auth_info.token = value
                            break
            elif isinstance(oauth_config, dict):
                auth_info.token = oauth_config.get('accessToken', '')
        
        else:
            auth_info.auth_type = AuthType.CUSTOM
        
        return auth_info
    
    def _process_scripts(self, endpoint: APIEndpoint, request: Dict[str, Any]):
        """
        Process scripts from Postman request.
        
        Args:
            endpoint: The API endpoint to update
            request: Request object
        """
        # Pre-request scripts
        events = request.get('event', [])
        if not isinstance(events, list):
            return
            
        for event in events:
            if not isinstance(event, dict):
                continue
                
            if event.get('listen') == 'prerequest':
                script = event.get('script', {})
                if isinstance(script, dict):
                    endpoint.pre_request_script = script.get('exec', [])
        
        # Test scripts
        for event in events:
            if not isinstance(event, dict):
                continue
                
            if event.get('listen') == 'test':
                script = event.get('script', {})
                if isinstance(script, dict):
                    endpoint.test_script = script.get('exec', [])
    
    def _process_response_examples(self, endpoint: APIEndpoint, request: Dict[str, Any]):
        """
        Process response examples from Postman request.
        
        Args:
            endpoint: The API endpoint to update
            request: Request object
        """
        response_examples = request.get('response', [])
        if not isinstance(response_examples, list) or not response_examples:
            return
            
        # Use the first response example
        example = response_examples[0]
        if not isinstance(example, dict):
            return
            
        # Extract response body
        body = example.get('body', '')
        if body:
            endpoint.response_body = body
        
        # Extract response status
        status = example.get('status', '')
        if status:
            try:
                endpoint.response_status = int(status)
            except ValueError:
                pass
        
        # Extract response headers
        headers = example.get('header', [])
        for header in headers:
            if isinstance(header, dict):
                header_obj = Header(
                    name=header.get('key', ''),
                    value=header.get('value', ''),
                    description=header.get('description', '')
                )
                endpoint.add_response_header(header_obj)
    
    def _create_parameter_from_postman(self, param: Dict[str, Any], location: ParameterLocation) -> Optional[Parameter]:
        """
        Create a Parameter from Postman parameter data.
        
        Args:
            param: Parameter data from Postman
            location: Parameter location
            
        Returns:
            The created Parameter or None if invalid
        """
        name = param.get('key', '')
        value = param.get('value', '')
        description = param.get('description', '')
        
        if not name:
            return None
        
        # Infer parameter type from value
        param_type = self._infer_parameter_type_from_value(value)
        
        # Create parameter
        param_obj = Parameter(
            name=name,
            location=location,
            value=value,
            param_type=param_type,
            required=param.get('disabled', False) == False,  # Not disabled = required
            description=description
        )
        
        return param_obj
    
    def _infer_parameter_type_from_value(self, value: Any) -> ParameterType:
        """
        Infer parameter type from example value.
        
        Args:
            value: Example value
            
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
    
    def _get_content_type(self, request_info: Dict[str, Any]) -> str:
        """
        Get content type from request info.
        
        Args:
            request_info: Request information
            
        Returns:
            Content type string
        """
        # Check headers for content type
        headers = request_info.get('header', [])
        for header in headers:
            if isinstance(header, dict) and header.get('key', '').lower() == 'content-type':
                return header.get('value', 'application/json')
        
        # Check body mode
        body = request_info.get('body', {})
        mode = body.get('mode', '')
        
        if mode == 'raw':
            return 'application/json'  # Default for raw
        elif mode == 'urlencoded':
            return 'application/x-www-form-urlencoded'
        elif mode == 'formdata':
            return 'multipart/form-data'
        elif mode == 'file':
            return 'application/octet-stream'
        
        return 'application/json'  # Default
    
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
    
    def get_collection_info(self) -> Dict[str, Any]:
        """Get the collection information."""
        return self.collection_info.copy()
    
    def get_variables(self) -> Dict[str, Any]:
        """Get the collection variables."""
        return self.variables.copy()
    
    def get_auth_configs(self) -> Dict[str, Any]:
        """Get the authentication configurations."""
        return self.auth_configs.copy()


if __name__ == "__main__":
    import sys
    import os
    
    def main():
        """Main function to run Postman parser from command line."""
        if len(sys.argv) != 2:
            print("Usage: python postman_parser.py <path_to_postman_collection>")
            print("\nExamples:")
            print("  python postman_parser.py ../samples/collection.json")
            print("  python postman_parser.py my_collection.json")
            return
        
        collection_file_path = sys.argv[1]
        
        # Check if file exists
        if not os.path.exists(collection_file_path):
            print(f"Error: File '{collection_file_path}' not found.")
            return
        
        # Initialize parser
        parser = PostmanParser()
        
        try:
            # Load and parse Postman collection
            with open(collection_file_path, 'r', encoding='utf-8') as f:
                collection_data = f.read()
            
            # Parse the data
            endpoints = parser.parse(collection_data)
            
            # Display results
            print(f"\n{'='*60}")
            print(f"Postman Parser Results for: {collection_file_path}")
            print(f"{'='*60}")
            
            if endpoints:
                print(f"\nFound {len(endpoints)} API endpoint(s):")
                print("-" * 40)
                
                for i, endpoint in enumerate(endpoints, 1):
                    print(f"\n{i}. {endpoint.method} {endpoint.full_url}")
                    print(f"   Path: {endpoint.path}")
                    
                    if endpoint.description:
                        print(f"   Name: {endpoint.description}")
                    
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
                    
                    if endpoint.request_body:
                        print(f"   Request Body: {endpoint.request_body}")
                    
                    if endpoint.request_body_schema:
                        print(f"   Request Schema: {json.dumps(endpoint.request_body_schema, indent=6)}")
                    
                    if endpoint.response_body:
                        print(f"   Response Body: {endpoint.response_body}")
                    
                    if endpoint.pre_request_script:
                        print(f"   Pre-request Script: {len(endpoint.pre_request_script)} lines")
                    
                    if endpoint.test_script:
                        print(f"   Test Script: {len(endpoint.test_script)} lines")
                    
                    print("-" * 60)
            else:
                print("\nNo API endpoints found in this Postman collection.")
                print("This might be because:")
                print("- The file is not a valid Postman collection")
                print("- The collection doesn't contain any requests")
                print("- The file structure is different from expected Postman format")
            
            # Show collection info
            collection_info = parser.get_collection_info()
            if collection_info:
                print(f"\n{'='*60}")
                print("Collection Information:")
                print(f"{'='*60}")
                for key, value in collection_info.items():
                    print(f"{key}: {value}")
            
            # Show variables
            variables = parser.get_variables()
            if variables:
                print(f"\n{'='*60}")
                print("Collection Variables:")
                print(f"{'='*60}")
                for key, value in variables.items():
                    print(f"{key}: {value}")
            
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
            print(f"Error parsing Postman collection: {e}")
    
    main() 