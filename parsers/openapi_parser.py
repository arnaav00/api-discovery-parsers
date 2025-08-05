import json
import yaml
from typing import List, Dict, Any, Optional, Union
from urllib.parse import urljoin, urlparse
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


class OpenAPIParser(BaseParser):
    """
    Parser for OpenAPI/Swagger specification files.
    
    This parser extracts API endpoints, parameters, schemas, and authentication
    information from OpenAPI specifications. It supports OpenAPI 2.0, 3.0, and 3.1.
    """
    
    def __init__(self):
        """Initialize the OpenAPI parser."""
        super().__init__()
        self.spec_version = None
        self.info = {}
        self.servers = []
        self.components = {}
        self.security_schemes = {}
        self.paths = {}
        self.base_url = None
        self.spec_data = None
        
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
                # Try to parse as JSON or YAML
                try:
                    spec_data = json.loads(data)
                except json.JSONDecodeError:
                    try:
                        spec_data = yaml.safe_load(data)
                    except yaml.YAMLError:
                        return False
                return self._validate_openapi_spec(spec_data)
            elif isinstance(data, dict):
                return self._validate_openapi_spec(data)
            else:
                return False
        except Exception:
            return False
    
    def parse(self, data: Any) -> List[APIEndpoint]:
        """
        Parse OpenAPI specification and extract API endpoints.
        
        Args:
            data: OpenAPI specification as string, dict, or file path
            
        Returns:
            List of discovered API endpoints
            
        Raises:
            ValueError: If the data is invalid or cannot be parsed
        """
        self.clear_results()
        
        try:
            # Parse input data
            self.spec_data = self._parse_input(data)
            
            # Validate OpenAPI structure
            if not self._validate_openapi_spec(self.spec_data):
                raise ValueError("Invalid OpenAPI specification structure")
            
            # Extract specification metadata
            self._extract_metadata()
            
            # Extract components and security schemes
            self._extract_components()
            
            # Process paths and extract endpoints
            self._process_paths()
            
            # Update final statistics
            self._update_final_stats()
            
            return self.parsed_endpoints
            
        except Exception as e:
            self.add_error(f"Failed to parse OpenAPI specification: {str(e)}")
            raise ValueError(f"OpenAPI parsing failed: {str(e)}")
    
    def _parse_input(self, data: Any) -> Dict[str, Any]:
        """
        Parse input data into OpenAPI format.
        
        Args:
            data: Input data (string, dict, or file path)
            
        Returns:
            Parsed OpenAPI data as dictionary
        """
        if isinstance(data, dict):
            return data
        elif isinstance(data, str):
            # Check if it's a file path
            if data.endswith(('.json', '.yaml', '.yml')):
                try:
                    with open(data, 'r', encoding='utf-8') as f:
                        content = f.read()
                except FileNotFoundError:
                    # Treat as JSON/YAML string
                    content = data
            else:
                content = data
            
            # Try to parse as JSON first
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                # Try to parse as YAML
                try:
                    return yaml.safe_load(content)
                except yaml.YAMLError as e:
                    raise ValueError(f"Failed to parse as JSON or YAML: {str(e)}")
        else:
            raise ValueError(f"Unsupported data type: {type(data)}")
    
    def _validate_openapi_spec(self, spec_data: Dict[str, Any]) -> bool:
        """
        Validate OpenAPI specification structure.
        
        Args:
            spec_data: The OpenAPI specification data
            
        Returns:
            True if valid, False otherwise
        """
        if not isinstance(spec_data, dict):
            return False
        
        # Check for required fields
        if 'paths' not in spec_data:
            return False
        
        # Check for OpenAPI version indicators
        version_fields = ['swagger', 'openapi']
        has_version = any(field in spec_data for field in version_fields)
        
        if not has_version:
            return False
        
        return True
    
    def _extract_metadata(self):
        """Extract metadata from OpenAPI specification."""
        self.spec_data = self.spec_data or {}
        
        # Determine version
        if 'swagger' in self.spec_data:
            self.spec_version = f"2.0 ({self.spec_data['swagger']})"
        elif 'openapi' in self.spec_data:
            self.spec_version = f"3.x ({self.spec_data['openapi']})"
        
        # Extract info
        self.info = self.spec_data.get('info', {})
        
        # Extract servers (OpenAPI 3.x)
        self.servers = self.spec_data.get('servers', [])
        
        # Extract base URL
        if self.servers:
            self.base_url = self.servers[0].get('url', '')
        elif 'host' in self.spec_data:  # OpenAPI 2.0
            scheme = self.spec_data.get('schemes', ['https'])[0]
            host = self.spec_data.get('host', '')
            base_path = self.spec_data.get('basePath', '')
            self.base_url = f"{scheme}://{host}{base_path}"
        
        # Update statistics
        self.update_stats('spec_version', self.spec_version)
        self.update_stats('title', self.info.get('title', 'Unknown'))
        self.update_stats('version', self.info.get('version', 'Unknown'))
        self.update_stats('servers_count', len(self.servers))
        self.update_stats('base_url', self.base_url)
    
    def _extract_components(self):
        """Extract components and security schemes."""
        # Extract components (OpenAPI 3.x)
        self.components = self.spec_data.get('components', {})
        
        # Extract security schemes
        if 'securityDefinitions' in self.spec_data:  # OpenAPI 2.0
            self.security_schemes = self.spec_data['securityDefinitions']
        elif 'components' in self.spec_data and 'securitySchemes' in self.spec_data['components']:
            self.security_schemes = self.spec_data['components']['securitySchemes']
        
        self.update_stats('security_schemes_count', len(self.security_schemes))
        self.update_stats('components_count', len(self.components))
    
    def _process_paths(self):
        """Process all paths and extract endpoints."""
        paths = self.spec_data.get('paths', {})
        self.paths = paths
        
        for path, path_item in paths.items():
            self._process_path(path, path_item)
        
        self.update_stats('total_paths', len(paths))
    
    def _process_path(self, path: str, path_item: Dict[str, Any]):
        """
        Process a single path and extract all endpoints.
        
        Args:
            path: The path string
            path_item: The path item object
        """
        # Get global security for this path
        path_security = path_item.get('security', [])
        
        # Process each HTTP method
        for method, operation in path_item.items():
            if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']:
                self._process_operation(method.upper(), path, operation, path_security)
    
    def _process_operation(self, method: str, path: str, operation: Dict[str, Any], path_security: List[Dict[str, Any]]):
        """
        Process a single operation and create an endpoint.
        
        Args:
            method: HTTP method
            path: API path
            operation: Operation object
            path_security: Security requirements for the path
        """
        # Create endpoint
        endpoint = self._create_endpoint(method, path, operation)
        
        # Process parameters
        self._process_parameters(endpoint, operation)
        
        # Process request body
        self._process_request_body(endpoint, operation)
        
        # Process responses
        self._process_responses(endpoint, operation)
        
        # Process security
        self._process_security(endpoint, operation, path_security)
        
        # Add the endpoint
        self.add_endpoint(endpoint)
    
    def _create_endpoint(self, method: str, path: str, operation: Dict[str, Any]) -> APIEndpoint:
        """
        Create an APIEndpoint from operation.
        
        Args:
            method: HTTP method
            path: API path
            operation: Operation object
            
        Returns:
            The created APIEndpoint
        """
        # Build full URL
        full_url = urljoin(self.base_url or 'http://localhost', path)
        
        # Extract URL components
        parsed_url = urlparse(full_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Create endpoint
        endpoint = APIEndpoint(
            method=method,
            path=path,
            full_url=full_url,
            base_url=base_url,
            timestamp=datetime.now().isoformat(),
            har_entry_index=len(self.parsed_endpoints)
        )
        
        # Set operation metadata
        endpoint.content_type = 'application/json'  # Default for OpenAPI
        
        return endpoint
    
    def _process_parameters(self, endpoint: APIEndpoint, operation: Dict[str, Any]):
        """
        Process operation parameters.
        
        Args:
            endpoint: The API endpoint to update
            operation: The operation object
        """
        parameters = operation.get('parameters', [])
        
        for param_data in parameters:
            # Handle Swagger 2.0 body parameters
            if param_data.get('in') == 'body':
                # This is a request body parameter, process it separately
                self._process_swagger_body_parameter(endpoint, param_data)
            else:
                param = self._create_parameter(param_data)
                if param:
                    endpoint.add_parameter(param)
    
    def _create_parameter(self, param_data: Dict[str, Any]) -> Optional[Parameter]:
        """
        Create a Parameter from parameter data.
        
        Args:
            param_data: Parameter data from OpenAPI spec
            
        Returns:
            The created Parameter or None if invalid
        """
        name = param_data.get('name', '')
        location = param_data.get('in', 'query')
        
        if not name:
            return None
        
        # Map OpenAPI location to our enum
        location_map = {
            'query': ParameterLocation.QUERY,
            'path': ParameterLocation.PATH,
            'header': ParameterLocation.HEADER,
            'cookie': ParameterLocation.COOKIE
        }
        
        param_location = location_map.get(location, ParameterLocation.QUERY)
        
        # Determine parameter type
        param_type = self._infer_parameter_type(param_data)
        
        # Create parameter
        param = Parameter(
            name=name,
            location=param_location,
            value=param_data.get('default'),
            param_type=param_type,
            required=param_data.get('required', False),
            description=param_data.get('description')
        )
        
        # Add schema information
        if 'schema' in param_data:
            param.schema = self._resolve_schema(param_data['schema'])
        
        # Add examples
        if 'example' in param_data:
            param.examples.append(param_data['example'])
        
        return param
    
    def _process_swagger_body_parameter(self, endpoint: APIEndpoint, param_data: Dict[str, Any]):
        """
        Process Swagger 2.0 body parameters.
        
        Args:
            endpoint: The API endpoint to update
            param_data: Body parameter data
        """
        if 'schema' in param_data:
            schema = self._resolve_schema(param_data['schema'])
            endpoint.request_body_schema = schema
            
            # Set content type for Swagger 2.0
            endpoint.content_type = 'application/json'
    
    def _infer_parameter_type(self, param_data: Dict[str, Any]) -> ParameterType:
        """
        Infer parameter type from OpenAPI parameter data.
        
        Args:
            param_data: Parameter data
            
        Returns:
            Inferred parameter type
        """
        # Check schema first
        if 'schema' in param_data:
            schema = param_data['schema']
            if isinstance(schema, dict):
                param_type = schema.get('type', 'string')
                return self._map_openapi_type_to_parameter_type(param_type)
        
        # Check type field (OpenAPI 2.0)
        if 'type' in param_data:
            param_type = param_data['type']
            return self._map_openapi_type_to_parameter_type(param_type)
        
        # Default to string
        return ParameterType.STRING
    
    def _map_openapi_type_to_parameter_type(self, openapi_type: str) -> ParameterType:
        """
        Map OpenAPI type to our ParameterType enum.
        
        Args:
            openapi_type: OpenAPI type string
            
        Returns:
            Mapped ParameterType
        """
        type_mapping = {
            'string': ParameterType.STRING,
            'integer': ParameterType.INTEGER,
            'number': ParameterType.NUMBER,
            'boolean': ParameterType.BOOLEAN,
            'array': ParameterType.ARRAY,
            'object': ParameterType.OBJECT,
            'file': ParameterType.FILE
        }
        
        return type_mapping.get(openapi_type, ParameterType.STRING)
    
    def _process_request_body(self, endpoint: APIEndpoint, operation: Dict[str, Any]):
        """
        Process request body.
        
        Args:
            endpoint: The API endpoint to update
            operation: The operation object
        """
        request_body = operation.get('requestBody')
        if not request_body:
            return
        
        # Process content types
        content = request_body.get('content', {})
        
        for content_type, content_data in content.items():
            if 'schema' in content_data:
                schema = self._resolve_schema(content_data['schema'])
                endpoint.request_body_schema = schema
                
                # Extract example
                if 'example' in content_data:
                    endpoint.request_body = content_data['example']
                elif 'examples' in content_data:
                    # Use first example
                    examples = content_data['examples']
                    if examples:
                        first_example = list(examples.values())[0]
                        if 'value' in first_example:
                            endpoint.request_body = first_example['value']
                
                endpoint.content_type = normalize_content_type(content_type)
                break
    
    def _process_responses(self, endpoint: APIEndpoint, operation: Dict[str, Any]):
        """
        Process operation responses.
        
        Args:
            endpoint: The API endpoint to update
            operation: The operation object
        """
        responses = operation.get('responses', {})
        
        # Find the first successful response (2xx)
        for status_code, response_data in responses.items():
            if status_code.startswith('2'):
                endpoint.response_status = int(status_code)
                
                # Handle OpenAPI 3.x content structure
                if 'content' in response_data:
                    content = response_data.get('content', {})
                    
                    for content_type, content_data in content.items():
                        if 'schema' in content_data:
                            schema = self._resolve_schema(content_data['schema'])
                            endpoint.response_body_schema = schema
                            
                            # Extract example
                            if 'example' in content_data:
                                endpoint.response_body = content_data['example']
                            elif 'examples' in content_data:
                                examples = content_data['examples']
                                if examples:
                                    first_example = list(examples.values())[0]
                                    if 'value' in first_example:
                                        endpoint.response_body = first_example['value']
                            
                            endpoint.content_type = normalize_content_type(content_type)
                            break
                
                # Handle Swagger 2.0 direct schema structure
                elif 'schema' in response_data:
                    schema = self._resolve_schema(response_data['schema'])
                    endpoint.response_body_schema = schema
                    endpoint.content_type = 'application/json'
                
                break
    
    def _process_security(self, endpoint: APIEndpoint, operation: Dict[str, Any], path_security: List[Dict[str, Any]]):
        """
        Process security requirements.
        
        Args:
            endpoint: The API endpoint to update
            operation: The operation object
            path_security: Security requirements for the path
        """
        # Use operation security if available, otherwise use path security
        security = operation.get('security', path_security)
        
        if not security:
            return
        
        # Process first security requirement
        if security and isinstance(security, list) and len(security) > 0:
            security_req = security[0]
            
            for scheme_name, scopes in security_req.items():
                if scheme_name in self.security_schemes:
                    auth_info = self._create_auth_info(scheme_name, self.security_schemes[scheme_name], scopes)
                    if auth_info:
                        endpoint.auth_info = auth_info
                        break
    
    def _create_auth_info(self, scheme_name: str, scheme_data: Dict[str, Any], scopes: List[str]) -> Optional[AuthInfo]:
        """
        Create AuthInfo from security scheme.
        
        Args:
            scheme_name: Name of the security scheme
            scheme_data: Security scheme data
            scopes: Required scopes
            
        Returns:
            The created AuthInfo or None
        """
        auth_info = AuthInfo()
        
        scheme_type = scheme_data.get('type', '')
        
        if scheme_type == 'http':
            auth_scheme = scheme_data.get('scheme', '')
            if auth_scheme == 'bearer':
                auth_info.auth_type = AuthType.BEARER
                auth_info.location = AuthLocation.HEADER
            elif auth_scheme == 'basic':
                auth_info.auth_type = AuthType.BASIC
                auth_info.location = AuthLocation.HEADER
        elif scheme_type == 'apiKey':
            auth_info.auth_type = AuthType.API_KEY
            auth_info.location = AuthLocation.HEADER
            auth_info.api_key = scheme_data.get('name', scheme_name)
        elif scheme_type == 'oauth2':
            auth_info.auth_type = AuthType.OAUTH
            auth_info.oauth_version = '2.0'
            auth_info.scope = ', '.join(scopes) if scopes else ''
        else:
            auth_info.auth_type = AuthType.CUSTOM
        
        auth_info.scheme = scheme_name
        auth_info.add_auth_header(scheme_name)
        
        return auth_info
    
    def _resolve_schema(self, schema: Any) -> Dict[str, Any]:
        """
        Resolve schema references and return the actual schema.
        
        Args:
            schema: Schema object or reference
            
        Returns:
            Resolved schema
        """
        if isinstance(schema, dict):
            # Check for $ref
            if '$ref' in schema:
                return self._resolve_reference(schema['$ref'])
            else:
                return schema
        else:
            return {'type': 'string'}
    
    def _resolve_reference(self, ref: str) -> Dict[str, Any]:
        """
        Resolve a $ref reference.
        
        Args:
            ref: Reference string (e.g., '#/components/schemas/User')
            
        Returns:
            Referenced object
        """
        if not ref.startswith('#/'):
            return {}
        
        # Remove leading '#/'
        path = ref[2:].split('/')
        
        # Navigate to the referenced object
        current = self.spec_data
        for part in path:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return {}
        
        return current if isinstance(current, dict) else {}
    
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
    
    def get_spec_version(self) -> Optional[str]:
        """Get the OpenAPI specification version."""
        return self.spec_version
    
    def get_info(self) -> Dict[str, Any]:
        """Get the API information."""
        return self.info.copy()
    
    def get_servers(self) -> List[Dict[str, Any]]:
        """Get the server configurations."""
        return self.servers.copy()
    
    def get_security_schemes(self) -> Dict[str, Any]:
        """Get the security schemes."""
        return self.security_schemes.copy()
    
    def get_components(self) -> Dict[str, Any]:
        """Get the components."""
        return self.components.copy()


if __name__ == "__main__":
    import sys
    import os
    
    def main():
        """Main function to run OpenAPI parser from command line."""
        if len(sys.argv) != 2:
            print("Usage: python openapi_parser.py <path_to_openapi_file>")
            print("\nExamples:")
            print("  python openapi_parser.py ../samples/api-spec.json")
            print("  python openapi_parser.py api-spec.yaml")
            return
        
        openapi_file_path = sys.argv[1]
        
        # Check if file exists
        if not os.path.exists(openapi_file_path):
            print(f"Error: File '{openapi_file_path}' not found.")
            return
        
        # Initialize parser
        parser = OpenAPIParser()
        
        try:
            # Load and parse OpenAPI file
            with open(openapi_file_path, 'r', encoding='utf-8') as f:
                openapi_data = f.read()
            
            # Parse the data
            endpoints = parser.parse(openapi_data)
            
            # Display results
            print(f"\n{'='*60}")
            print(f"OpenAPI Parser Results for: {openapi_file_path}")
            print(f"{'='*60}")
            
            if endpoints:
                print(f"\nFound {len(endpoints)} API endpoint(s):")
                print("-" * 40)
                
                for i, endpoint in enumerate(endpoints, 1):
                    print(f"\n{i}. {endpoint.method} {endpoint.full_url}")
                    print(f"   Path: {endpoint.path}")
                    
                    if endpoint.parameters:
                        print(f"   Parameters ({len(endpoint.parameters)}):")
                        for param in endpoint.parameters:
                            value_display = f" = {param.value}" if param.value else ""
                            print(f"     - {param.name} ({param.param_type.value}) in {param.location.value}{value_display}")
                    
                    if endpoint.auth_info:
                        auth_str = endpoint.auth_info.get_auth_string()
                        print(f"   Authentication: {endpoint.auth_info.auth_type.value}")
                        if auth_str:
                            print(f"     Auth Details: {auth_str}")
                    
                    if endpoint.request_body_schema:
                        print(f"   Request Schema: {json.dumps(endpoint.request_body_schema, indent=6)}")
                    
                    if endpoint.response_body_schema:
                        print(f"   Response Schema: {json.dumps(endpoint.response_body_schema, indent=6)}")
                    
                    print("-" * 60)
            else:
                print("\nNo API endpoints found in this OpenAPI specification.")
                print("This might be because:")
                print("- The file is not a valid OpenAPI specification")
                print("- The specification doesn't contain any paths")
                print("- The file structure is different from expected OpenAPI format")
            
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
            print(f"Error parsing OpenAPI file: {e}")
    
    main() 