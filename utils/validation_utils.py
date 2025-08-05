import json
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse


def validate_har_file(har_data: Dict[str, Any]) -> bool:
    """
    Validate that the provided data is a valid HAR file structure.
    
    Args:
        har_data: The HAR data to validate
        
    Returns:
        True if the data is a valid HAR file, False otherwise
    """
    try:
        # Check if it has the required top-level structure
        if not isinstance(har_data, dict):
            return False
        
        if 'log' not in har_data:
            return False
        
        log = har_data['log']
        if not isinstance(log, dict):
            return False
        
        # Check for required log properties
        required_props = ['version', 'entries']
        for prop in required_props:
            if prop not in log:
                return False
        
        # Validate version
        version = log['version']
        if not isinstance(version, str):
            return False
        
        # Validate entries
        entries = log['entries']
        if not isinstance(entries, list):
            return False
        
        # Validate each entry
        for entry in entries:
            if not validate_har_entry(entry):
                return False
        
        return True
        
    except Exception:
        return False


def validate_har_entry(entry: Dict[str, Any]) -> bool:
    """
    Validate a single HAR entry.
    
    Args:
        entry: The HAR entry to validate
        
    Returns:
        True if the entry is valid, False otherwise
    """
    try:
        if not isinstance(entry, dict):
            return False
        
        # Check for required properties
        required_props = ['request']
        for prop in required_props:
            if prop not in entry:
                return False
        
        # Validate request
        request = entry['request']
        if not isinstance(request, dict):
            return False
        
        if not validate_har_request(request):
            return False
        
        # Validate response if present
        if 'response' in entry:
            response = entry['response']
            if not isinstance(response, dict):
                return False
            
            if not validate_har_response(response):
                return False
        
        return True
        
    except Exception:
        return False


def validate_har_request(request: Dict[str, Any]) -> bool:
    """
    Validate a HAR request object.
    
    Args:
        request: The HAR request to validate
        
    Returns:
        True if the request is valid, False otherwise
    """
    try:
        if not isinstance(request, dict):
            return False
        
        # Check for required properties
        required_props = ['method', 'url']
        for prop in required_props:
            if prop not in request:
                return False
        
        # Validate method
        method = request['method']
        if not isinstance(method, str) or not method.strip():
            return False
        
        # Validate URL
        url = request['url']
        if not isinstance(url, str) or not url.strip():
            return False
        
        # Validate headers if present
        if 'headers' in request:
            headers = request['headers']
            if not isinstance(headers, list):
                return False
            
            for header in headers:
                if not validate_har_header(header):
                    return False
        
        # Validate queryString if present
        if 'queryString' in request:
            query_string = request['queryString']
            if not isinstance(query_string, list):
                return False
            
            for param in query_string:
                if not validate_har_query_param(param):
                    return False
        
        return True
        
    except Exception:
        return False


def validate_har_response(response: Dict[str, Any]) -> bool:
    """
    Validate a HAR response object.
    
    Args:
        response: The HAR response to validate
        
    Returns:
        True if the response is valid, False otherwise
    """
    try:
        if not isinstance(response, dict):
            return False
        
        # Check for required properties
        required_props = ['status']
        for prop in required_props:
            if prop not in response:
                return False
        
        # Validate status
        status = response['status']
        if not isinstance(status, int):
            return False
        
        # Validate headers if present
        if 'headers' in response:
            headers = response['headers']
            if not isinstance(headers, list):
                return False
            
            for header in headers:
                if not validate_har_header(header):
                    return False
        
        return True
        
    except Exception:
        return False


def validate_har_header(header: Dict[str, Any]) -> bool:
    """
    Validate a HAR header object.
    
    Args:
        header: The HAR header to validate
        
    Returns:
        True if the header is valid, False otherwise
    """
    try:
        if not isinstance(header, dict):
            return False
        
        # Check for required properties
        required_props = ['name', 'value']
        for prop in required_props:
            if prop not in header:
                return False
        
        # Validate name and value
        name = header['name']
        value = header['value']
        
        if not isinstance(name, str) or not isinstance(value, str):
            return False
        
        return True
        
    except Exception:
        return False


def validate_har_query_param(param: Dict[str, Any]) -> bool:
    """
    Validate a HAR query parameter object.
    
    Args:
        param: The HAR query parameter to validate
        
    Returns:
        True if the parameter is valid, False otherwise
    """
    try:
        if not isinstance(param, dict):
            return False
        
        # Check for required properties
        required_props = ['name', 'value']
        for prop in required_props:
            if prop not in param:
                return False
        
        # Validate name and value
        name = param['name']
        value = param['value']
        
        if not isinstance(name, str) or not isinstance(value, str):
            return False
        
        return True
        
    except Exception:
        return False


def validate_json_content(content: str) -> bool:
    """
    Validate that a string contains valid JSON.
    
    Args:
        content: The string to validate
        
    Returns:
        True if the content is valid JSON, False otherwise
    """
    try:
        if not isinstance(content, str):
            return False
        
        json.loads(content)
        return True
        
    except (json.JSONDecodeError, TypeError):
        return False


def validate_url(url: str) -> bool:
    """
    Validate that a string is a valid URL.
    
    Args:
        url: The URL string to validate
        
    Returns:
        True if the URL is valid, False otherwise
    """
    try:
        if not isinstance(url, str) or not url.strip():
            return False
        
        parsed = urlparse(url)
        
        # Check for required components
        if not parsed.scheme or not parsed.netloc:
            return False
        
        # Validate scheme
        valid_schemes = ['http', 'https', 'ftp', 'ftps', 'ws', 'wss']
        if parsed.scheme.lower() not in valid_schemes:
            return False
        
        return True
        
    except Exception:
        return False


def is_valid_json(data: Any) -> bool:
    """
    Check if data can be serialized to JSON.
    
    Args:
        data: The data to check
        
    Returns:
        True if the data can be serialized to JSON, False otherwise
    """
    try:
        json.dumps(data)
        return True
    except (TypeError, ValueError):
        return False


def is_valid_xml(content: str) -> bool:
    """
    Basic validation for XML content.
    
    Args:
        content: The XML content to validate
        
    Returns:
        True if the content appears to be valid XML, False otherwise
    """
    try:
        if not isinstance(content, str):
            return False
        
        # Basic XML structure check
        content = content.strip()
        
        # Must start with < and end with >
        if not content.startswith('<') or not content.endswith('>'):
            return False
        
        # Must have at least one tag
        if '<' not in content[1:] or '>' not in content[:-1]:
            return False
        
        # Check for balanced tags (basic check)
        open_tags = content.count('<')
        close_tags = content.count('>')
        
        if open_tags != close_tags:
            return False
        
        return True
        
    except Exception:
        return False


def validate_content_type(content_type: str) -> bool:
    """
    Validate a content type string.
    
    Args:
        content_type: The content type to validate
        
    Returns:
        True if the content type is valid, False otherwise
    """
    try:
        if not isinstance(content_type, str):
            return False
        
        # Basic content type pattern
        pattern = r'^[a-zA-Z0-9!#$&\-\^_]*/[a-zA-Z0-9!#$&\-\^_]*(\+[a-zA-Z0-9!#$&\-\^_]*)?(;\s*[a-zA-Z0-9!#$&\-\^_]*=[a-zA-Z0-9!#$&\-\^_]*)*$'
        
        return bool(re.match(pattern, content_type))
        
    except Exception:
        return False


def validate_http_method(method: str) -> bool:
    """
    Validate an HTTP method.
    
    Args:
        method: The HTTP method to validate
        
    Returns:
        True if the method is valid, False otherwise
    """
    try:
        if not isinstance(method, str):
            return False
        
        valid_methods = [
            'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'
        ]
        
        return method.upper() in valid_methods
        
    except Exception:
        return False


def validate_status_code(status_code: int) -> bool:
    """
    Validate an HTTP status code.
    
    Args:
        status_code: The status code to validate
        
    Returns:
        True if the status code is valid, False otherwise
    """
    try:
        if not isinstance(status_code, int):
            return False
        
        return 100 <= status_code <= 599
        
    except Exception:
        return False


def sanitize_har_data(har_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize HAR data by removing sensitive information.
    
    Args:
        har_data: The HAR data to sanitize
        
    Returns:
        The sanitized HAR data
    """
    try:
        # Create a deep copy to avoid modifying the original
        sanitized = json.loads(json.dumps(har_data))
        
        # Define sensitive header names
        sensitive_headers = [
            'authorization', 'cookie', 'x-api-key', 'x-auth-token',
            'x-access-token', 'x-secret', 'x-password'
        ]
        
        # Define sensitive parameter names
        sensitive_params = [
            'password', 'token', 'key', 'secret', 'auth', 'authorization',
            'api_key', 'apikey', 'access_token', 'refresh_token'
        ]
        
        # Sanitize entries
        if 'log' in sanitized and 'entries' in sanitized['log']:
            for entry in sanitized['log']['entries']:
                # Sanitize request headers
                if 'request' in entry and 'headers' in entry['request']:
                    for header in entry['request']['headers']:
                        if header.get('name', '').lower() in sensitive_headers:
                            header['value'] = '***'
                
                # Sanitize query parameters
                if 'request' in entry and 'queryString' in entry['request']:
                    for param in entry['request']['queryString']:
                        if param.get('name', '').lower() in sensitive_params:
                            param['value'] = '***'
                
                # Sanitize response headers
                if 'response' in entry and 'headers' in entry['response']:
                    for header in entry['response']['headers']:
                        if header.get('name', '').lower() in sensitive_headers:
                            header['value'] = '***'
        
        return sanitized
        
    except Exception:
        return har_data 