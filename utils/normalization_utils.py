import json
import re
from typing import Dict, Any, List, Optional, Union
from collections import defaultdict


def normalize_json_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a JSON schema to a standard format.
    
    Args:
        schema: The JSON schema to normalize
        
    Returns:
        The normalized JSON schema
    """
    try:
        if not isinstance(schema, dict):
            return {}
        
        normalized = {
            'type': schema.get('type', 'object'),
            'properties': {},
            'required': schema.get('required', []),
            'description': schema.get('description', ''),
            'examples': schema.get('examples', [])
        }
        
        # Normalize properties
        properties = schema.get('properties', {})
        if isinstance(properties, dict):
            for prop_name, prop_schema in properties.items():
                normalized['properties'][prop_name] = normalize_property_schema(prop_schema)
        
        return normalized
        
    except Exception:
        return {}


def normalize_property_schema(prop_schema: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a property schema.
    
    Args:
        prop_schema: The property schema to normalize
        
    Returns:
        The normalized property schema
    """
    try:
        if not isinstance(prop_schema, dict):
            return {}
        
        normalized = {
            'type': prop_schema.get('type', 'string'),
            'description': prop_schema.get('description', ''),
            'required': prop_schema.get('required', False),
            'default': prop_schema.get('default'),
            'examples': prop_schema.get('examples', [])
        }
        
        # Handle different types
        prop_type = prop_schema.get('type', 'string')
        
        if prop_type == 'string':
            normalized.update({
                'minLength': prop_schema.get('minLength'),
                'maxLength': prop_schema.get('maxLength'),
                'pattern': prop_schema.get('pattern'),
                'format': prop_schema.get('format')
            })
        elif prop_type in ['integer', 'number']:
            normalized.update({
                'minimum': prop_schema.get('minimum'),
                'maximum': prop_schema.get('maximum'),
                'exclusiveMinimum': prop_schema.get('exclusiveMinimum'),
                'exclusiveMaximum': prop_schema.get('exclusiveMaximum')
            })
        elif prop_type == 'array':
            normalized['items'] = normalize_property_schema(prop_schema.get('items', {}))
            normalized['minItems'] = prop_schema.get('minItems')
            normalized['maxItems'] = prop_schema.get('maxItems')
        elif prop_type == 'object':
            normalized['properties'] = {}
            properties = prop_schema.get('properties', {})
            if isinstance(properties, dict):
                for prop_name, sub_schema in properties.items():
                    normalized['properties'][prop_name] = normalize_property_schema(sub_schema)
        
        return normalized
        
    except Exception:
        return {}


def infer_parameter_types(data: Any) -> Dict[str, str]:
    """
    Infer parameter types from data.
    
    Args:
        data: The data to analyze
        
    Returns:
        Dictionary mapping parameter names to inferred types
    """
    try:
        if isinstance(data, dict):
            return {key: _infer_type_from_value(value) for key, value in data.items()}
        elif isinstance(data, list) and data:
            # For lists, infer from the first item
            if isinstance(data[0], dict):
                return infer_parameter_types(data[0])
        return {}
        
    except Exception:
        return {}


def _infer_type_from_value(value: Any) -> str:
    """
    Infer the type of a single value.
    
    Args:
        value: The value to analyze
        
    Returns:
        The inferred type as a string
    """
    if value is None:
        return 'null'
    elif isinstance(value, bool):
        return 'boolean'
    elif isinstance(value, int):
        return 'integer'
    elif isinstance(value, float):
        return 'number'
    elif isinstance(value, str):
        # Try to infer more specific types from string values
        if value.lower() in ['true', 'false']:
            return 'boolean'
        elif value.isdigit():
            return 'integer'
        elif _is_numeric_string(value):
            return 'number'
        elif _is_date_string(value):
            return 'date'
        elif _is_email_string(value):
            return 'email'
        elif _is_url_string(value):
            return 'url'
        else:
            return 'string'
    elif isinstance(value, list):
        return 'array'
    elif isinstance(value, dict):
        return 'object'
    else:
        return 'unknown'


def _is_numeric_string(value: str) -> bool:
    """Check if a string represents a numeric value."""
    try:
        float(value)
        return True
    except ValueError:
        return False


def _is_date_string(value: str) -> bool:
    """Check if a string represents a date."""
    date_patterns = [
        r'^\d{4}-\d{2}-\d{2}$',
        r'^\d{2}/\d{2}/\d{4}$',
        r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',
        r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'
    ]
    
    for pattern in date_patterns:
        if re.match(pattern, value):
            return True
    return False


def _is_email_string(value: str) -> bool:
    """Check if a string represents an email address."""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, value))


def _is_url_string(value: str) -> bool:
    """Check if a string represents a URL."""
    url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    return bool(re.match(url_pattern, value))


def extract_schema_from_json(json_data: Any) -> Dict[str, Any]:
    """
    Extract a JSON schema from JSON data.
    
    Args:
        json_data: The JSON data to analyze
        
    Returns:
        A JSON schema representing the data structure
    """
    try:
        if json_data is None:
            return {'type': 'null'}
        
        if isinstance(json_data, bool):
            return {'type': 'boolean'}
        
        if isinstance(json_data, int):
            return {'type': 'integer'}
        
        if isinstance(json_data, float):
            return {'type': 'number'}
        
        if isinstance(json_data, str):
            return {'type': 'string'}
        
        if isinstance(json_data, list):
            if not json_data:
                return {'type': 'array', 'items': {}}
            
            # Analyze all items to find common schema
            item_schemas = [extract_schema_from_json(item) for item in json_data]
            common_schema = _merge_schemas(item_schemas)
            
            return {
                'type': 'array',
                'items': common_schema
            }
        
        if isinstance(json_data, dict):
            properties = {}
            required = []
            
            for key, value in json_data.items():
                properties[key] = extract_schema_from_json(value)
                # Consider all properties as required for now
                required.append(key)
            
            return {
                'type': 'object',
                'properties': properties,
                'required': required
            }
        
        return {'type': 'unknown'}
        
    except Exception:
        return {'type': 'unknown'}


def _merge_schemas(schemas: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Merge multiple schemas into a common schema.
    
    Args:
        schemas: List of schemas to merge
        
    Returns:
        The merged schema
    """
    if not schemas:
        return {}
    
    if len(schemas) == 1:
        return schemas[0]
    
    # Find common type
    types = [schema.get('type', 'unknown') for schema in schemas]
    common_type = types[0] if all(t == types[0] for t in types) else 'mixed'
    
    if common_type == 'object':
        # Merge object properties
        all_properties = {}
        all_required = set()
        
        for schema in schemas:
            properties = schema.get('properties', {})
            required = schema.get('required', [])
            
            for prop_name, prop_schema in properties.items():
                if prop_name in all_properties:
                    # Merge property schemas
                    all_properties[prop_name] = _merge_schemas([
                        all_properties[prop_name], prop_schema
                    ])
                else:
                    all_properties[prop_name] = prop_schema
            
            all_required.update(required)
        
        return {
            'type': 'object',
            'properties': all_properties,
            'required': list(all_required)
        }
    
    elif common_type == 'array':
        # Merge array item schemas
        item_schemas = [schema.get('items', {}) for schema in schemas]
        merged_items = _merge_schemas(item_schemas)
        
        return {
            'type': 'array',
            'items': merged_items
        }
    
    else:
        # For primitive types, return the first schema
        return schemas[0]


def merge_schemas(schema1: Dict[str, Any], schema2: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge two JSON schemas.
    
    Args:
        schema1: First schema
        schema2: Second schema
        
    Returns:
        The merged schema
    """
    return _merge_schemas([schema1, schema2])


def deduplicate_endpoints(endpoints: List[Any]) -> List[Any]:
    """
    Remove duplicate endpoints based on method and path.
    
    Args:
        endpoints: List of endpoints to deduplicate
        
    Returns:
        List of unique endpoints
    """
    try:
        seen = set()
        unique_endpoints = []
        
        for endpoint in endpoints:
            # Create a unique key based on method and path
            key = f"{endpoint.method}:{endpoint.path}"
            
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(endpoint)
        
        return unique_endpoints
        
    except Exception:
        return endpoints


def normalize_content_type(content_type: str) -> str:
    """
    Normalize a content type string.
    
    Args:
        content_type: The content type to normalize
        
    Returns:
        The normalized content type
    """
    try:
        if not content_type:
            return 'application/octet-stream'
        
        # Remove parameters and normalize
        base_type = content_type.split(';')[0].strip().lower()
        
        # Common normalizations
        normalizations = {
            'text/json': 'application/json',
            'application/x-javascript': 'application/javascript',
            'text/xml': 'application/xml',
            'text/plain': 'text/plain',
            'text/html': 'text/html',
            'application/x-www-form-urlencoded': 'application/x-www-form-urlencoded',
            'multipart/form-data': 'multipart/form-data'
        }
        
        return normalizations.get(base_type, base_type)
        
    except Exception:
        return 'application/octet-stream'


def extract_common_patterns(endpoints: List[Any]) -> Dict[str, List[str]]:
    """
    Extract common patterns from a list of endpoints.
    
    Args:
        endpoints: List of endpoints to analyze
        
    Returns:
        Dictionary of pattern categories and their values
    """
    try:
        patterns = {
            'base_urls': set(),
            'path_prefixes': set(),
            'http_methods': set(),
            'content_types': set(),
            'auth_types': set()
        }
        
        for endpoint in endpoints:
            # Extract base URL
            if hasattr(endpoint, 'base_url'):
                patterns['base_urls'].add(endpoint.base_url)
            
            # Extract path prefix
            if hasattr(endpoint, 'path'):
                path_parts = endpoint.path.split('/')
                if len(path_parts) > 1:
                    prefix = '/'.join(path_parts[:2])  # First two segments
                    patterns['path_prefixes'].add(prefix)
            
            # Extract HTTP method
            if hasattr(endpoint, 'method'):
                patterns['http_methods'].add(endpoint.method)
            
            # Extract content type
            if hasattr(endpoint, 'content_type') and endpoint.content_type:
                patterns['content_types'].add(endpoint.content_type)
            
            # Extract auth type
            if hasattr(endpoint, 'auth_info') and endpoint.auth_info:
                patterns['auth_types'].add(endpoint.auth_info.auth_type.value)
        
        # Convert sets to lists
        return {key: list(value) for key, value in patterns.items()}
        
    except Exception:
        return {}


def standardize_parameter_names(param_names: List[str]) -> List[str]:
    """
    Standardize parameter names to common conventions.
    
    Args:
        param_names: List of parameter names to standardize
        
    Returns:
        List of standardized parameter names
    """
    try:
        standardized = []
        
        for name in param_names:
            # Convert to lowercase
            std_name = name.lower()
            
            # Replace common separators with underscores
            std_name = re.sub(r'[-\s]+', '_', std_name)
            
            # Remove special characters
            std_name = re.sub(r'[^a-z0-9_]', '', std_name)
            
            # Remove leading/trailing underscores
            std_name = std_name.strip('_')
            
            if std_name:
                standardized.append(std_name)
        
        return list(set(standardized))  # Remove duplicates
        
    except Exception:
        return param_names 