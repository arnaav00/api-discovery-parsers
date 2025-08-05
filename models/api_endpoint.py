from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from .parameter import Parameter
from .header import Header
from .auth_info import AuthInfo
from .ssl_info import SSLInfo


@dataclass
class APIEndpoint:
    """Represents a discovered API endpoint with all its metadata."""
    
    # Basic endpoint information
    method: str
    path: str
    full_url: str
    base_url: str
    
    # Request information
    headers: List[Header] = field(default_factory=list)
    parameters: List[Parameter] = field(default_factory=list)
    request_body: Optional[Dict[str, Any]] = None
    request_body_schema: Optional[Dict[str, Any]] = None
    
    # Response information
    response_status: Optional[int] = None
    response_headers: List[Header] = field(default_factory=list)
    response_body: Optional[Dict[str, Any]] = None
    response_body_schema: Optional[Dict[str, Any]] = None
    
    # Authentication and security
    auth_info: Optional[AuthInfo] = None
    ssl_info: Optional[SSLInfo] = None
    
    # Metadata
    content_type: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: Optional[str] = None
    duration: Optional[float] = None
    
    # HAR-specific information
    har_entry_index: Optional[int] = None
    page_ref: Optional[str] = None
    
    # Inferred information
    inferred_patterns: List[str] = field(default_factory=list)
    parameter_types: Dict[str, str] = field(default_factory=dict)
    
    # Postman-specific information
    description: Optional[str] = None
    pre_request_script: Optional[List[str]] = None
    test_script: Optional[List[str]] = None
    
    def __post_init__(self):
        """Validate and normalize the endpoint data after initialization."""
        if not self.method:
            raise ValueError("HTTP method is required")
        if not self.path:
            raise ValueError("Path is required")
        if not self.full_url:
            raise ValueError("Full URL is required")
        
        # Normalize method to uppercase
        self.method = self.method.upper()
        
        # Ensure path starts with /
        if not self.path.startswith('/'):
            self.path = '/' + self.path
    
    def add_parameter(self, param: Parameter):
        """Add a parameter to the endpoint."""
        self.parameters.append(param)
    
    def add_header(self, header: Header):
        """Add a header to the endpoint."""
        self.headers.append(header)
    
    def add_response_header(self, header: Header):
        """Add a response header to the endpoint."""
        self.response_headers.append(header)
    
    def get_parameter_by_name(self, name: str) -> Optional[Parameter]:
        """Get a parameter by name."""
        for param in self.parameters:
            if param.name == name:
                return param
        return None
    
    def get_header_by_name(self, name: str) -> Optional[Header]:
        """Get a header by name (case-insensitive)."""
        name_lower = name.lower()
        for header in self.headers:
            if header.name.lower() == name_lower:
                return header
        return None
    
    def get_auth_headers(self) -> List[Header]:
        """Get authentication-related headers."""
        auth_headers = []
        auth_header_names = ['authorization', 'x-api-key', 'x-auth-token', 'cookie']
        
        for header in self.headers:
            if header.name.lower() in auth_header_names:
                auth_headers.append(header)
        
        return auth_headers
    
    def has_request_body(self) -> bool:
        """Check if the endpoint has a request body."""
        return self.request_body is not None or (
            self.request_body_schema is not None and len(self.request_body_schema) > 0
        )
    
    def has_response_body(self) -> bool:
        """Check if the endpoint has a response body."""
        return self.response_body is not None or (
            self.response_body_schema is not None and len(self.response_body_schema) > 0
        )
    
    def is_authenticated(self) -> bool:
        """Check if the endpoint requires authentication."""
        return (
            self.auth_info is not None or 
            len(self.get_auth_headers()) > 0 or
            any(param.name.lower() in ['token', 'key', 'auth'] for param in self.parameters)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the endpoint to a dictionary representation."""
        return {
            'method': self.method,
            'path': self.path,
            'full_url': self.full_url,
            'base_url': self.base_url,
            'headers': [h.to_dict() for h in self.headers],
            'parameters': [p.to_dict() for p in self.parameters],
            'request_body': self.request_body,
            'request_body_schema': self.request_body_schema,
            'response_status': self.response_status,
            'response_headers': [h.to_dict() for h in self.response_headers],
            'response_body': self.response_body,
            'response_body_schema': self.response_body_schema,
            'auth_info': self.auth_info.to_dict() if self.auth_info else None,
            'ssl_info': self.ssl_info.to_dict() if self.ssl_info else None,
            'content_type': self.content_type,
            'user_agent': self.user_agent,
            'timestamp': self.timestamp,
            'duration': self.duration,
            'har_entry_index': self.har_entry_index,
            'page_ref': self.page_ref,
            'inferred_patterns': self.inferred_patterns,
            'parameter_types': self.parameter_types,
            'description': self.description,
            'pre_request_script': self.pre_request_script,
            'test_script': self.test_script
        }
    
    def __str__(self) -> str:
        """String representation of the endpoint."""
        return f"{self.method} {self.path}"
    
    def __repr__(self) -> str:
        """Detailed string representation of the endpoint."""
        return f"APIEndpoint(method='{self.method}', path='{self.path}', parameters={len(self.parameters)})" 