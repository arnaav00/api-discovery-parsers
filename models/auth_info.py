from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from enum import Enum


class AuthType(Enum):
    """Enumeration of authentication types."""
    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    DIGEST = "digest"
    OAUTH = "oauth"
    API_KEY = "api_key"
    COOKIE = "cookie"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class AuthLocation(Enum):
    """Enumeration of authentication locations."""
    HEADER = "header"
    QUERY = "query"
    BODY = "body"
    COOKIE = "cookie"
    URL = "url"


@dataclass
class AuthInfo:
    """Represents authentication information extracted from API requests."""
    
    # Basic authentication info
    auth_type: AuthType = AuthType.UNKNOWN
    location: AuthLocation = AuthLocation.HEADER
    
    # Authentication details
    scheme: Optional[str] = None
    token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    
    # Headers and parameters used for auth
    auth_headers: List[str] = field(default_factory=list)
    auth_parameters: List[str] = field(default_factory=list)
    
    # Additional metadata
    realm: Optional[str] = None
    scope: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    
    # OAuth specific
    oauth_version: Optional[str] = None
    oauth_signature_method: Optional[str] = None
    
    # Security information
    is_secure: bool = False
    requires_ssl: bool = False
    
    # Additional properties
    properties: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate and normalize authentication information."""
        if self.auth_type == AuthType.BASIC and not (self.username or self.password):
            # Try to extract from token if present
            if self.token:
                self._extract_basic_auth()
        
        if self.auth_type == AuthType.BEARER and not self.token:
            # Look for bearer token in properties
            if 'authorization' in self.properties:
                auth_value = self.properties['authorization']
                if isinstance(auth_value, str) and auth_value.lower().startswith('bearer '):
                    self.token = auth_value[7:]  # Remove 'Bearer ' prefix
    
    def _extract_basic_auth(self):
        """Extract username and password from basic auth token."""
        if not self.token:
            return
        
        try:
            import base64
            decoded = base64.b64decode(self.token).decode('utf-8')
            if ':' in decoded:
                self.username, self.password = decoded.split(':', 1)
        except Exception:
            # If decoding fails, keep the token as is
            pass
    
    def add_auth_header(self, header_name: str):
        """Add an authentication header name."""
        if header_name not in self.auth_headers:
            self.auth_headers.append(header_name)
    
    def add_auth_parameter(self, param_name: str):
        """Add an authentication parameter name."""
        if param_name not in self.auth_parameters:
            self.auth_parameters.append(param_name)
    
    def set_property(self, key: str, value: Any):
        """Set an additional property."""
        self.properties[key] = value
    
    def get_property(self, key: str, default: Any = None) -> Any:
        """Get an additional property."""
        return self.properties.get(key, default)
    
    def is_oauth(self) -> bool:
        """Check if this is OAuth authentication."""
        return self.auth_type in [AuthType.OAUTH] or 'oauth' in str(self.scheme).lower()
    
    def is_token_based(self) -> bool:
        """Check if this is token-based authentication."""
        return self.auth_type in [AuthType.BEARER, AuthType.OAUTH, AuthType.API_KEY]
    
    def is_credential_based(self) -> bool:
        """Check if this is credential-based authentication."""
        return self.auth_type in [AuthType.BASIC, AuthType.DIGEST]
    
    def requires_credentials(self) -> bool:
        """Check if this authentication requires credentials."""
        return bool(self.username or self.password or self.client_id or self.client_secret)
    
    def get_auth_string(self) -> Optional[str]:
        """Get a string representation of the authentication."""
        if self.auth_type == AuthType.BASIC and self.username:
            return f"Basic {self.username}:***"
        elif self.auth_type == AuthType.BEARER and self.token:
            return f"Bearer {self.token[:10]}..." if len(self.token) > 10 else f"Bearer {self.token}"
        elif self.auth_type == AuthType.API_KEY and self.api_key:
            return f"API Key: {self.api_key[:10]}..." if len(self.api_key) > 10 else f"API Key: {self.api_key}"
        elif self.auth_type == AuthType.OAUTH:
            return f"OAuth {self.oauth_version or '1.0'}"
        else:
            return str(self.auth_type.value)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the authentication info to a dictionary representation."""
        return {
            'auth_type': self.auth_type.value,
            'location': self.location.value,
            'scheme': self.scheme,
            'token': self.token,
            'username': self.username,
            'password': self.password,
            'api_key': self.api_key,
            'auth_headers': self.auth_headers,
            'auth_parameters': self.auth_parameters,
            'realm': self.realm,
            'scope': self.scope,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'oauth_version': self.oauth_version,
            'oauth_signature_method': self.oauth_signature_method,
            'is_secure': self.is_secure,
            'requires_ssl': self.requires_ssl,
            'properties': self.properties,
            'auth_string': self.get_auth_string()
        }
    
    def __str__(self) -> str:
        """String representation of the authentication info."""
        auth_str = self.get_auth_string()
        return f"{self.auth_type.value} ({self.location.value})" + (f": {auth_str}" if auth_str else "")
    
    def __repr__(self) -> str:
        """Detailed string representation of the authentication info."""
        return f"AuthInfo(type={self.auth_type.value}, location={self.location.value})" 