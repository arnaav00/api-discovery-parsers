from dataclasses import dataclass
from typing import Optional, Any
from enum import Enum


class HeaderCategory(Enum):
    """Enumeration of header categories."""
    GENERAL = "general"
    REQUEST = "request"
    RESPONSE = "response"
    ENTITY = "entity"
    AUTHENTICATION = "authentication"
    CACHE = "cache"
    SECURITY = "security"
    CORS = "cors"
    CONTENT = "content"
    UNKNOWN = "unknown"


@dataclass
class Header:
    """Represents an HTTP header with metadata and analysis capabilities."""
    
    name: str
    value: str
    
    # Metadata
    category: HeaderCategory = HeaderCategory.UNKNOWN
    description: Optional[str] = None
    is_standard: bool = False
    
    # Analysis flags
    is_sensitive: bool = False
    is_authentication_related: bool = False
    is_security_related: bool = False
    
    def __post_init__(self):
        """Analyze the header after initialization."""
        self._analyze_header()
    
    def _analyze_header(self):
        """Analyze the header to determine its category and properties."""
        name_lower = self.name.lower()
        
        # Determine category
        self.category = self._categorize_header(name_lower)
        
        # Check if it's a standard header
        self.is_standard = self._is_standard_header(name_lower)
        
        # Check if it's sensitive
        self.is_sensitive = self._is_sensitive_header(name_lower)
        
        # Check if it's authentication-related
        self.is_authentication_related = self._is_auth_header(name_lower)
        
        # Check if it's security-related
        self.is_security_related = self._is_security_header(name_lower)
    
    def _categorize_header(self, name: str) -> HeaderCategory:
        """Categorize the header based on its name."""
        # General headers
        general_headers = {
            'connection', 'date', 'trailer', 'transfer-encoding', 'upgrade', 'via', 'warning'
        }
        
        # Request headers
        request_headers = {
            'accept', 'accept-charset', 'accept-encoding', 'accept-language',
            'authorization', 'expect', 'from', 'host', 'if-match', 'if-modified-since',
            'if-none-match', 'if-range', 'if-unmodified-since', 'max-forwards',
            'proxy-authorization', 'range', 'referer', 'te', 'user-agent'
        }
        
        # Response headers
        response_headers = {
            'accept-ranges', 'age', 'etag', 'location', 'proxy-authenticate',
            'retry-after', 'server', 'vary', 'www-authenticate'
        }
        
        # Entity headers
        entity_headers = {
            'allow', 'content-encoding', 'content-language', 'content-length',
            'content-location', 'content-md5', 'content-range', 'content-type',
            'expires', 'last-modified'
        }
        
        # Authentication headers
        auth_headers = {
            'authorization', 'proxy-authorization', 'www-authenticate',
            'proxy-authenticate', 'x-api-key', 'x-auth-token', 'x-access-token'
        }
        
        # Cache headers
        cache_headers = {
            'cache-control', 'expires', 'pragma', 'if-modified-since',
            'if-none-match', 'etag', 'last-modified'
        }
        
        # Security headers
        security_headers = {
            'x-frame-options', 'x-content-type-options', 'x-xss-protection',
            'strict-transport-security', 'content-security-policy',
            'x-permitted-cross-domain-policies', 'referrer-policy'
        }
        
        # CORS headers
        cors_headers = {
            'access-control-allow-origin', 'access-control-allow-methods',
            'access-control-allow-headers', 'access-control-allow-credentials',
            'access-control-expose-headers', 'access-control-max-age',
            'origin', 'access-control-request-method', 'access-control-request-headers'
        }
        
        # Content headers
        content_headers = {
            'content-type', 'content-length', 'content-encoding',
            'content-language', 'content-disposition', 'content-range'
        }
        
        if name in general_headers:
            return HeaderCategory.GENERAL
        elif name in request_headers:
            return HeaderCategory.REQUEST
        elif name in response_headers:
            return HeaderCategory.RESPONSE
        elif name in entity_headers:
            return HeaderCategory.ENTITY
        elif name in auth_headers:
            return HeaderCategory.AUTHENTICATION
        elif name in cache_headers:
            return HeaderCategory.CACHE
        elif name in security_headers:
            return HeaderCategory.SECURITY
        elif name in cors_headers:
            return HeaderCategory.CORS
        elif name in content_headers:
            return HeaderCategory.CONTENT
        else:
            return HeaderCategory.UNKNOWN
    
    def _is_standard_header(self, name: str) -> bool:
        """Check if this is a standard HTTP header."""
        standard_headers = {
            'accept', 'accept-charset', 'accept-encoding', 'accept-language',
            'accept-ranges', 'age', 'allow', 'authorization', 'cache-control',
            'connection', 'content-encoding', 'content-language', 'content-length',
            'content-location', 'content-md5', 'content-range', 'content-type',
            'date', 'etag', 'expect', 'expires', 'from', 'host', 'if-match',
            'if-modified-since', 'if-none-match', 'if-range', 'if-unmodified-since',
            'last-modified', 'location', 'max-forwards', 'pragma', 'proxy-authenticate',
            'proxy-authorization', 'range', 'referer', 'retry-after', 'server',
            'te', 'trailer', 'transfer-encoding', 'upgrade', 'user-agent',
            'vary', 'via', 'warning', 'www-authenticate'
        }
        return name in standard_headers
    
    def _is_sensitive_header(self, name: str) -> bool:
        """Check if this header contains sensitive information."""
        sensitive_headers = {
            'authorization', 'proxy-authorization', 'cookie', 'x-api-key',
            'x-auth-token', 'x-access-token', 'x-secret', 'x-password'
        }
        return name in sensitive_headers
    
    def _is_auth_header(self, name: str) -> bool:
        """Check if this is an authentication-related header."""
        auth_headers = {
            'authorization', 'proxy-authorization', 'www-authenticate',
            'proxy-authenticate', 'x-api-key', 'x-auth-token', 'x-access-token',
            'x-secret', 'x-password', 'cookie'
        }
        return name in auth_headers
    
    def _is_security_header(self, name: str) -> bool:
        """Check if this is a security-related header."""
        security_headers = {
            'x-frame-options', 'x-content-type-options', 'x-xss-protection',
            'strict-transport-security', 'content-security-policy',
            'x-permitted-cross-domain-policies', 'referrer-policy',
            'x-powered-by', 'server'
        }
        return name in security_headers
    
    def get_auth_type(self) -> Optional[str]:
        """Get the authentication type if this is an auth header."""
        if not self.is_authentication_related:
            return None
        
        name_lower = self.name.lower()
        value_lower = self.value.lower()
        
        if name_lower == 'authorization':
            if value_lower.startswith('bearer '):
                return 'bearer'
            elif value_lower.startswith('basic '):
                return 'basic'
            elif value_lower.startswith('digest '):
                return 'digest'
            elif value_lower.startswith('oauth '):
                return 'oauth'
            else:
                return 'custom'
        elif name_lower in ['x-api-key', 'x-auth-token', 'x-access-token']:
            return 'api_key'
        elif name_lower == 'cookie':
            return 'cookie'
        else:
            return 'custom'
    
    def to_dict(self) -> dict:
        """Convert the header to a dictionary representation."""
        return {
            'name': self.name,
            'value': self.value,
            'category': self.category.value,
            'description': self.description,
            'is_standard': self.is_standard,
            'is_sensitive': self.is_sensitive,
            'is_authentication_related': self.is_authentication_related,
            'is_security_related': self.is_security_related,
            'auth_type': self.get_auth_type()
        }
    
    def __str__(self) -> str:
        """String representation of the header."""
        return f"{self.name}: {self.value}"
    
    def __repr__(self) -> str:
        """Detailed string representation of the header."""
        return f"Header(name='{self.name}', category={self.category.value})" 