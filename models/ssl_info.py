from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class SSLInfo:
    """Represents SSL certificate information extracted from HTTPS requests."""
    
    # Certificate information
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    fingerprint: Optional[str] = None
    
    # Validity dates
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    
    # Certificate details
    version: Optional[str] = None
    signature_algorithm: Optional[str] = None
    public_key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    
    # Subject Alternative Names
    san_dns_names: List[str] = None
    san_ip_addresses: List[str] = None
    
    # Certificate chain
    certificate_chain: List[str] = None
    
    # Security information
    is_valid: bool = True
    is_self_signed: bool = False
    is_expired: bool = False
    is_revoked: bool = False
    
    # Protocol information
    protocol_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    key_exchange_algorithm: Optional[str] = None
    
    # Additional properties
    properties: Dict[str, Any] = None
    
    def __post_init__(self):
        """Initialize default values for lists and dicts."""
        if self.san_dns_names is None:
            self.san_dns_names = []
        if self.san_ip_addresses is None:
            self.san_ip_addresses = []
        if self.certificate_chain is None:
            self.certificate_chain = []
        if self.properties is None:
            self.properties = {}
    
    def add_san_dns_name(self, dns_name: str):
        """Add a DNS name to the Subject Alternative Names."""
        if dns_name not in self.san_dns_names:
            self.san_dns_names.append(dns_name)
    
    def add_san_ip_address(self, ip_address: str):
        """Add an IP address to the Subject Alternative Names."""
        if ip_address not in self.san_ip_addresses:
            self.san_ip_addresses.append(ip_address)
    
    def add_certificate_to_chain(self, certificate: str):
        """Add a certificate to the certificate chain."""
        if certificate not in self.certificate_chain:
            self.certificate_chain.append(certificate)
    
    def set_property(self, key: str, value: Any):
        """Set an additional property."""
        self.properties[key] = value
    
    def get_property(self, key: str, default: Any = None) -> Any:
        """Get an additional property."""
        return self.properties.get(key, default)
    
    def is_wildcard_certificate(self) -> bool:
        """Check if this is a wildcard certificate."""
        if not self.san_dns_names:
            return False
        return any('*' in dns_name for dns_name in self.san_dns_names)
    
    def matches_domain(self, domain: str) -> bool:
        """Check if the certificate matches a specific domain."""
        if not domain:
            return False
        
        # Check SAN DNS names
        for san_dns in self.san_dns_names:
            if self._domain_matches(san_dns, domain):
                return True
        
        # Check subject CN
        if self.subject and 'CN=' in self.subject:
            cn_start = self.subject.find('CN=') + 3
            cn_end = self.subject.find(',', cn_start)
            if cn_end == -1:
                cn_end = len(self.subject)
            cn = self.subject[cn_start:cn_end]
            if self._domain_matches(cn, domain):
                return True
        
        return False
    
    def _domain_matches(self, pattern: str, domain: str) -> bool:
        """Check if a domain matches a pattern (supports wildcards)."""
        if pattern == domain:
            return True
        
        if '*' in pattern:
            # Handle wildcard certificates
            pattern_parts = pattern.split('.')
            domain_parts = domain.split('.')
            
            if len(pattern_parts) != len(domain_parts):
                return False
            
            for i, (pattern_part, domain_part) in enumerate(zip(pattern_parts, domain_parts)):
                if pattern_part == '*':
                    continue
                if pattern_part != domain_part:
                    return False
            
            return True
        
        return False
    
    def get_days_until_expiry(self) -> Optional[int]:
        """Get the number of days until the certificate expires."""
        if not self.valid_until:
            return None
        
        now = datetime.now()
        delta = self.valid_until - now
        return delta.days
    
    def is_expiring_soon(self, days_threshold: int = 30) -> bool:
        """Check if the certificate is expiring soon."""
        days_until_expiry = self.get_days_until_expiry()
        if days_until_expiry is None:
            return False
        return days_until_expiry <= days_threshold
    
    def get_security_score(self) -> int:
        """Calculate a security score for the certificate (0-100)."""
        score = 100
        
        # Deduct points for various issues
        if not self.is_valid:
            score -= 50
        if self.is_self_signed:
            score -= 30
        if self.is_expired:
            score -= 40
        if self.is_revoked:
            score -= 50
        if self.is_expiring_soon(7):  # Expiring within a week
            score -= 20
        elif self.is_expiring_soon(30):  # Expiring within a month
            score -= 10
        
        # Deduct points for weak algorithms
        if self.signature_algorithm and 'md5' in self.signature_algorithm.lower():
            score -= 20
        if self.key_size and self.key_size < 2048:
            score -= 15
        
        return max(0, score)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the SSL info to a dictionary representation."""
        return {
            'subject': self.subject,
            'issuer': self.issuer,
            'serial_number': self.serial_number,
            'fingerprint': self.fingerprint,
            'valid_from': self.valid_from.isoformat() if self.valid_from else None,
            'valid_until': self.valid_until.isoformat() if self.valid_until else None,
            'version': self.version,
            'signature_algorithm': self.signature_algorithm,
            'public_key_algorithm': self.public_key_algorithm,
            'key_size': self.key_size,
            'san_dns_names': self.san_dns_names,
            'san_ip_addresses': self.san_ip_addresses,
            'certificate_chain': self.certificate_chain,
            'is_valid': self.is_valid,
            'is_self_signed': self.is_self_signed,
            'is_expired': self.is_expired,
            'is_revoked': self.is_revoked,
            'protocol_version': self.protocol_version,
            'cipher_suite': self.cipher_suite,
            'key_exchange_algorithm': self.key_exchange_algorithm,
            'properties': self.properties,
            'days_until_expiry': self.get_days_until_expiry(),
            'security_score': self.get_security_score(),
            'is_wildcard': self.is_wildcard_certificate()
        }
    
    def __str__(self) -> str:
        """String representation of the SSL info."""
        if self.subject:
            return f"SSL: {self.subject}"
        elif self.issuer:
            return f"SSL: {self.issuer}"
        else:
            return "SSL: Unknown Certificate"
    
    def __repr__(self) -> str:
        """Detailed string representation of the SSL info."""
        return f"SSLInfo(subject='{self.subject}', valid={self.is_valid}, score={self.get_security_score()})" 