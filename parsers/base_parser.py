from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from models import APIEndpoint


class BaseParser(ABC):
    """
    Abstract base class for all API discovery parsers.
    
    This class defines the common interface and functionality that all parsers
    must implement. It provides a standardized way to parse different data sources
    and extract API endpoint information.
    """
    
    def __init__(self):
        """Initialize the base parser."""
        self.parsed_endpoints: List[APIEndpoint] = []
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.stats: Dict[str, Any] = {}
    
    @abstractmethod
    def parse(self, data: Any) -> List[APIEndpoint]:
        """
        Parse the input data and extract API endpoints.
        
        Args:
            data: The data to parse (format depends on the parser type)
            
        Returns:
            List of discovered API endpoints
            
        Raises:
            ValueError: If the data is invalid or cannot be parsed
        """
        pass
    
    @abstractmethod
    def can_parse(self, data: Any) -> bool:
        """
        Check if this parser can handle the given data.
        
        Args:
            data: The data to check
            
        Returns:
            True if the parser can handle this data type, False otherwise
        """
        pass
    
    def validate_input(self, data: Any) -> bool:
        """
        Validate the input data before parsing.
        
        Args:
            data: The data to validate
            
        Returns:
            True if the data is valid, False otherwise
        """
        return data is not None
    
    def add_endpoint(self, endpoint: APIEndpoint):
        """
        Add an endpoint to the parsed results.
        
        Args:
            endpoint: The API endpoint to add
        """
        if endpoint and isinstance(endpoint, APIEndpoint):
            self.parsed_endpoints.append(endpoint)
    
    def add_error(self, error: str):
        """
        Add an error message.
        
        Args:
            error: The error message to add
        """
        if error and isinstance(error, str):
            self.errors.append(error)
    
    def add_warning(self, warning: str):
        """
        Add a warning message.
        
        Args:
            warning: The warning message to add
        """
        if warning and isinstance(warning, str):
            self.warnings.append(warning)
    
    def update_stats(self, key: str, value: Any):
        """
        Update parser statistics.
        
        Args:
            key: The statistic key
            value: The statistic value
        """
        self.stats[key] = value
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get parser statistics.
        
        Returns:
            Dictionary of parser statistics
        """
        return self.stats.copy()
    
    def get_errors(self) -> List[str]:
        """
        Get all error messages.
        
        Returns:
            List of error messages
        """
        return self.errors.copy()
    
    def get_warnings(self) -> List[str]:
        """
        Get all warning messages.
        
        Returns:
            List of warning messages
        """
        return self.warnings.copy()
    
    def has_errors(self) -> bool:
        """
        Check if there are any errors.
        
        Returns:
            True if there are errors, False otherwise
        """
        return len(self.errors) > 0
    
    def has_warnings(self) -> bool:
        """
        Check if there are any warnings.
        
        Returns:
            True if there are warnings, False otherwise
        """
        return len(self.warnings) > 0
    
    def clear_results(self):
        """Clear all parsed results and messages."""
        self.parsed_endpoints.clear()
        self.errors.clear()
        self.warnings.clear()
        self.stats.clear()
    
    def get_endpoints(self) -> List[APIEndpoint]:
        """
        Get all parsed endpoints.
        
        Returns:
            List of parsed API endpoints
        """
        return self.parsed_endpoints.copy()
    
    def get_endpoint_count(self) -> int:
        """
        Get the number of parsed endpoints.
        
        Returns:
            Number of parsed endpoints
        """
        return len(self.parsed_endpoints)
    
    def filter_endpoints(self, **filters) -> List[APIEndpoint]:
        """
        Filter endpoints based on criteria.
        
        Args:
            **filters: Filter criteria (method, path, base_url, etc.)
            
        Returns:
            List of filtered endpoints
        """
        filtered = []
        
        for endpoint in self.parsed_endpoints:
            match = True
            
            for key, value in filters.items():
                if hasattr(endpoint, key):
                    attr_value = getattr(endpoint, key)
                    if attr_value != value:
                        match = False
                        break
                else:
                    match = False
                    break
            
            if match:
                filtered.append(endpoint)
        
        return filtered
    
    def get_unique_methods(self) -> List[str]:
        """
        Get unique HTTP methods from parsed endpoints.
        
        Returns:
            List of unique HTTP methods
        """
        methods = set()
        for endpoint in self.parsed_endpoints:
            if hasattr(endpoint, 'method'):
                methods.add(endpoint.method)
        return list(methods)
    
    def get_unique_base_urls(self) -> List[str]:
        """
        Get unique base URLs from parsed endpoints.
        
        Returns:
            List of unique base URLs
        """
        base_urls = set()
        for endpoint in self.parsed_endpoints:
            if hasattr(endpoint, 'base_url'):
                base_urls.add(endpoint.base_url)
        return list(base_urls)
    
    def get_authenticated_endpoints(self) -> List[APIEndpoint]:
        """
        Get endpoints that require authentication.
        
        Returns:
            List of authenticated endpoints
        """
        return [ep for ep in self.parsed_endpoints if ep.is_authenticated()]
    
    def get_endpoints_with_request_body(self) -> List[APIEndpoint]:
        """
        Get endpoints that have request bodies.
        
        Returns:
            List of endpoints with request bodies
        """
        return [ep for ep in self.parsed_endpoints if ep.has_request_body()]
    
    def get_endpoints_with_response_body(self) -> List[APIEndpoint]:
        """
        Get endpoints that have response bodies.
        
        Returns:
            List of endpoints with response bodies
        """
        return [ep for ep in self.parsed_endpoints if ep.has_response_body()]
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert parser results to a dictionary.
        
        Returns:
            Dictionary representation of parser results
        """
        return {
            'endpoints': [ep.to_dict() for ep in self.parsed_endpoints],
            'errors': self.errors,
            'warnings': self.warnings,
            'stats': self.stats,
            'endpoint_count': self.get_endpoint_count(),
            'unique_methods': self.get_unique_methods(),
            'unique_base_urls': self.get_unique_base_urls(),
            'authenticated_endpoints': len(self.get_authenticated_endpoints()),
            'endpoints_with_request_body': len(self.get_endpoints_with_request_body()),
            'endpoints_with_response_body': len(self.get_endpoints_with_response_body())
        }
    
    def __str__(self) -> str:
        """String representation of the parser."""
        return f"{self.__class__.__name__}(endpoints={self.get_endpoint_count()}, errors={len(self.errors)})"
    
    def __repr__(self) -> str:
        """Detailed string representation of the parser."""
        return f"{self.__class__.__name__}(endpoints={self.get_endpoint_count()}, errors={len(self.errors)}, warnings={len(self.warnings)})"
