from dataclasses import dataclass, field
from typing import Optional, Any, List
from enum import Enum


class ParameterType(Enum):
    """Enumeration of parameter types."""
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"
    FILE = "file"
    UNKNOWN = "unknown"


class ParameterLocation(Enum):
    """Enumeration of parameter locations."""
    QUERY = "query"
    PATH = "path"
    HEADER = "header"
    COOKIE = "cookie"
    BODY = "body"
    FORM_DATA = "form-data"


@dataclass
class Parameter:
    """Represents an API parameter with metadata and type information."""
    
    name: str
    location: ParameterLocation
    value: Optional[Any] = None
    
    # Type information
    param_type: ParameterType = ParameterType.UNKNOWN
    inferred_type: Optional[str] = None
    
    # Validation and constraints
    required: bool = False
    default_value: Optional[Any] = None
    description: Optional[str] = None
    
    # Schema information
    schema: Optional[dict] = None
    examples: List[Any] = field(default_factory=list)
    
    # Additional metadata
    pattern: Optional[str] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    
    def __post_init__(self):
        """Infer parameter type from value if not specified."""
        if self.param_type == ParameterType.UNKNOWN and self.value is not None:
            self.param_type = self._infer_type_from_value(self.value)
            self.inferred_type = self.param_type.value
    
    def _infer_type_from_value(self, value: Any) -> ParameterType:
        """Infer parameter type from the provided value."""
        if value is None:
            return ParameterType.UNKNOWN
        
        if isinstance(value, bool):
            return ParameterType.BOOLEAN
        elif isinstance(value, int):
            return ParameterType.INTEGER
        elif isinstance(value, float):
            return ParameterType.NUMBER
        elif isinstance(value, str):
            # Try to infer more specific types from string values
            if value.lower() in ['true', 'false']:
                return ParameterType.BOOLEAN
            elif value.isdigit():
                return ParameterType.INTEGER
            elif self._is_numeric_string(value):
                return ParameterType.NUMBER
            else:
                return ParameterType.STRING
        elif isinstance(value, list):
            return ParameterType.ARRAY
        elif isinstance(value, dict):
            return ParameterType.OBJECT
        else:
            return ParameterType.UNKNOWN
    
    def _is_numeric_string(self, value: str) -> bool:
        """Check if a string represents a numeric value."""
        try:
            float(value)
            return True
        except ValueError:
            return False
    
    def add_example(self, example: Any):
        """Add an example value for this parameter."""
        self.examples.append(example)
        
        # Update inferred type based on new example
        if self.param_type == ParameterType.UNKNOWN:
            self.param_type = self._infer_type_from_value(example)
            self.inferred_type = self.param_type.value
    
    def is_authentication_related(self) -> bool:
        """Check if this parameter is related to authentication."""
        auth_keywords = [
            'token', 'key', 'auth', 'authorization', 'api_key', 
            'apikey', 'secret', 'password', 'credential'
        ]
        return any(keyword in self.name.lower() for keyword in auth_keywords)
    
    def is_sensitive(self) -> bool:
        """Check if this parameter contains sensitive information."""
        sensitive_keywords = [
            'password', 'secret', 'key', 'token', 'credential',
            'private', 'auth', 'authorization'
        ]
        return any(keyword in self.name.lower() for keyword in sensitive_keywords)
    
    def to_dict(self) -> dict:
        """Convert the parameter to a dictionary representation."""
        return {
            'name': self.name,
            'location': self.location.value,
            'value': self.value,
            'param_type': self.param_type.value,
            'inferred_type': self.inferred_type,
            'required': self.required,
            'default_value': self.default_value,
            'description': self.description,
            'schema': self.schema,
            'examples': self.examples,
            'pattern': self.pattern,
            'min_length': self.min_length,
            'max_length': self.max_length,
            'min_value': self.min_value,
            'max_value': self.max_value,
            'is_authentication_related': self.is_authentication_related(),
            'is_sensitive': self.is_sensitive()
        }
    
    def __str__(self) -> str:
        """String representation of the parameter."""
        return f"{self.name} ({self.location.value})"
    
    def __repr__(self) -> str:
        """Detailed string representation of the parameter."""
        return f"Parameter(name='{self.name}', location={self.location.value}, type={self.param_type.value})" 