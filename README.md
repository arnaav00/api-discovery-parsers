# API Discovery Parsers

A comprehensive suite of standalone API discovery parsers that can extract API endpoints, parameters, payloads, and authentication information from various data sources.

## Overview

This project provides a modular framework for discovering and analyzing API endpoints from different data sources. The parsers extract detailed information including:

- **API Endpoints**: HTTP method, path, full URL, base URL
- **Parameters**: Query parameters, path parameters, request body parameters
- **Headers**: Request and response headers with categorization
- **Authentication**: Bearer tokens, API keys, Basic auth, OAuth, etc.
- **Request/Response Bodies**: JSON schemas, form data, XML content
- **Security Information**: SSL certificates, sensitive data detection
- **Timing Information**: Request duration, performance metrics

## Current Implementation

### HAR Parser (`parsers/har_parser.py`)

The HAR (HTTP Archive) parser is fully implemented and can extract API endpoints from HAR 1.2 format files.

#### Features

- ✅ **HAR 1.2 Format Support**: Full compliance with HAR specification
- ✅ **API Endpoint Detection**: Intelligent filtering of API vs non-API requests
- ✅ **Parameter Extraction**: Query parameters, path parameters, form data
- ✅ **Header Analysis**: Categorized headers with authentication detection
- ✅ **Request/Response Body Parsing**: JSON, XML, form-encoded data
- ✅ **Authentication Detection**: Bearer tokens, API keys, Basic auth, OAuth
- ✅ **Schema Inference**: Automatic JSON schema generation from request/response bodies
- ✅ **Type Inference**: Automatic parameter type detection
- ✅ **Compression Support**: Gzip and deflate decompression
- ✅ **Error Handling**: Comprehensive validation and error reporting
- ✅ **Statistics**: Detailed parsing statistics and metrics

#### Usage

```python
from parsers.har_parser import HARParser

# Initialize parser
parser = HARParser()

# Parse HAR data (string, dict, or file path)
with open('sample.har', 'r') as f:
    har_data = f.read()

endpoints = parser.parse(har_data)

# Access results
for endpoint in endpoints:
    print(f"{endpoint.method} {endpoint.path}")
    print(f"Parameters: {len(endpoint.parameters)}")
    print(f"Headers: {len(endpoint.headers)}")
    print(f"Auth: {endpoint.auth_info.auth_type.value if endpoint.auth_info else 'None'}")
    print(f"Request body: {endpoint.has_request_body()}")
    print(f"Response body: {endpoint.has_response_body()}")
    print()

# Get statistics
stats = parser.get_stats()
print(f"Total endpoints: {stats['api_endpoints_found']}")
print(f"Success rate: {stats['success_rate']:.1f}%")

# Filter endpoints
get_endpoints = parser.get_endpoints_by_method('GET')
auth_endpoints = parser.get_authenticated_endpoints()
req_body_endpoints = parser.get_endpoints_with_request_body()
```

#### Example Output

```
============================================================
HAR Parser Demonstration
============================================================

1. Parsing HAR data...
   ✓ Found 3 API endpoints
   ✓ Processed 3 entries
   ✓ Success rate: 100.0%

2. Endpoint Details:

   Endpoint 1:
   ├─ Method: GET
   ├─ Path: /v1/users
   ├─ Full URL: https://api.example.com/v1/users?page=1&limit=10
   ├─ Base URL: https://api.example.com
   ├─ Status: 200
   ├─ Duration: 150ms
   ├─ Content Type: application/json
   ├─ Parameters (2):
   │  ├─ page (query): 1 (integer)
   │  ├─ limit (query): 10 (integer)
   ├─ Auth Headers (1):
   │  ├─ Authorization: Bearer eyJhbGciOiJIU...
   ├─ Authentication: bearer
   │  └─ Token: eyJhbGciOiJIUzI1NiIs...
   ├─ Response Body: dict
   │  └─ Schema: object
```

## Project Structure

```
api-discovery-parsers/
├── parsers/                    # Core parser modules
│   ├── __init__.py
│   ├── base_parser.py         # Abstract base class ✅
│   ├── har_parser.py          # HTTP Archive files ✅
│   ├── openapi_parser.py      # OpenAPI/Swagger specs (planned)
│   ├── postman_parser.py      # Postman collections (planned)
│   ├── mitm_parser.py         # MITM proxy logs (planned)
│   ├── source_code_parser.py  # Static code analysis (planned)
│   └── base_url_parser.py     # Base URL discovery (planned)
├── models/                     # Data models ✅
│   ├── __init__.py
│   ├── api_endpoint.py        # Common endpoint model ✅
│   ├── parameter.py           # Parameter definitions ✅
│   ├── header.py              # HTTP headers ✅
│   ├── auth_info.py           # Authentication data ✅
│   └── ssl_info.py            # SSL certificate info ✅
├── utils/                      # Utility functions ✅
│   ├── __init__.py
│   ├── url_utils.py           # URL normalization ✅
│   ├── validation_utils.py    # Input validation ✅
│   └── normalization_utils.py # Data normalization ✅
├── samples/                    # Sample data files
│   └── sample.har.json        # Sample HAR file ✅
├── tests/                      # Test suite (planned)
├── benchmarks/                 # Performance tests (planned)
├── docs/                       # Documentation (planned)
├── test_har_parser.py         # Simple test script ✅
├── example_usage.py           # Comprehensive example ✅
└── README.md                  # This file ✅
```

## Data Models

### APIEndpoint

Represents a discovered API endpoint with comprehensive metadata:

```python
@dataclass
class APIEndpoint:
    method: str                    # HTTP method (GET, POST, etc.)
    path: str                      # URL path
    full_url: str                  # Complete URL
    base_url: str                  # Base URL (scheme + netloc)
    headers: List[Header]          # Request headers
    parameters: List[Parameter]    # Query/path/body parameters
    request_body: Optional[Dict]   # Parsed request body
    response_body: Optional[Dict]  # Parsed response body
    auth_info: Optional[AuthInfo]  # Authentication information
    ssl_info: Optional[SSLInfo]    # SSL certificate info
    # ... additional metadata
```

### Parameter

Represents API parameters with type inference:

```python
@dataclass
class Parameter:
    name: str                      # Parameter name
    location: ParameterLocation    # query, path, header, body, etc.
    value: Any                     # Parameter value
    param_type: ParameterType      # string, integer, boolean, etc.
    required: bool                 # Whether parameter is required
    # ... additional metadata
```

### Header

Represents HTTP headers with categorization:

```python
@dataclass
class Header:
    name: str                      # Header name
    value: str                     # Header value
    category: HeaderCategory       # request, response, auth, etc.
    is_standard: bool              # Whether it's a standard HTTP header
    is_sensitive: bool             # Whether it contains sensitive data
    # ... additional metadata
```

### AuthInfo

Represents authentication information:

```python
@dataclass
class AuthInfo:
    auth_type: AuthType            # bearer, basic, api_key, oauth, etc.
    location: AuthLocation         # header, query, body, cookie
    token: Optional[str]           # Authentication token
    api_key: Optional[str]         # API key value
    # ... additional metadata
```

## Utility Functions

### URL Utilities

- `extract_base_url(url)`: Extract base URL from full URL
- `extract_path_from_url(url)`: Extract path with query parameters
- `normalize_url(url)`: Normalize URL format
- `is_api_endpoint(url, method)`: Detect if URL is likely an API endpoint
- `extract_query_parameters(url)`: Parse query parameters
- `extract_path_parameters(path)`: Identify potential path parameters

### Validation Utilities

- `validate_har_file(data)`: Validate HAR file structure
- `validate_json_content(content)`: Validate JSON content
- `validate_url(url)`: Validate URL format
- `validate_http_method(method)`: Validate HTTP method
- `validate_status_code(code)`: Validate HTTP status code

### Normalization Utilities

- `normalize_json_schema(schema)`: Normalize JSON schema format
- `infer_parameter_types(data)`: Infer parameter types from data
- `extract_schema_from_json(data)`: Generate schema from JSON data
- `merge_schemas(schema1, schema2)`: Merge multiple schemas
- `deduplicate_endpoints(endpoints)`: Remove duplicate endpoints

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd api-discovery-parsers
```

2. Install dependencies (if any):
```bash
pip install -r requirements.txt
```

3. Run the example:
```bash
python example_usage.py
```

## Testing

Run the simple test:
```bash
python test_har_parser.py
```

## Planned Features

### OpenAPI Parser
- Support for OAS 2.0, 3.0, 3.1
- Extract parameters, schemas, authentication
- Parse request/response examples
- Handle references and components

### Postman Collection Parser
- Handle variables and environments
- Extract request/response examples
- Parse authentication configurations
- Support different Postman versions

### MITM Parser
- Extract SSL certificate information
- Handle different log formats
- Parse request/response bodies
- Infer API patterns from repeated requests

### Source Code Parser
- Support JavaScript/TypeScript (Express, Fastify, NestJS)
- Support Python (Flask, Django, FastAPI)
- Support Java (Spring Boot, JAX-RS)
- Extract route definitions and parameters
- Parse request body schemas from code

### Base URL Parser
- Common endpoint enumeration
- Authentication detection
- Rate limiting detection
- Infer API structure from discovered endpoints

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests
5. Submit a pull request

## License

[Add your license here]

## Support

For questions and support, please open an issue on GitHub. 