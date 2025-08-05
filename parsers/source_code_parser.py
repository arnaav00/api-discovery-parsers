import json
import re
import os
import ast
from typing import List, Dict, Any, Optional, Union, Set
from pathlib import Path
from urllib.parse import urlparse, urljoin
from datetime import datetime
import tokenize
import io

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


class SourceCodeParser(BaseParser):
    """
    Parser for extracting API endpoints from source code.
    
    This parser performs static code analysis to discover API endpoints,
    route definitions, parameters, and schemas from various programming
    languages and frameworks.
    """
    
    def __init__(self):
        """Initialize the Source Code parser."""
        super().__init__()
        self.source_files = []
        self.framework_detected = None
        self.language_detected = None
        self.config_files = {}
        self.dependencies = {}
        
        # Framework patterns
        self.framework_patterns = {
            'javascript': {
                'express': [
                    r'app\.(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                    r'router\.(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                    r'@(Get|Post|Put|Delete|Patch)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                ],
                'fastify': [
                    r'fastify\.(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                    r'@(Get|Post|Put|Delete|Patch)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                ],
                'nest': [
                    r'@Controller\s*\(\s*[\'"]([^\'"]+)[\'"]',
                    r'@(Get|Post|Put|Delete|Patch)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                ],
                'koa': [
                    r'router\.(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                ],
                'hapi': [
                    r'method:\s*[\'"](get|post|put|delete|patch)[\'"]',
                    r'path:\s*[\'"]([^\'"]+)[\'"]',
                ]
            },
            'python': {
                'flask': [
                    r'@app\.(route|get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                    r'@bp\.(route|get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                ],
                'django': [
                    r'path\s*\(\s*[\'"]([^\'"]+)[\'"]',
                    r're_path\s*\(\s*[\'"]([^\'"]+)[\'"]',
                ],
                'fastapi': [
                    r'@app\.(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                    r'@router\.(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                ],
                'bottle': [
                    r'@(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                ],
                'tornado': [
                    r'class\s+\w+\(web\.RequestHandler\):',
                ]
            },
            'java': {
                'spring': [
                    r'@(Get|Post|Put|Delete|Patch)Mapping\s*\(\s*[\'"]([^\'"]+)[\'"]',
                    r'@RequestMapping\s*\(\s*[\'"]([^\'"]+)[\'"]',
                    r'@RestController',
                ],
                'jaxrs': [
                    r'@(GET|POST|PUT|DELETE|PATCH)',
                    r'@Path\s*\(\s*[\'"]([^\'"]+)[\'"]',
                ],
                'micronaut': [
                    r'@Controller\s*\(\s*[\'"]([^\'"]+)[\'"]',
                    r'@(Get|Post|Put|Delete|Patch)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                ],
                'quarkus': [
                    r'@Path\s*\(\s*[\'"]([^\'"]+)[\'"]',
                    r'@(GET|POST|PUT|DELETE|PATCH)',
                ]
            }
        }
        
        # Parameter patterns
        self.parameter_patterns = {
            'javascript': [
                r'req\.params\.(\w+)',
                r'req\.query\.(\w+)',
                r'req\.body\.(\w+)',
                r'@Param\s*\(\s*[\'"]([^\'"]+)[\'"]',
                r'@Query\s*\(\s*[\'"]([^\'"]+)[\'"]',
                r'@Body\s*\(\s*[\'"]([^\'"]+)[\'"]',
            ],
            'python': [
                r'request\.args\.get\s*\(\s*[\'"]([^\'"]+)[\'"]',
                r'request\.form\.get\s*\(\s*[\'"]([^\'"]+)[\'"]',
                r'request\.json\.get\s*\(\s*[\'"]([^\'"]+)[\'"]',
                r'@Query\s*\(\s*[\'"]([^\'"]+)[\'"]',
                r'@Path\s*\(\s*[\'"]([^\'"]+)[\'"]',
                r'@Body\s*\(\s*[\'"]([^\'"]+)[\'"]',
            ],
            'java': [
                r'@PathVariable\s*\(\s*[\'"]([^\'"]+)[\'"]',
                r'@RequestParam\s*\(\s*[\'"]([^\'"]+)[\'"]',
                r'@RequestBody\s*(\w+)',
                r'@PathParam\s*\(\s*[\'"]([^\'"]+)[\'"]',
                r'@QueryParam\s*\(\s*[\'"]([^\'"]+)[\'"]',
            ]
        }
        
        # Schema patterns
        self.schema_patterns = {
            'javascript': [
                r'interface\s+(\w+)\s*\{',
                r'type\s+(\w+)\s*=\s*\{',
                r'class\s+(\w+)\s*\{',
                r'@Schema\s*\(\s*\{',
            ],
            'python': [
                r'class\s+(\w+)\s*\(.*\):',
                r'@dataclass',
                r'class\s+(\w+)\s*\(BaseModel\):',
                r'class\s+(\w+)\s*\(Model\):',
            ],
            'java': [
                r'class\s+(\w+)\s*\{',
                r'@Entity',
                r'@Data',
                r'@JsonIgnoreProperties',
            ]
        }
        
    def can_parse(self, data: Any) -> bool:
        """
        Check if this parser can handle the given data.
        
        Args:
            data: The data to check (can be string, dict, or file path)
            
        Returns:
            True if the parser can handle this data type, False otherwise
        """
        if isinstance(data, str):
            # Check if it's a file path
            if os.path.exists(data):
                return self._is_source_code_file(data)
            # Check if it's source code content
            return self._is_source_code_content(data)
        elif isinstance(data, list):
            # Check if it's a list of file paths
            return all(os.path.exists(path) for path in data)
        else:
            return False
    
    def parse(self, data: Any) -> List[APIEndpoint]:
        """
        Parse source code and extract API endpoints.
        
        Args:
            data: Source code files as string, list, or file path
            
        Returns:
            List of discovered API endpoints
            
        Raises:
            ValueError: If the data is invalid or cannot be parsed
        """
        self.clear_results()
        
        try:
            # Parse input data
            self.source_files = self._parse_input(data)
            
            # Validate source files
            if not self.source_files:
                raise ValueError("No valid source code files found")
            
            # Detect language and framework
            self._detect_language_and_framework()
            
            # Parse configuration files
            self._parse_config_files()
            
            # Extract endpoints from source code
            self._extract_endpoints()
            
            # Update final statistics
            self._update_final_stats()
            
            return self.parsed_endpoints
            
        except Exception as e:
            self.add_error(f"Failed to parse source code: {str(e)}")
            raise ValueError(f"Source code parsing failed: {str(e)}")
    
    def _parse_input(self, data: Any) -> List[str]:
        """
        Parse input data into source code files.
        
        Args:
            data: Input data (string, list, or file path)
            
        Returns:
            List of source code file paths
        """
        if isinstance(data, list):
            return [path for path in data if os.path.exists(path)]
        elif isinstance(data, str):
            if os.path.exists(data):
                if os.path.isfile(data):
                    return [data]
                elif os.path.isdir(data):
                    return self._find_source_files(data)
            else:
                # Treat as source code content
                return []
        else:
            raise ValueError(f"Unsupported data type: {type(data)}")
    
    def _find_source_files(self, directory: str) -> List[str]:
        """
        Find source code files in directory.
        
        Args:
            directory: Directory to search
            
        Returns:
            List of source code file paths
        """
        source_files = []
        source_extensions = {
            '.js', '.ts', '.jsx', '.tsx',  # JavaScript/TypeScript
            '.py', '.pyx', '.pyi',          # Python
            '.java', '.kt', '.groovy',      # Java/Kotlin/Groovy
            '.go', '.rs', '.php', '.rb',    # Other languages
        }
        
        for root, dirs, files in os.walk(directory):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', 'target', 'build'}]
            
            for file in files:
                if any(file.endswith(ext) for ext in source_extensions):
                    source_files.append(os.path.join(root, file))
        
        return source_files
    
    def _is_source_code_file(self, file_path: str) -> bool:
        """
        Check if file is a source code file.
        
        Args:
            file_path: File path to check
            
        Returns:
            True if source code file
        """
        source_extensions = {
            '.js', '.ts', '.jsx', '.tsx',
            '.py', '.pyx', '.pyi',
            '.java', '.kt', '.groovy',
            '.go', '.rs', '.php', '.rb',
        }
        
        return any(file_path.endswith(ext) for ext in source_extensions)
    
    def _is_source_code_content(self, content: str) -> bool:
        """
        Check if content looks like source code.
        
        Args:
            content: Content to check
            
        Returns:
            True if source code content
        """
        # Look for common programming patterns
        patterns = [
            r'function\s+\w+\s*\(',
            r'def\s+\w+\s*\(',
            r'public\s+class\s+\w+',
            r'import\s+',
            r'require\s*\(',
            r'from\s+\w+\s+import',
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns)
    
    def _detect_language_and_framework(self):
        """Detect programming language and framework from source files."""
        language_counts = {'javascript': 0, 'python': 0, 'java': 0}
        framework_counts = {}
        
        for file_path in self.source_files:
            ext = os.path.splitext(file_path)[1].lower()
            
            # Detect language by file extension
            if ext in {'.js', '.ts', '.jsx', '.tsx'}:
                language_counts['javascript'] += 1
            elif ext in {'.py', '.pyx', '.pyi'}:
                language_counts['python'] += 1
            elif ext in {'.java', '.kt', '.groovy'}:
                language_counts['java'] += 1
            
            # Detect framework by reading file content
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    self._detect_framework_from_content(content, framework_counts)
            except Exception:
                continue
        
        # Set detected language
        self.language_detected = max(language_counts.items(), key=lambda x: x[1])[0] if any(language_counts.values()) else None
        
        # Set detected framework
        if framework_counts:
            self.framework_detected = max(framework_counts.items(), key=lambda x: x[1])[0]
        
        self.update_stats('language_detected', self.language_detected)
        self.update_stats('framework_detected', self.framework_detected)
    
    def _detect_framework_from_content(self, content: str, framework_counts: Dict[str, int]):
        """
        Detect framework from file content.
        
        Args:
            content: File content
            framework_counts: Dictionary to update with framework counts
        """
        for language, frameworks in self.framework_patterns.items():
            for framework, patterns in frameworks.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        framework_counts[framework] = framework_counts.get(framework, 0) + 1
    
    def _parse_config_files(self):
        """Parse configuration files to extract dependencies and settings."""
        config_files = {
            'package.json': self._parse_package_json,
            'requirements.txt': self._parse_requirements_txt,
            'pom.xml': self._parse_pom_xml,
            'build.gradle': self._parse_build_gradle,
            'pyproject.toml': self._parse_pyproject_toml,
            'setup.py': self._parse_setup_py,
        }
        
        for file_name, parser_func in config_files.items():
            for file_path in self.source_files:
                if os.path.basename(file_path) == file_name:
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            config_data = parser_func(content)
                            self.config_files[file_name] = config_data
                    except Exception as e:
                        self.add_warning(f"Failed to parse {file_name}: {str(e)}")
    
    def _parse_package_json(self, content: str) -> Dict[str, Any]:
        """Parse package.json file."""
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {}
    
    def _parse_requirements_txt(self, content: str) -> Dict[str, str]:
        """Parse requirements.txt file."""
        dependencies = {}
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                # Extract package name and version
                parts = line.split('==')
                if len(parts) == 2:
                    dependencies[parts[0]] = parts[1]
                else:
                    dependencies[line] = 'latest'
        return dependencies
    
    def _parse_pom_xml(self, content: str) -> Dict[str, Any]:
        """Parse pom.xml file."""
        # Simple XML parsing for dependencies
        dependencies = {}
        dep_pattern = r'<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>'
        for match in re.finditer(dep_pattern, content):
            dependencies[match.group(1)] = match.group(2)
        return dependencies
    
    def _parse_build_gradle(self, content: str) -> Dict[str, Any]:
        """Parse build.gradle file."""
        dependencies = {}
        dep_pattern = r'implementation\s+[\'"]([^\'"]+)[\'"]'
        for match in re.finditer(dep_pattern, content):
            dependencies[match.group(1)] = 'latest'
        return dependencies
    
    def _parse_pyproject_toml(self, content: str) -> Dict[str, Any]:
        """Parse pyproject.toml file."""
        dependencies = {}
        dep_pattern = r'([^=]+)\s*=\s*[\'"]([^\'"]+)[\'"]'
        for match in re.finditer(dep_pattern, content):
            dependencies[match.group(1).strip()] = match.group(2)
        return dependencies
    
    def _parse_setup_py(self, content: str) -> Dict[str, Any]:
        """Parse setup.py file."""
        dependencies = {}
        dep_pattern = r'install_requires\s*=\s*\[(.*?)\]'
        match = re.search(dep_pattern, content, re.DOTALL)
        if match:
            deps_str = match.group(1)
            for dep in re.finditer(r'[\'"]([^\'"]+)[\'"]', deps_str):
                dependencies[dep.group(1)] = 'latest'
        return dependencies
    
    def _extract_endpoints(self):
        """Extract API endpoints from source code files."""
        for file_path in self.source_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Extract endpoints based on detected language
                if self.language_detected == 'javascript':
                    self._extract_javascript_endpoints(content, file_path)
                elif self.language_detected == 'python':
                    self._extract_python_endpoints(content, file_path)
                elif self.language_detected == 'java':
                    self._extract_java_endpoints(content, file_path)
                    
            except Exception as e:
                self.add_warning(f"Failed to parse {file_path}: {str(e)}")
    
    def _extract_javascript_endpoints(self, content: str, file_path: str):
        """
        Extract endpoints from JavaScript/TypeScript code.
        
        Args:
            content: JavaScript/TypeScript code content
            file_path: Source file path
        """
        # Extract Express.js routes
        express_patterns = [
            (r'app\.(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]', 'express'),
            (r'router\.(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]', 'express'),
            (r'@(Get|Post|Put|Delete|Patch)\s*\(\s*[\'"]([^\'"]+)[\'"]', 'nest'),
            (r'fastify\.(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]', 'fastify'),
        ]
        
        for pattern, framework in express_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                method = match.group(1).upper()
                path = match.group(2)
                
                # Extract parameters
                parameters = self._extract_javascript_parameters(content, path)
                
                # Create endpoint
                endpoint = self._create_endpoint_from_code(method, path, parameters, file_path, framework)
                self.add_endpoint(endpoint)
    
    def _extract_python_endpoints(self, content: str, file_path: str):
        """
        Extract endpoints from Python code.
        
        Args:
            content: Python code content
            file_path: Source file path
        """
        # Extract Flask routes
        flask_patterns = [
            (r'@app\.(route|get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]', 'flask'),
            (r'@bp\.(route|get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]', 'flask'),
        ]
        
        # Extract FastAPI routes
        fastapi_patterns = [
            (r'@app\.(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]', 'fastapi'),
            (r'@router\.(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]', 'fastapi'),
        ]
        
        all_patterns = flask_patterns + fastapi_patterns
        
        for pattern, framework in all_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                method = match.group(1).upper()
                path = match.group(2)
                
                # Extract parameters
                parameters = self._extract_python_parameters(content, path)
                
                # Create endpoint
                endpoint = self._create_endpoint_from_code(method, path, parameters, file_path, framework)
                self.add_endpoint(endpoint)
    
    def _extract_java_endpoints(self, content: str, file_path: str):
        """
        Extract endpoints from Java code.
        
        Args:
            content: Java code content
            file_path: Source file path
        """
        # Extract Spring Boot endpoints
        spring_patterns = [
            (r'@(Get|Post|Put|Delete|Patch)Mapping\s*\(\s*[\'"]([^\'"]+)[\'"]', 'spring'),
            (r'@RequestMapping\s*\(\s*[\'"]([^\'"]+)[\'"]', 'spring'),
        ]
        
        # Extract JAX-RS endpoints
        jaxrs_patterns = [
            (r'@(GET|POST|PUT|DELETE|PATCH)', 'jaxrs'),
            (r'@Path\s*\(\s*[\'"]([^\'"]+)[\'"]', 'jaxrs'),
        ]
        
        all_patterns = spring_patterns + jaxrs_patterns
        
        for pattern, framework in all_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                method = match.group(1).upper()
                path = match.group(2) if len(match.groups()) > 1 else '/'
                
                # Extract parameters
                parameters = self._extract_java_parameters(content, path)
                
                # Create endpoint
                endpoint = self._create_endpoint_from_code(method, path, parameters, file_path, framework)
                self.add_endpoint(endpoint)
    
    def _extract_javascript_parameters(self, content: str, path: str) -> List[Parameter]:
        """
        Extract parameters from JavaScript code.
        
        Args:
            content: JavaScript code content
            path: API path
            
        Returns:
            List of parameters
        """
        parameters = []
        
        # Extract path parameters
        path_params = re.findall(r'/:(\w+)', path)
        for param_name in path_params:
            param = Parameter(
                name=param_name,
                location=ParameterLocation.PATH,
                param_type=ParameterType.STRING,
                required=True
            )
            parameters.append(param)
        
        # Extract query parameters
        query_patterns = [
            r'req\.query\.(\w+)',
            r'@Query\s*\(\s*[\'"]([^\'"]+)[\'"]',
        ]
        
        for pattern in query_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                param_name = match.group(1)
                param = Parameter(
                    name=param_name,
                    location=ParameterLocation.QUERY,
                    param_type=ParameterType.STRING,
                    required=False
                )
                parameters.append(param)
        
        # Extract body parameters
        body_patterns = [
            r'req\.body\.(\w+)',
            r'@Body\s*\(\s*[\'"]([^\'"]+)[\'"]',
        ]
        
        for pattern in body_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                param_name = match.group(1)
                param = Parameter(
                    name=param_name,
                    location=ParameterLocation.BODY,
                    param_type=ParameterType.OBJECT,
                    required=False
                )
                parameters.append(param)
        
        return parameters
    
    def _extract_python_parameters(self, content: str, path: str) -> List[Parameter]:
        """
        Extract parameters from Python code.
        
        Args:
            content: Python code content
            path: API path
            
        Returns:
            List of parameters
        """
        parameters = []
        
        # Extract path parameters
        path_params = re.findall(r'<(\w+)>', path)
        for param_name in path_params:
            param = Parameter(
                name=param_name,
                location=ParameterLocation.PATH,
                param_type=ParameterType.STRING,
                required=True
            )
            parameters.append(param)
        
        # Extract query parameters
        query_patterns = [
            r'request\.args\.get\s*\(\s*[\'"]([^\'"]+)[\'"]',
            r'@Query\s*\(\s*[\'"]([^\'"]+)[\'"]',
        ]
        
        for pattern in query_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                param_name = match.group(1)
                param = Parameter(
                    name=param_name,
                    location=ParameterLocation.QUERY,
                    param_type=ParameterType.STRING,
                    required=False
                )
                parameters.append(param)
        
        # Extract body parameters
        body_patterns = [
            r'request\.json\.get\s*\(\s*[\'"]([^\'"]+)[\'"]',
            r'@Body\s*\(\s*[\'"]([^\'"]+)[\'"]',
        ]
        
        for pattern in body_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                param_name = match.group(1)
                param = Parameter(
                    name=param_name,
                    location=ParameterLocation.BODY,
                    param_type=ParameterType.OBJECT,
                    required=False
                )
                parameters.append(param)
        
        return parameters
    
    def _extract_java_parameters(self, content: str, path: str) -> List[Parameter]:
        """
        Extract parameters from Java code.
        
        Args:
            content: Java code content
            path: API path
            
        Returns:
            List of parameters
        """
        parameters = []
        
        # Extract path parameters
        path_params = re.findall(r'\{(\w+)\}', path)
        for param_name in path_params:
            param = Parameter(
                name=param_name,
                location=ParameterLocation.PATH,
                param_type=ParameterType.STRING,
                required=True
            )
            parameters.append(param)
        
        # Extract query parameters
        query_patterns = [
            r'@RequestParam\s*\(\s*[\'"]([^\'"]+)[\'"]',
            r'@QueryParam\s*\(\s*[\'"]([^\'"]+)[\'"]',
        ]
        
        for pattern in query_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                param_name = match.group(1)
                param = Parameter(
                    name=param_name,
                    location=ParameterLocation.QUERY,
                    param_type=ParameterType.STRING,
                    required=False
                )
                parameters.append(param)
        
        # Extract body parameters
        body_patterns = [
            r'@RequestBody\s*(\w+)',
            r'@Consumes\s*\(\s*[\'"]([^\'"]+)[\'"]',
        ]
        
        for pattern in body_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                param_name = match.group(1)
                param = Parameter(
                    name=param_name,
                    location=ParameterLocation.BODY,
                    param_type=ParameterType.OBJECT,
                    required=False
                )
                parameters.append(param)
        
        return parameters
    
    def _create_endpoint_from_code(self, method: str, path: str, parameters: List[Parameter], file_path: str, framework: str) -> APIEndpoint:
        """
        Create APIEndpoint from source code.
        
        Args:
            method: HTTP method
            path: API path
            parameters: List of parameters
            file_path: Source file path
            framework: Framework name
            
        Returns:
            Created APIEndpoint
        """
        # Create endpoint
        endpoint = APIEndpoint(
            method=method,
            path=path,
            full_url=f"https://api.example.com{path}",
            base_url="https://api.example.com",
            timestamp=datetime.now().isoformat(),
            har_entry_index=len(self.parsed_endpoints)
        )
        
        # Add parameters
        for param in parameters:
            endpoint.add_parameter(param)
        
        # Set content type based on framework
        if framework in ['fastapi', 'spring']:
            endpoint.content_type = 'application/json'
        elif framework in ['flask', 'express']:
            endpoint.content_type = 'application/json'
        
        # Add framework information
        endpoint.description = f"Extracted from {framework} code in {os.path.basename(file_path)}"
        
        return endpoint
    
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
        
        # Source code statistics
        self.update_stats('source_files_analyzed', len(self.source_files))
        self.update_stats('config_files_found', len(self.config_files))
    
    def get_config_files(self) -> Dict[str, Any]:
        """Get the parsed configuration files."""
        return self.config_files.copy()
    
    def get_dependencies(self) -> Dict[str, Any]:
        """Get the extracted dependencies."""
        return self.dependencies.copy()


if __name__ == "__main__":
    import sys
    import os
    
    def main():
        """Main function to run Source Code parser from command line."""
        if len(sys.argv) != 2:
            print("Usage: python source_code_parser.py <path_to_source_code>")
            print("\nExamples:")
            print("  python source_code_parser.py ./src")
            print("  python source_code_parser.py app.js")
            print("  python source_code_parser.py /path/to/project")
            return
        
        source_path = sys.argv[1]
        
        # Check if path exists
        if not os.path.exists(source_path):
            print(f"Error: Path '{source_path}' not found.")
            return
        
        # Initialize parser
        parser = SourceCodeParser()
        
        try:
            # Parse source code
            endpoints = parser.parse(source_path)
            
            # Display results
            print(f"\n{'='*60}")
            print(f"Source Code Parser Results for: {source_path}")
            print(f"{'='*60}")
            
            if endpoints:
                print(f"\nFound {len(endpoints)} API endpoint(s):")
                print("-" * 40)
                
                for i, endpoint in enumerate(endpoints, 1):
                    print(f"\n{i}. {endpoint.method} {endpoint.path}")
                    print(f"   Full URL: {endpoint.full_url}")
                    print(f"   Description: {endpoint.description}")
                    
                    if endpoint.parameters:
                        print(f"   Parameters ({len(endpoint.parameters)}):")
                        for param in endpoint.parameters:
                            print(f"     - {param.name} ({param.param_type.value}) in {param.location.value}")
                    
                    if endpoint.content_type:
                        print(f"   Content Type: {endpoint.content_type}")
                    
                    print("-" * 60)
            else:
                print("\nNo API endpoints found in the source code.")
                print("This might be because:")
                print("- The code doesn't contain API routes")
                print("- The framework patterns are not recognized")
                print("- The files are not in a supported format")
            
            # Show language and framework detection
            if parser.language_detected:
                print(f"\n{'='*60}")
                print("Detection Results:")
                print(f"{'='*60}")
                print(f"Language: {parser.language_detected}")
                print(f"Framework: {parser.framework_detected}")
            
            # Show configuration files
            config_files = parser.get_config_files()
            if config_files:
                print(f"\n{'='*60}")
                print("Configuration Files:")
                print(f"{'='*60}")
                for file_name, config_data in config_files.items():
                    print(f"{file_name}: {len(config_data)} items")
            
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
            print(f"Error parsing source code: {e}")
    
    main() 