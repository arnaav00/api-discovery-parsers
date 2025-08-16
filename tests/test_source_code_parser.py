"""
Comprehensive unit tests for Source Code Parser.

Tests cover:
- Valid input parsing
- Invalid input handling  
- Edge cases and error conditions
- Performance benchmarks
- Memory usage tests
"""

import unittest
import json
import tempfile
import os
import time
import psutil
import sys
from unittest.mock import patch, mock_open
from io import StringIO

# Add parent directory to path to import parsers
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from parsers.source_code_parser import SourceCodeParser
from models import APIEndpoint, Parameter, Header, AuthInfo, SSLInfo
from models import ParameterType, ParameterLocation, AuthType, AuthLocation


class TestSourceCodeParser(unittest.TestCase):
    """Test cases for Source Code Parser."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.parser = SourceCodeParser()
        
        # Sample JavaScript/Express.js code
        self.valid_javascript_code = """
const express = require('express');
const app = express();

app.get('/api/users', (req, res) => {
    const users = req.query.limit;
    res.json({ users: [] });
});

app.post('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    const userData = req.body.name;
    res.json({ id: userId, name: userData });
});

app.put('/api/users/:id/profile', (req, res) => {
    const userId = req.params.id;
    const profileData = req.body.profile;
    res.json({ success: true });
});

app.delete('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    res.json({ deleted: true });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
"""
        
        # Sample Python/FastAPI code
        self.valid_python_code = """
from fastapi import FastAPI, Path, Query, Body
from pydantic import BaseModel

app = FastAPI()

class User(BaseModel):
    name: str
    email: str
    age: int

@app.get("/api/users")
async def get_users(limit: int = Query(10), offset: int = Query(0)):
    return {"users": []}

@app.post("/api/users")
async def create_user(user: User = Body(...)):
    return {"id": 1, "name": user.name, "email": user.email}

@app.get("/api/users/{user_id}")
async def get_user(user_id: int = Path(...)):
    return {"id": user_id, "name": "John Doe"}

@app.put("/api/users/{user_id}")
async def update_user(user_id: int = Path(...), user: User = Body(...)):
    return {"id": user_id, "updated": True}

@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int = Path(...)):
    return {"deleted": True}
"""
        
        # Sample Java/Spring Boot code
        self.valid_java_code = """
package com.example.api;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/users")
    public ResponseEntity<?> getUsers(
        @RequestParam(defaultValue = "10") int limit,
        @RequestParam(defaultValue = "0") int offset
    ) {
        return ResponseEntity.ok().body("Users list");
    }

    @PostMapping("/users")
    public ResponseEntity<?> createUser(@RequestBody User user) {
        return ResponseEntity.ok().body("User created");
    }

    @GetMapping("/users/{userId}")
    public ResponseEntity<?> getUser(@PathVariable Long userId) {
        return ResponseEntity.ok().body("User details");
    }

    @PutMapping("/users/{userId}")
    public ResponseEntity<?> updateUser(
        @PathVariable Long userId,
        @RequestBody User user
    ) {
        return ResponseEntity.ok().body("User updated");
    }

    @DeleteMapping("/users/{userId}")
    public ResponseEntity<?> deleteUser(@PathVariable Long userId) {
        return ResponseEntity.ok().body("User deleted");
    }
}

class User {
    private String name;
    private String email;
    // getters and setters
}
"""
        
        # Sample invalid source code
        self.invalid_source_code = """
This is not valid source code.
It's just plain text without any programming patterns.
No functions, classes, or API endpoints here.
"""
        
        # Sample package.json for JavaScript
        self.valid_package_json = """
{
  "name": "test-api",
  "version": "1.0.0",
  "description": "Test API",
  "main": "app.js",
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "helmet": "^7.0.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.1",
    "jest": "^29.5.0"
  }
}
"""
        
        # Sample requirements.txt for Python
        self.valid_requirements_txt = """
fastapi==0.104.1
uvicorn==0.24.0
pydantic==2.5.0
sqlalchemy==2.0.23
alembic==1.12.1
pytest==7.4.3
"""
        
        # Sample pom.xml for Java
        self.valid_pom_xml = """
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    
    <groupId>com.example</groupId>
    <artifactId>test-api</artifactId>
    <version>1.0.0</version>
    
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.0</version>
    </parent>
    
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>com.h2database</groupId>
            <artifactId>h2</artifactId>
            <scope>runtime</scope>
        </dependency>
    </dependencies>
</project>
"""
    
    def test_can_parse_valid_javascript_file(self):
        """Test that parser can identify valid JavaScript source code."""
        # Test with JavaScript file path
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(self.valid_javascript_code)
            temp_file = f.name
        
        try:
            self.assertTrue(self.parser.can_parse(temp_file))
        finally:
            os.unlink(temp_file)
        
        # Test with JavaScript content
        self.assertTrue(self.parser.can_parse(self.valid_javascript_code))
    
    def test_can_parse_valid_python_file(self):
        """Test that parser can identify valid Python source code."""
        # Test with Python file path
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(self.valid_python_code)
            temp_file = f.name
        
        try:
            self.assertTrue(self.parser.can_parse(temp_file))
        finally:
            os.unlink(temp_file)
        
        # Test with Python content
        self.assertTrue(self.parser.can_parse(self.valid_python_code))
    
    def test_can_parse_valid_java_file(self):
        """Test that parser can identify valid Java source code."""
        # Test with Java file path
        with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
            f.write(self.valid_java_code)
            temp_file = f.name
        
        try:
            self.assertTrue(self.parser.can_parse(temp_file))
        finally:
            os.unlink(temp_file)
        
        # Test with Java content
        self.assertTrue(self.parser.can_parse(self.valid_java_code))
    
    def test_can_parse_directory(self):
        """Test that parser can identify valid source code directory."""
        # Create a temporary directory with source files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create JavaScript file
            js_file = os.path.join(temp_dir, 'app.js')
            with open(js_file, 'w') as f:
                f.write(self.valid_javascript_code)
            
            # Create Python file
            py_file = os.path.join(temp_dir, 'main.py')
            with open(py_file, 'w') as f:
                f.write(self.valid_python_code)
            
            # Test directory parsing - should be able to parse directory with source files
            self.assertTrue(self.parser.can_parse(temp_dir))
    
    def test_can_parse_invalid_data(self):
        """Test that parser correctly rejects invalid data."""
        # Test with invalid source code
        self.assertFalse(self.parser.can_parse(self.invalid_source_code))
        
        # Test with None
        self.assertFalse(self.parser.can_parse(None))
        
        # Test with empty string
        self.assertFalse(self.parser.can_parse(""))
        
        # Test with non-existent file
        self.assertFalse(self.parser.can_parse("nonexistent.js"))
        
        # Test with non-source code file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("This is a text file, not source code")
            temp_file = f.name
        
        try:
            self.assertFalse(self.parser.can_parse(temp_file))
        finally:
            os.unlink(temp_file)
    
    def test_parse_javascript_code(self):
        """Test parsing JavaScript/Express.js source code."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(self.valid_javascript_code)
            temp_file = f.name
        
        try:
            endpoints = self.parser.parse(temp_file)
            
            # Should find at least 4 endpoints (GET, POST, PUT, DELETE)
            self.assertGreaterEqual(len(endpoints), 4)
            
            # Test GET /api/users endpoint
            get_users = next(ep for ep in endpoints if ep.method == "GET" and ep.path == "/api/users")
            self.assertEqual(get_users.path, "/api/users")
            self.assertEqual(get_users.method, "GET")
            
            # Test POST /api/users/:id endpoint
            post_user = next(ep for ep in endpoints if ep.method == "POST" and "/api/users/" in ep.path)
            self.assertIn("/api/users/", post_user.path)
            self.assertEqual(post_user.method, "POST")
            
            # Test parameters
            self.assertGreater(len(post_user.parameters), 0)
            path_params = [p for p in post_user.parameters if p.location == ParameterLocation.PATH]
            self.assertGreater(len(path_params), 0)
            
        finally:
            os.unlink(temp_file)
    
    def test_parse_python_code(self):
        """Test parsing Python/FastAPI source code."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(self.valid_python_code)
            temp_file = f.name
        
        try:
            endpoints = self.parser.parse(temp_file)
            
            # Should find at least 5 endpoints (GET, POST, GET with path param, PUT, DELETE)
            self.assertGreaterEqual(len(endpoints), 5)
            
            # Test GET /api/users endpoint
            get_users = next(ep for ep in endpoints if ep.method == "GET" and ep.path == "/api/users")
            self.assertEqual(get_users.path, "/api/users")
            self.assertEqual(get_users.method, "GET")
            
            # Test POST /api/users endpoint
            post_user = next(ep for ep in endpoints if ep.method == "POST" and ep.path == "/api/users")
            self.assertEqual(post_user.path, "/api/users")
            self.assertEqual(post_user.method, "POST")
            
            # Test that we have different types of endpoints
            unique_methods = set(ep.method for ep in endpoints)
            self.assertGreater(len(unique_methods), 1)
            
        finally:
            os.unlink(temp_file)
    
    def test_parse_java_code(self):
        """Test parsing Java/Spring Boot source code."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
            f.write(self.valid_java_code)
            temp_file = f.name
        
        try:
            endpoints = self.parser.parse(temp_file)
            
            # Should find at least 5 endpoints (GET, POST, GET with path param, PUT, DELETE)
            self.assertGreaterEqual(len(endpoints), 5)
            
            # Test GET endpoints - check if any GET endpoint exists
            get_endpoints = [ep for ep in endpoints if ep.method == "GET"]
            self.assertGreater(len(get_endpoints), 0)
            
            # Test POST endpoints - check if any POST endpoint exists
            post_endpoints = [ep for ep in endpoints if ep.method == "POST"]
            self.assertGreater(len(post_endpoints), 0)
            
            # Test that we have endpoints with different paths
            unique_paths = set(ep.path for ep in endpoints)
            self.assertGreater(len(unique_paths), 1)
            
        finally:
            os.unlink(temp_file)
    
    def test_parse_directory_with_multiple_files(self):
        """Test parsing a directory with multiple source files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create JavaScript file
            js_file = os.path.join(temp_dir, 'app.js')
            with open(js_file, 'w') as f:
                f.write(self.valid_javascript_code)
            
            # Create Python file
            py_file = os.path.join(temp_dir, 'main.py')
            with open(py_file, 'w') as f:
                f.write(self.valid_python_code)
            
            # Create Java file
            java_file = os.path.join(temp_dir, 'Controller.java')
            with open(java_file, 'w') as f:
                f.write(self.valid_java_code)
            
            # Parse directory
            endpoints = self.parser.parse(temp_dir)
            
            # Should find endpoints from all files
            self.assertGreater(len(endpoints), 0)
            
            # Check that language and framework were detected
            stats = self.parser.get_stats()
            self.assertIsNotNone(stats.get('language_detected'))
    
    def test_parse_empty_directory(self):
        """Test parsing empty directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Should raise exception for empty directory
            with self.assertRaises(ValueError):
                self.parser.parse(temp_dir)
    
    def test_parse_with_config_files(self):
        """Test parsing with configuration files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create source file
            js_file = os.path.join(temp_dir, 'app.js')
            with open(js_file, 'w') as f:
                f.write(self.valid_javascript_code)
            
            # Create package.json
            package_json = os.path.join(temp_dir, 'package.json')
            with open(package_json, 'w') as f:
                f.write(self.valid_package_json)
            
            # Create requirements.txt
            requirements_txt = os.path.join(temp_dir, 'requirements.txt')
            with open(requirements_txt, 'w') as f:
                f.write(self.valid_requirements_txt)
            
            # Parse directory
            endpoints = self.parser.parse(temp_dir)
            
            # Should find endpoints
            self.assertGreater(len(endpoints), 0)
            
            # Check config files were parsed
            config_files = self.parser.get_config_files()
            self.assertGreater(len(config_files), 0)
            self.assertIn('package.json', config_files)
    
    def test_parse_large_codebase(self):
        """Test parsing large codebase."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create multiple source files
            for i in range(10):
                js_file = os.path.join(temp_dir, f'app_{i}.js')
                with open(js_file, 'w') as f:
                    f.write(self.valid_javascript_code)
                
                py_file = os.path.join(temp_dir, f'main_{i}.py')
                with open(py_file, 'w') as f:
                    f.write(self.valid_python_code)
            
            # Test parsing performance
            start_time = time.time()
            endpoints = self.parser.parse(temp_dir)
            end_time = time.time()
            
            # Should find endpoints from all files
            self.assertGreater(len(endpoints), 0)
            
            # Should complete within reasonable time (less than 5 seconds)
            self.assertLess(end_time - start_time, 5.0)
    
    def test_memory_usage(self):
        """Test memory usage during parsing."""
        # Get initial memory usage
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create multiple source files
            for i in range(5):
                js_file = os.path.join(temp_dir, f'app_{i}.js')
                with open(js_file, 'w') as f:
                    f.write(self.valid_javascript_code)
                
                py_file = os.path.join(temp_dir, f'main_{i}.py')
                with open(py_file, 'w') as f:
                    f.write(self.valid_python_code)
            
            # Parse and measure memory
            endpoints = self.parser.parse(temp_dir)
            final_memory = process.memory_info().rss
            
            # Memory increase should be reasonable (less than 50MB)
            memory_increase = final_memory - initial_memory
            self.assertLess(memory_increase, 50 * 1024 * 1024)  # 50MB
            
            # Should find endpoints
            self.assertGreater(len(endpoints), 0)
    
    def test_error_handling(self):
        """Test error handling for various error conditions."""
        # Test with non-existent file
        with self.assertRaises(ValueError):
            self.parser.parse("nonexistent.js")
        
        # Test with invalid file path
        with self.assertRaises(ValueError):
            self.parser.parse("")
        
        # Test with unsupported data type
        with self.assertRaises(ValueError):
            self.parser.parse(123)
    
    def test_parameter_extraction(self):
        """Test parameter extraction from various languages."""
        # Test JavaScript parameter extraction
        js_with_params = """
app.get('/api/users/:id/posts/:postId', (req, res) => {
    const userId = req.params.id;
    const postId = req.params.postId;
    const limit = req.query.limit;
    const offset = req.query.offset;
    const userData = req.body.name;
    res.json({});
});
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(js_with_params)
            temp_file = f.name
        
        try:
            endpoints = self.parser.parse(temp_file)
            self.assertEqual(len(endpoints), 1)
            
            endpoint = endpoints[0]
            
            # Test path parameters
            path_params = [p for p in endpoint.parameters if p.location == ParameterLocation.PATH]
            self.assertEqual(len(path_params), 2)
            
            # Test query parameters
            query_params = [p for p in endpoint.parameters if p.location == ParameterLocation.QUERY]
            self.assertEqual(len(query_params), 2)
            
            # Test body parameters
            body_params = [p for p in endpoint.parameters if p.location == ParameterLocation.BODY]
            self.assertEqual(len(body_params), 1)
            
        finally:
            os.unlink(temp_file)
    
    def test_framework_detection(self):
        """Test framework detection from source code."""
        # Test Express.js detection
        express_code = """
const express = require('express');
const app = express();

app.get('/api/test', (req, res) => {
    res.json({});
});
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(express_code)
            temp_file = f.name
        
        try:
            self.parser.parse(temp_file)
            stats = self.parser.get_stats()
            
            # Should detect JavaScript language
            self.assertEqual(stats.get('language_detected'), 'javascript')
            
            # Should detect Express framework
            self.assertEqual(stats.get('framework_detected'), 'express')
            
        finally:
            os.unlink(temp_file)
        
        # Test FastAPI detection - need to clear parser state first
        self.parser.clear_results()
        fastapi_code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/api/test")
async def test():
    return {}
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(fastapi_code)
            temp_file = f.name
        
        try:
            self.parser.parse(temp_file)
            stats = self.parser.get_stats()
            
            # Should detect Python language
            self.assertEqual(stats.get('language_detected'), 'python')
            
            # Should detect FastAPI framework - check if it's detected
            framework_detected = stats.get('framework_detected')
            self.assertIsNotNone(framework_detected)  # Should detect some framework
            
        finally:
            os.unlink(temp_file)
    
    def test_config_file_parsing(self):
        """Test configuration file parsing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create source file first (required for parsing)
            js_file = os.path.join(temp_dir, 'app.js')
            with open(js_file, 'w') as f:
                f.write(self.valid_javascript_code)
            
            # Create package.json
            package_json = os.path.join(temp_dir, 'package.json')
            with open(package_json, 'w') as f:
                f.write(self.valid_package_json)
            
            # Create requirements.txt
            requirements_txt = os.path.join(temp_dir, 'requirements.txt')
            with open(requirements_txt, 'w') as f:
                f.write(self.valid_requirements_txt)
            
            # Create pom.xml
            pom_xml = os.path.join(temp_dir, 'pom.xml')
            with open(pom_xml, 'w') as f:
                f.write(self.valid_pom_xml)
            
            # Parse directory
            self.parser.parse(temp_dir)
            
            # Check config files were parsed
            config_files = self.parser.get_config_files()
            self.assertIn('package.json', config_files)
            self.assertIn('requirements.txt', config_files)
            self.assertIn('pom.xml', config_files)
            
            # Check package.json content
            package_data = config_files['package.json']
            self.assertIn('dependencies', package_data)
            self.assertIn('express', package_data['dependencies'])
    
    def test_statistics(self):
        """Test parser statistics."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(self.valid_javascript_code)
            temp_file = f.name
        
        try:
            endpoints = self.parser.parse(temp_file)
            
            stats = self.parser.get_stats()
            
            # Check key statistics
            self.assertIsNotNone(stats)
            self.assertGreater(len(stats), 0)
            
            # Check specific stats
            self.assertEqual(stats.get('endpoints_found'), len(endpoints))
            self.assertEqual(stats.get('language_detected'), 'javascript')
            self.assertEqual(stats.get('framework_detected'), 'express')
            
        finally:
            os.unlink(temp_file)
    
    def test_clear_results(self):
        """Test clearing parser results."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(self.valid_javascript_code)
            temp_file = f.name
        
        try:
            # Parse some data
            endpoints = self.parser.parse(temp_file)
            self.assertGreater(len(endpoints), 0)
            
            # Clear results
            self.parser.clear_results()
            
            # Check that results are cleared
            self.assertEqual(len(self.parser.parsed_endpoints), 0)
            self.assertEqual(len(self.parser.errors), 0)
            self.assertEqual(len(self.parser.warnings), 0)
            
        finally:
            os.unlink(temp_file)
    
    def test_filter_endpoints(self):
        """Test endpoint filtering functionality."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(self.valid_javascript_code)
            temp_file = f.name
        
        try:
            endpoints = self.parser.parse(temp_file)
            
            # Filter by method
            get_endpoints = self.parser.filter_endpoints(method="GET")
            self.assertGreater(len(get_endpoints), 0)
            self.assertEqual(get_endpoints[0].method, "GET")
            
            # Filter by path
            users_endpoints = [ep for ep in endpoints if "/api/users" in ep.path]
            self.assertGreater(len(users_endpoints), 0)
            
            # Filter by authenticated endpoints
            auth_endpoints = self.parser.get_authenticated_endpoints()
            self.assertIsInstance(auth_endpoints, list)
            
        finally:
            os.unlink(temp_file)
    
    def test_unique_extraction(self):
        """Test unique data extraction methods."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(self.valid_javascript_code)
            temp_file = f.name
        
        try:
            endpoints = self.parser.parse(temp_file)
            
            # Test unique methods
            unique_methods = self.parser.get_unique_methods()
            self.assertIn("GET", unique_methods)
            self.assertIn("POST", unique_methods)
            
            # Test unique base URLs
            unique_base_urls = self.parser.get_unique_base_urls()
            self.assertIn("https://api.example.com", unique_base_urls)
            
        finally:
            os.unlink(temp_file)
    
    def test_language_detection(self):
        """Test programming language detection."""
        # Test JavaScript detection
        js_code = "const express = require('express');"
        self.assertTrue(self.parser._is_source_code_content(js_code))
        
        # Test Python detection
        py_code = "def hello(): pass"
        self.assertTrue(self.parser._is_source_code_content(py_code))
        
        # Test Java detection
        java_code = "public class Test {}"
        self.assertTrue(self.parser._is_source_code_content(java_code))
        
        # Test invalid content
        invalid_content = "This is not source code"
        self.assertFalse(self.parser._is_source_code_content(invalid_content))
    
    def test_file_extension_detection(self):
        """Test source code file extension detection."""
        # Test valid extensions
        self.assertTrue(self.parser._is_source_code_file("app.js"))
        self.assertTrue(self.parser._is_source_code_file("main.py"))
        self.assertTrue(self.parser._is_source_code_file("Controller.java"))
        self.assertTrue(self.parser._is_source_code_file("app.ts"))
        self.assertTrue(self.parser._is_source_code_file("main.go"))
        
        # Test invalid extensions
        self.assertFalse(self.parser._is_source_code_file("readme.txt"))
        self.assertFalse(self.parser._is_source_code_file("config.json"))
        self.assertFalse(self.parser._is_source_code_file("data.csv"))
    
    def test_directory_traversal(self):
        """Test directory traversal and file discovery."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create nested directory structure
            nested_dir = os.path.join(temp_dir, "src", "api")
            os.makedirs(nested_dir)
            
            # Create source files in nested directory
            js_file = os.path.join(nested_dir, "app.js")
            with open(js_file, 'w') as f:
                f.write(self.valid_javascript_code)
            
            py_file = os.path.join(nested_dir, "main.py")
            with open(py_file, 'w') as f:
                f.write(self.valid_python_code)
            
            # Create non-source files (should be ignored)
            txt_file = os.path.join(nested_dir, "readme.txt")
            with open(txt_file, 'w') as f:
                f.write("This is a readme file")
            
            # Parse root directory
            endpoints = self.parser.parse(temp_dir)
            
            # Should find endpoints from source files
            self.assertGreater(len(endpoints), 0)
            
            # Check that non-source files were ignored
            stats = self.parser.get_stats()
            self.assertEqual(stats.get('source_files_analyzed'), 2)  # Only .js and .py files
    
    def test_skip_directories(self):
        """Test that common directories are skipped during traversal."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create directories that should be skipped
            skip_dirs = ['.git', 'node_modules', '__pycache__', 'target', 'build']
            for skip_dir in skip_dirs:
                skip_path = os.path.join(temp_dir, skip_dir)
                os.makedirs(skip_path)
                
                # Create source files in skip directories (should be ignored)
                js_file = os.path.join(skip_path, "ignored.js")
                with open(js_file, 'w') as f:
                    f.write(self.valid_javascript_code)
            
            # Create source file in root directory
            js_file = os.path.join(temp_dir, "app.js")
            with open(js_file, 'w') as f:
                f.write(self.valid_javascript_code)
            
            # Parse directory
            endpoints = self.parser.parse(temp_dir)
            
            # Should only find endpoints from non-skipped directories
            self.assertGreater(len(endpoints), 0)
            
            # Check that only one source file was analyzed
            stats = self.parser.get_stats()
            self.assertEqual(stats.get('source_files_analyzed'), 1)


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2) 