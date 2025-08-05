package com.example.api.controller;

import com.example.api.model.User;
import com.example.api.model.Product;
import com.example.api.model.LoginRequest;
import com.example.api.model.LoginResponse;
import com.example.api.service.UserService;
import com.example.api.service.ProductService;
import com.example.api.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import javax.validation.constraints.Min;
import javax.validation.constraints.Max;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Email;
import java.util.List;
import java.util.Optional;
import java.util.Map;

@RestController
@RequestMapping("/api")
@Validated
public class ApiController {

    @Autowired
    private UserService userService;

    @Autowired
    private ProductService productService;

    @Autowired
    private AuthService authService;

    // User endpoints
    @GetMapping("/users")
    public ResponseEntity<Page<User>> getUsers(
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "10") @Min(1) @Max(100) int size,
            @RequestParam(required = false) String name,
            @RequestParam(required = false) @Email String email
    ) {
        Pageable pageable = PageRequest.of(page, size);
        Page<User> users = userService.findUsers(name, email, pageable);
        return ResponseEntity.ok(users);
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<User> getUser(@PathVariable @Min(1) Long id) {
        Optional<User> user = userService.findById(id);
        return user.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/users")
    public ResponseEntity<User> createUser(@Valid @RequestBody User user) {
        User createdUser = userService.createUser(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdUser);
    }

    @PutMapping("/users/{id}")
    public ResponseEntity<User> updateUser(
            @PathVariable @Min(1) Long id,
            @Valid @RequestBody User user
    ) {
        Optional<User> updatedUser = userService.updateUser(id, user);
        return updatedUser.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable @Min(1) Long id) {
        boolean deleted = userService.deleteUser(id);
        return deleted ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    // Product endpoints
    @GetMapping("/products")
    public ResponseEntity<Page<Product>> getProducts(
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "10") @Min(1) @Max(100) int size,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) @Min(0) Double minPrice,
            @RequestParam(required = false) @Min(0) Double maxPrice
    ) {
        Pageable pageable = PageRequest.of(page, size);
        Page<Product> products = productService.findProducts(category, minPrice, maxPrice, pageable);
        return ResponseEntity.ok(products);
    }

    @GetMapping("/products/{id}")
    public ResponseEntity<Product> getProduct(@PathVariable @Min(1) Long id) {
        Optional<Product> product = productService.findById(id);
        return product.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/products")
    public ResponseEntity<Product> createProduct(@Valid @RequestBody Product product) {
        Product createdProduct = productService.createProduct(product);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdProduct);
    }

    @PutMapping("/products/{id}")
    public ResponseEntity<Product> updateProduct(
            @PathVariable @Min(1) Long id,
            @Valid @RequestBody Product product
    ) {
        Optional<Product> updatedProduct = productService.updateProduct(id, product);
        return updatedProduct.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/products/{id}")
    public ResponseEntity<Void> deleteProduct(@PathVariable @Min(1) Long id) {
        boolean deleted = productService.deleteProduct(id);
        return deleted ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    // Authentication endpoints
    @PostMapping("/auth/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
        LoginResponse response = authService.login(loginRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<Void> logout() {
        authService.logout();
        return ResponseEntity.ok().build();
    }

    @PostMapping("/auth/refresh")
    public ResponseEntity<LoginResponse> refreshToken(@RequestParam @NotBlank String refreshToken) {
        LoginResponse response = authService.refreshToken(refreshToken);
        return ResponseEntity.ok(response);
    }

    // Health check
    @GetMapping("/health")
    public ResponseEntity<Object> healthCheck() {
        return ResponseEntity.ok(Map.of(
            "status", "healthy",
            "timestamp", java.time.LocalDateTime.now().toString(),
            "version", "1.0.0"
        ));
    }

    // Documentation
    @GetMapping("/docs")
    public ResponseEntity<Object> getDocs() {
        return ResponseEntity.ok(Map.of(
            "title", "Sample API",
            "version", "1.0.0",
            "endpoints", List.of(
                Map.of("path", "/api/users", "method", "GET"),
                Map.of("path", "/api/users/{id}", "method", "GET"),
                Map.of("path", "/api/users", "method", "POST")
            )
        ));
    }

    // Admin endpoints
    @GetMapping("/admin/users")
    public ResponseEntity<Page<User>> adminGetUsers(
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size
    ) {
        Pageable pageable = PageRequest.of(page, size);
        Page<User> users = userService.findAllUsers(pageable);
        return ResponseEntity.ok(users);
    }

    @GetMapping("/admin/stats")
    public ResponseEntity<Object> adminGetStats() {
        return ResponseEntity.ok(Map.of(
            "totalUsers", userService.countUsers(),
            "activeUsers", userService.countActiveUsers(),
            "totalProducts", productService.countProducts()
        ));
    }

    // Search endpoint
    @GetMapping("/search")
    public ResponseEntity<Object> search(
            @RequestParam @NotBlank String q,
            @RequestParam(required = false) String type,
            @RequestParam(defaultValue = "10") @Min(1) @Max(100) int limit
    ) {
        List<Object> results = userService.search(q, type, limit);
        return ResponseEntity.ok(Map.of(
            "query", q,
            "type", type,
            "results", results,
            "total", results.size()
        ));
    }

    // File upload
    @PostMapping("/upload")
    public ResponseEntity<Object> uploadFile(
            @RequestParam @NotBlank String file,
            @RequestParam(required = false) String description
    ) {
        return ResponseEntity.ok(Map.of(
            "id", "file-123",
            "filename", file,
            "description", description,
            "uploadedAt", java.time.LocalDateTime.now().toString()
        ));
    }

    // Webhook endpoint
    @PostMapping("/webhooks/github")
    public ResponseEntity<Object> githubWebhook(
            @RequestParam @NotBlank String event,
            @RequestBody Object payload
    ) {
        return ResponseEntity.ok(Map.of(
            "received", true,
            "event", event
        ));
    }

    // User profile endpoint
    @GetMapping("/users/me")
    public ResponseEntity<User> getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        Optional<User> user = userService.findByUsername(username);
        return user.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // Product search endpoint
    @GetMapping("/products/search")
    public ResponseEntity<List<Product>> searchProducts(
            @RequestParam @NotBlank String q,
            @RequestParam(defaultValue = "10") @Min(1) @Max(100) int limit
    ) {
        List<Product> products = productService.searchProducts(q, limit);
        return ResponseEntity.ok(products);
    }

    // Category endpoints
    @GetMapping("/categories")
    public ResponseEntity<List<String>> getCategories() {
        List<String> categories = productService.getAllCategories();
        return ResponseEntity.ok(categories);
    }

    @GetMapping("/categories/{category}/products")
    public ResponseEntity<Page<Product>> getProductsByCategory(
            @PathVariable @NotBlank String category,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "10") @Min(1) @Max(100) int size
    ) {
        Pageable pageable = PageRequest.of(page, size);
        Page<Product> products = productService.findByCategory(category, pageable);
        return ResponseEntity.ok(products);
    }

    // Order endpoints
    @PostMapping("/orders")
    public ResponseEntity<Object> createOrder(@Valid @RequestBody Object orderRequest) {
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
            "id", "order-123",
            "status", "created",
            "createdAt", java.time.LocalDateTime.now().toString()
        ));
    }

    @GetMapping("/orders/{id}")
    public ResponseEntity<Object> getOrder(@PathVariable @NotBlank String id) {
        return ResponseEntity.ok(Map.of(
            "id", id,
            "status", "processing",
            "items", List.of()
        ));
    }

    // Payment endpoints
    @PostMapping("/payments")
    public ResponseEntity<Object> processPayment(@Valid @RequestBody Object paymentRequest) {
        return ResponseEntity.ok(Map.of(
            "id", "payment-123",
            "status", "completed",
            "amount", 99.99
        ));
    }

    // Notification endpoints
    @PostMapping("/notifications")
    public ResponseEntity<Object> sendNotification(@Valid @RequestBody Object notificationRequest) {
        return ResponseEntity.ok(Map.of(
            "id", "notification-123",
            "status", "sent",
            "recipient", "user@example.com"
        ));
    }

    // Analytics endpoints
    @GetMapping("/analytics/users")
    public ResponseEntity<Object> getUserAnalytics(
            @RequestParam(required = false) String period,
            @RequestParam(required = false) String metric
    ) {
        return ResponseEntity.ok(Map.of(
            "period", period,
            "metric", metric,
            "data", List.of()
        ));
    }

    @GetMapping("/analytics/products")
    public ResponseEntity<Object> getProductAnalytics(
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String period
    ) {
        return ResponseEntity.ok(Map.of(
            "category", category,
            "period", period,
            "data", List.of()
        ));
    }
} 