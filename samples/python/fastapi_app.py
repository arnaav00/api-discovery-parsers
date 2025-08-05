from fastapi import FastAPI, HTTPException, Depends, Query, Path, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
import uvicorn

app = FastAPI(title="Sample API", version="1.0.0")
security = HTTPBearer()

# Pydantic models
class User(BaseModel):
    id: Optional[int] = None
    name: str = Field(..., min_length=1, max_length=100)
    email: str = Field(..., regex=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    age: Optional[int] = Field(None, ge=0, le=150)
    active: bool = True

class Product(BaseModel):
    id: Optional[int] = None
    name: str = Field(..., min_length=1, max_length=200)
    price: float = Field(..., gt=0)
    category: str
    in_stock: bool = True

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    token: str
    user: User

# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials.credentials:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"user_id": 1, "username": "test_user"}

# User endpoints
@app.get("/api/users", response_model=List[User])
async def get_users(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(10, ge=1, le=100, description="Items per page"),
    current_user: dict = Depends(get_current_user)
):
    """Get all users with pagination"""
    return [
        User(id=1, name="John Doe", email="john@example.com", age=30),
        User(id=2, name="Jane Smith", email="jane@example.com", age=25)
    ]

@app.get("/api/users/{user_id}", response_model=User)
async def get_user(
    user_id: int = Path(..., description="User ID"),
    current_user: dict = Depends(get_current_user)
):
    """Get user by ID"""
    return User(id=user_id, name="John Doe", email="john@example.com", age=30)

@app.post("/api/users", response_model=User, status_code=201)
async def create_user(
    user: User = Body(..., description="User data"),
    current_user: dict = Depends(get_current_user)
):
    """Create a new user"""
    user.id = 1
    return user

@app.put("/api/users/{user_id}", response_model=User)
async def update_user(
    user_id: int = Path(..., description="User ID"),
    user: User = Body(..., description="Updated user data"),
    current_user: dict = Depends(get_current_user)
):
    """Update user by ID"""
    user.id = user_id
    return user

@app.delete("/api/users/{user_id}", status_code=204)
async def delete_user(
    user_id: int = Path(..., description="User ID"),
    current_user: dict = Depends(get_current_user)
):
    """Delete user by ID"""
    return None

# Product endpoints
@app.get("/api/products", response_model=List[Product])
async def get_products(
    category: Optional[str] = Query(None, description="Filter by category"),
    min_price: Optional[float] = Query(None, ge=0, description="Minimum price"),
    max_price: Optional[float] = Query(None, ge=0, description="Maximum price")
):
    """Get all products with optional filtering"""
    return [
        Product(id=1, name="Laptop", price=999.99, category="electronics"),
        Product(id=2, name="Phone", price=599.99, category="electronics")
    ]

@app.get("/api/products/{product_id}", response_model=Product)
async def get_product(product_id: int = Path(..., description="Product ID")):
    """Get product by ID"""
    return Product(id=product_id, name="Laptop", price=999.99, category="electronics")

@app.post("/api/products", response_model=Product, status_code=201)
async def create_product(
    product: Product = Body(..., description="Product data"),
    current_user: dict = Depends(get_current_user)
):
    """Create a new product"""
    product.id = 1
    return product

@app.put("/api/products/{product_id}", response_model=Product)
async def update_product(
    product_id: int = Path(..., description="Product ID"),
    product: Product = Body(..., description="Updated product data"),
    current_user: dict = Depends(get_current_user)
):
    """Update product by ID"""
    product.id = product_id
    return product

@app.delete("/api/products/{product_id}", status_code=204)
async def delete_product(
    product_id: int = Path(..., description="Product ID"),
    current_user: dict = Depends(get_current_user)
):
    """Delete product by ID"""
    return None

# Authentication endpoints
@app.post("/api/auth/login", response_model=LoginResponse)
async def login(login_data: LoginRequest = Body(..., description="Login credentials")):
    """Authenticate user and return token"""
    return LoginResponse(
        token="jwt-token-here",
        user=User(id=1, name="John Doe", email="john@example.com")
    )

@app.post("/api/auth/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """Logout user"""
    return {"message": "Logged out successfully"}

@app.post("/api/auth/refresh")
async def refresh_token(
    refresh_token: str = Body(..., embed=True, description="Refresh token")
):
    """Refresh authentication token"""
    return {"token": "new-jwt-token"}

# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }

# Documentation
@app.get("/docs")
async def get_docs():
    """Get API documentation"""
    return {
        "title": "Sample API",
        "version": "1.0.0",
        "endpoints": [
            {"path": "/api/users", "method": "GET"},
            {"path": "/api/users/{user_id}", "method": "GET"},
            {"path": "/api/users", "method": "POST"}
        ]
    }

# Admin endpoints
@app.get("/admin/users")
async def admin_get_users(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user)
):
    """Admin endpoint to get all users"""
    return {
        "users": [],
        "total": 100,
        "page": page,
        "limit": limit
    }

@app.get("/admin/stats")
async def admin_get_stats(current_user: dict = Depends(get_current_user)):
    """Admin endpoint to get system statistics"""
    return {
        "total_users": 1000,
        "active_users": 750,
        "total_products": 500
    }

# Search endpoint
@app.get("/api/search")
async def search(
    q: str = Query(..., description="Search query"),
    type: Optional[str] = Query(None, description="Search type"),
    limit: int = Query(10, ge=1, le=100, description="Maximum results")
):
    """Search across all entities"""
    return {
        "query": q,
        "type": type,
        "results": [],
        "total": 0
    }

# File upload
@app.post("/api/upload")
async def upload_file(
    file: str = Body(..., description="File content"),
    description: Optional[str] = Body(None, description="File description"),
    current_user: dict = Depends(get_current_user)
):
    """Upload a file"""
    return {
        "id": "file-123",
        "filename": file,
        "description": description,
        "uploaded_at": datetime.now().isoformat()
    }

# Webhook endpoint
@app.post("/api/webhooks/github")
async def github_webhook(
    event: str = Body(..., embed=True),
    payload: dict = Body(..., embed=True)
):
    """Handle GitHub webhooks"""
    return {"received": True, "event": event}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000) 