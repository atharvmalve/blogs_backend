import os
import re
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from supabase import create_client, Client
from postgrest.exceptions import APIError
import json

# ==========================================
# 1. CONFIGURATION & ENVIRONMENT VARIABLES
# ==========================================

class Settings(BaseSettings):
    SUPABASE_URL: str
    SUPABASE_KEY: str
    
    ADMIN_USERNAME: str
    ADMIN_PASSWORD: str
    
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_HOURS: int = 24

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

# Initialize settings
settings = Settings()

# Initialize FastAPI App
app = FastAPI(
    title="Minimal Blog Backend",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
origins = [
    "http://localhost:3000",
    "https://atharvmalve.vercel.app"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# 2. PYDANTIC SCHEMAS
# ==========================================

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class BlogCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    content: str  # Markdown content accepted natively
    youtube_url: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    published: bool = False

class BlogUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    youtube_url: Optional[str] = None
    tags: Optional[List[str]] = None
    published: Optional[bool] = None

class BlogResponse(BaseModel):
    id: str
    title: str
    slug: str
    content: str
    youtube_url: Optional[str] = None
    tags: List[str]
    published: bool
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ==========================================
# 3. SUPABASE CLIENT & DB HELPERS
# ==========================================

# Initialize Supabase client
supabase: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)




def sanitize_db_output(data):
    """
    Explicitly forces stringified tags from Supabase/Postgres 
    into real Python lists before FastAPI processes the response.
    """
    if data is None:
        return data
        
    # If it's a list of blogs (like a GET all feed)
    if isinstance(data, list):
        return [sanitize_db_output(item) for item in data]
        
    # If it's a single blog dictionary
    if isinstance(data, dict) and "tags" in data:
        tags_val = data["tags"]
        if isinstance(tags_val, str):
            try:
                # Handles '["product", "startup"]'
                data["tags"] = json.loads(tags_val)
            except json.JSONDecodeError:
                # Fallback for Postgres native bracket array strings like '{product,startup}'
                if tags_val.startswith('{') and tags_val.endswith('}'):
                    data["tags"] = [t.strip('" ') for t in tags_val[1:-1].split(',') if t.strip()]
                else:
                    data["tags"] = [tags_val] if tags_val else []
                    
    return data
def generate_slug(title: str) -> str:
    """Generates a clean, URL-safe slug from a title string."""
    slug = title.lower()
    slug = re.sub(r'[^a-z0-9\s-]', '', slug)  # Remove non-alphanumeric chars
    slug = re.sub(r'[\s-]+', '-', slug)       # Replace spaces and multiple hyphens with a single hyphen
    return slug.strip('-')


# ==========================================
# 4. AUTHENTICATION & DEPENDENCIES
# ==========================================

security_agent = HTTPBearer()

def create_access_token(username: str) -> str:
    """Generates a JWT token valid for the configured expiration period."""
    expire = datetime.now(timezone.utc) + timedelta(hours=settings.JWT_EXPIRE_HOURS)
    to_encode = {"sub": username, "exp": expire}
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def get_current_admin(credentials: HTTPAuthorizationCredentials = Depends(security_agent)) -> str:
    """Dependency injection to protect admin routes. Validates incoming JWT."""
    token = credentials.credentials
    exception_unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username != settings.ADMIN_USERNAME:
            raise exception_unauthorized
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.PyJWTError:
        raise exception_unauthorized


# ==========================================
# 5. PUBLIC ROUTES
# ==========================================

@app.get("/blogs", response_model=List[BlogResponse])
def get_all_public_blogs(tag: Optional[str] = None):
    """Fetches all published blogs. Optional filtering by tag."""
    try:
        query = supabase.table("blogs").select("*").eq("published", True)
        
        if tag:
            # Postgrest syntax to check if an array contains a value
            query = query.contains("tags", [tag])
            
        # Sort public feeds by newest first
        query = query.order("created_at", desc=True)
        
        response = query.execute()
        return sanitize_db_output(response.data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/blogs/{slug}", response_model=BlogResponse)
def get_blog_by_slug(slug: str):
    """Fetches a single published blog by its unique slug."""
    try:
        response = supabase.table("blogs").select("*").eq("slug", slug).eq("published", True).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Blog post not found")
        return sanitize_db_output(response.data[0])
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


# ==========================================
# 6. ADMIN ROUTES
# ==========================================

@app.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    """Validates single admin credentials against env values and issues a JWT."""
    if payload.username != settings.ADMIN_USERNAME or payload.password != settings.ADMIN_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    token = create_access_token(username=payload.username)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/admin/blogs", response_model=List[BlogResponse])
def get_admin_blogs(current_admin: str = Depends(get_current_admin)):
    """Admin dashboard feed returning drafts, published items, ordered newest first."""
    try:
        response = supabase.table("blogs").select("*").order("created_at", desc=True).execute()
        return sanitize_db_output(response.data[0])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.post("/admin/blogs", response_model=BlogResponse, status_code=status.HTTP_201_CREATED)
def create_blog(blog: BlogCreate, current_admin: str = Depends(get_current_admin)):
    """Creates a new blog post. Automatically formats and assigns slugs."""
    generated_slug = generate_slug(blog.title)
    
    blog_data = blog.model_dump()
    blog_data["slug"] = generated_slug
    
    try:
        response = supabase.table("blogs").insert(blog_data).execute()
        return sanitize_db_output(response.data[0])
    except APIError as e:
        # Check for unique constraint violation error code in PostgreSQL (23505)
        if e.code == "23505":
            raise HTTPException(status_code=400, detail="A blog post with this title or slug already exists.")
        raise HTTPException(status_code=500, detail=e.message)


@app.put("/admin/blogs/{id}", response_model=BlogResponse)
def update_blog(id: str, blog: BlogUpdate, current_admin: str = Depends(get_current_admin)):
    """Updates an existing blog entry and enforces updated_at tracking."""
    # Exclude non-provided fields
    update_data = blog.model_dump(exclude_unset=True)
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields provided to update")
    
    # Recalculate slug if title is modified
    if "title" in update_data:
        update_data["slug"] = generate_slug(update_data["title"])
        
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    
    try:
        response = supabase.table("blogs").update(update_data).eq("id", id).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Blog post not found to update")
        return sanitize_db_output(response.data[0])
    except APIError as e:
        if e.code == "23505":
            raise HTTPException(status_code=400, detail="Updating this title conflicts with an existing slug.")
        raise HTTPException(status_code=500, detail=e.message)


@app.delete("/admin/blogs/{id}", status_code=status.HTTP_200_OK)
def delete_blog(id: str, current_admin: str = Depends(get_current_admin)):
    """Executes a hard delete for a blog record matching the target ID."""
    try:
        response = supabase.table("blogs").delete().eq("id", id).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Blog post not found to delete")
        return {"detail": "Blog post successfully deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


# ==========================================
# 7. EXECUTION
# ==========================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)