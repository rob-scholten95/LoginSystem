from fastapi import FastAPI, Depends, HTTPException, Request, Header, Security
from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
security = HTTPBearer()

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded

from prometheus_client import Counter, generate_latest
from starlette.responses import Response
from datetime import datetime, timedelta
from jose import JWTError, jwt
import bcrypt
from typing import Optional

import logging
logging.basicConfig(level=logging.INFO)



from generate_api_key import generate_api_key as genkey
import password_hashing as hash

from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException
from sqlalchemy_models import User, SessionLocal

from pydantic_schema import UserCreate, UserResponse


# Initialize FastAPI app
app = FastAPI()

# API key configuration
API_KEY = "apikey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

#------------------------------------------------ || CORS POLICY || -----------------------------------------
#Define CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # React frontend origin
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods (e.g., POST, GET)
    allow_headers=["*"],  # Allow all headers
)
#------------------------------------------------ || DATABASE || -----------------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
#------------------------------------------------ || ACCESS TOKENS || -----------------------------------------
#creating the access token
def create_access_token(data: dict):
    """Generate a JWT token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, API_KEY, algorithm=ALGORITHM)

#verifying the access token
def verify_access_token(token: str):
    try:
        payload = jwt.decode(token, API_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    api_key: str = Header(None, alias="X-API-KEY"),
    db: Session = Depends(get_db),
):
    # Validate JWT Token
    token = credentials.credentials
    if not verify_access_token(token):  # Replace with actual JWT validation logic
        raise HTTPException(status_code=401, detail="Invalid JWT token")

    # Validate API Key
    user = db.query(User).filter(User.api_key == api_key).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return user

#------------------------------------------------ || API CONFIG|| -----------------------------------------

api_key_header = APIKeyHeader(name="Authorization", auto_error=False)


# Initialize SlowAPI Limiter
limiter = Limiter(key_func=get_remote_address)

# Add SlowAPI Middleware
app.add_middleware(SlowAPIMiddleware)
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc):
    return Response("Too Many Requests", status_code=429)

# Metrics for monitoring
REQUEST_COUNT = Counter("request_count", "Total API Requests", ["method", "endpoint"])
 

        
        
#------------------------------------------------ || ENDPOINTS|| -----------------------------------------
#-------------------------------------------------------> Register endpoint -----------------------------------------
@app.post("/register")
async def register(user: UserCreate, db: Session = Depends(get_db)):
    # Check if user already exists
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    # Hash the password
    hashed_password = bcrypt.hashpw(user.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    # Add user to the database
    new_user = User(username=user.username, hashed_password=hashed_password,api_key=genkey(10))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": f"User {user.username} registered successfully"}
#-------------------------------------------------------> Print endpoint -----------------------------------------
@app.post("/access")
async def access(user: User = Depends(get_current_user)):
    return {"message": f"Access granted for user: {user.username}"}
   
#-------------------------------------------------------> Login endpoint -----------------------------------------
@app.post("/login")
async def login(user: UserCreate, db: Session = Depends(get_db)):
    # Fetch the user from the database
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not bcrypt.checkpw(user.password.encode("utf-8"), db_user.hashed_password.encode("utf-8")):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    
    # Generate a new API key and update the database
    if not db_user.api_key:
        db_user.api_key = genkey(32)
        db.commit()
    
    # Create a JWT token
    token = create_access_token(data={"sub": user.username})
    
    # Return the JWT token and the API key
    return {"access_token": token, "api_key": db_user.api_key}

#-------------------------------------------------------> Regenerate API Key endpoint -----------------------------------------
@app.post("/regeneratekey")
async def regenerate_key(user: UserCreate, db: Session = Depends(get_db)):
    """
    Regenerates the API key for the authenticated user.
    """
    # Fetch the user from the database
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Generate a new API key
    db_user.api_key = genkey(32)  # Generate a new 32-character API key
    
    # Update the user's API key in the database
    db.commit()
    db.refresh(db_user)
    logging.info(f"Generated API Key: {db_user.api_key}")
    # Return the new API key
    return {"message": "API key regenerated successfully", "api_key": db_user.api_key}

#uvicorn main:app --host 0.0.0.0 --port 8000
