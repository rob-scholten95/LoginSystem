from pydantic import BaseModel

# Pydantic model for user creation (request body)
class UserCreate(BaseModel):
    username: str
    password: str

# Pydantic model for user response (response body)
class UserResponse(BaseModel):
    id: int
    username: str

    class Config:
        orm_mode = True  # Enable ORM compatibility to convert SQLAlchemy models