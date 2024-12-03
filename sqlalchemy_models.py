from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Base class for database models
Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    api_key = Column(String, nullable=True)  # Optional API key field

# SQLite database URL
DATABASE_URL = "sqlite:///./users.db"

# Create the SQLite database engine
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Session maker for interacting with the database
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create tables
Base.metadata.create_all(bind=engine)

