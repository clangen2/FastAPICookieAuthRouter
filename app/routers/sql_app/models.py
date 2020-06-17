"""Models for the database tables. Column(Type) just defines the type we expect that column to contain, rather than acually assigning a value to it."""

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    items =  relationship("Item", back_populates="owner")



class Item(Base):
    __tablename__ = "items"
    title = Column(String, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="items")
