from typing import List

from pydantic import BaseModel

class ItemBase(BaseModel):
    title: str



class ItemCreate(ItemBase):
    pass


class Item(ItemBase):
    sections : str
    owner_id : int
    class Config:
        orm_mode = True




class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str
    #susbclass for creating users; protects the password


class User(UserBase):
    #
    id: int
    is_active: bool
    items: List[Item] = []
    class Config:
        orm_mode = True
