
from typing import List
from pydantic import BaseModel, validator
import enum

class UserRoles(str, enum.Enum):
    ADMIN = "admin"
    USER = "user"


class User:

    def __init__(self, username, email, hashed_password, role=UserRoles.USER):
        self.username = username
        self.hashed_password = hashed_password
        self.email = email
        self.role = role


class GetUser(BaseModel):
    username: str
    email: str
    role: str


class UserList(BaseModel):
    user_list: List[GetUser]


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    confirm_password: str

    @validator('confirm_password')
    def check_both_password_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError("password and confirm password should match")
        return v
