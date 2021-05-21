
from typing import List
from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str

class ApiErrorResponse(BaseModel):
    code: int = 0
    success: bool = False
    message: str = 'Unknown Error Occurred.'

class ApiUnprocessableEntityResponse(BaseModel):
    code: int = 0
    success: bool = False
    message: str = "Unable to Process JSON response"
    errors: List = None

class ApiSuccessResponse(BaseModel):
    code: int = 200
    success: bool = True
    message: str = "Successful Operation"


