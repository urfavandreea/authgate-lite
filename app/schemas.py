from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(
        min_length=8,
        max_length=128,
    )


class RegisterResponse(BaseModel):
    id: int
    email: EmailStr
    role: str
    created_at: datetime
    message: str