from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field


class SubscriptionCreate(BaseModel):
    email: EmailStr
    app_name: str = Field(..., min_length=1)
    severities: List[str] = Field(default_factory=list)


class SubscriptionRead(BaseModel):
    id: str
    email: EmailStr
    app_name: str
    severities: List[str]
    active: bool

    class Config:
        from_attributes = True
