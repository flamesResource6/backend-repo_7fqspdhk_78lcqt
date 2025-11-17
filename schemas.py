from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal, Dict
from datetime import datetime

# Users collection
class User(BaseModel):
    name: str = Field(..., description="Display name")
    email: EmailStr
    password_hash: Optional[str] = Field(None, description="BCrypt hash for local auth")
    provider: Literal["local", "google"] = "local"
    city: Optional[str] = None
    points: int = 0
    badges: List[str] = []
    is_admin: bool = False
    created_at: Optional[datetime] = None
    last_report_at: Optional[datetime] = None

# Reports collection
class Report(BaseModel):
    location: Dict[str, float] = Field(..., description="{lat, lng}")
    type: Literal["traffic_jam", "accident", "pothole", "police_checkpoint", "roadwork", "flood"]
    description: Optional[str] = None
    photo: Optional[str] = Field(None, description="data URL or hosted image URL")
    user_id: Optional[str] = None
    city: Optional[str] = None
    timestamp: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    upvotes: int = 0
    downvotes: int = 0
    status: Literal["active", "resolved", "expired"] = "active"

# Votes collection
class Vote(BaseModel):
    report_id: str
    user_id: Optional[str] = None
    value: Literal[1, -1]
    created_at: Optional[datetime] = None

# Subscriptions (for push notifications)
class Subscription(BaseModel):
    user_id: str
    route: Dict[str, Dict[str, float]] = Field(..., description="{start:{lat,lng}, end:{lat,lng}}")
    created_at: Optional[datetime] = None
