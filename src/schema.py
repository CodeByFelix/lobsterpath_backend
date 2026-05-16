from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field, validator
from src.model import UserReturn, UserBase
import uuid
import re
from datetime import datetime

#-----User Schemas-----
class UserLogin (BaseModel):
    email: EmailStr
    password: str

class UserCreate (UserBase):
    password: str = Field(min_length=8, description="Password must be at least 8 characters long")

    @validator("password")
    def validate_password_strength(cls, value):
        """
        Validates that the password is strong:
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        """
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long")

        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter")

        if not re.search(r"[a-z]", value):
            raise ValueError("Password must contain at least one lowercase letter")

        if not re.search(r"\d", value):
            raise ValueError("Password must contain at least one number")

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>/]", value):
            raise ValueError("Password must contain at least one special character")

        return value

class LoginReturn (BaseModel):
    user: UserReturn
    token: str
    token_type: str
    message: str

class VerifyEmailRequest (BaseModel):
    otp: str

class SessionResponse(BaseModel):
    id: uuid.UUID
    ip_address: Optional[str] = None
    os: Optional[str] = None
    browser: Optional[str] = None
    device_type: Optional[str] = None
    created_at: datetime
    is_current_session: bool = False

#-----AI-SOC Schemas-----

class ProjectCreate(BaseModel):
    name: str

class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    alert_email: Optional[EmailStr] = None
    deny_alert_threshold: Optional[int] = None
    deny_alert_window: Optional[int] = None
    is_active: Optional[bool] = None

class ProjectRead(BaseModel):
    id: uuid.UUID
    name: str
    alert_email: Optional[EmailStr] = None
    deny_alert_threshold: int
    deny_alert_window: int
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class APIKeyCreate(BaseModel):
    name: str
    project_id: uuid.UUID
    backend_url: str
    backend_api_key: str

class APIKeyRead(BaseModel):
    id: uuid.UUID
    name: str
    project_id: uuid.UUID
    backend_url: str
    backend_api_key: Optional[str] = None
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class APIKeyCreated(APIKeyRead):
    api_key: str # The plain text key returned only once

#-----AI-SOC Policy Schemas-----

class RuleInfo(BaseModel):
    id: str  # The key name like "block_pii"
    name: str # Human readable name
    description: str

class RuleBankResponse(BaseModel):
    ingress: List[RuleInfo]
    egress: List[RuleInfo]

class PolicySelectionUpdate(BaseModel):
    enabled_ingress: List[str] = Field(..., description="List of policy names/IDs to enable for incoming prompts (e.g., ['block_pii', 'detect_jailbreak'])")
    enabled_egress: List[str] = Field(..., description="List of policy names/IDs to enable for outgoing LLM responses (e.g., ['mask_secrets'])")

class PolicyRead(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    selection_json: dict
    updated_at: datetime

    class Config:
        from_attributes = True

#-----LLM Provider Schemas-----

class LLMProvider(BaseModel):
    name: str
    base_url: str

class LLMProviderList(BaseModel):
    providers: List[LLMProvider]

#-----Audit & Observability Schemas-----

class AuditEventRead(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    request_id: str
    prompt_snippet: Optional[str] = None
    response_snippet: Optional[str] = None
    model_used: Optional[str] = None
    total_tokens: int
    prompt_tokens: int
    completion_tokens: int
    verdict: str
    metadata: dict = Field(alias="metadata_") # Map internal metadata_ to metadata
    created_at: datetime

    class Config:
        from_attributes = True
        populate_by_name = True

class ReportRequest(BaseModel):
    api_key_id: uuid.UUID
    model: str

class ModelListResponse(BaseModel):
    provider: str
    models: List[str]
