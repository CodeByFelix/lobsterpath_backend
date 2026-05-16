from typing import Optional
from sqlmodel import SQLModel, Field, Column, String, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSON
from pydantic import EmailStr
import uuid
from src.database import USER_DATA
from datetime import datetime, timezone


#-----User Models-----
class UserBase (SQLModel):
    email: EmailStr = Field (sa_column=Column(String, unique=True, index=True))
    first_name: Optional[str] = None
    last_name: Optional[str] = None

class User (UserBase, table=True):
    __tablename__ = "users"
    __table_args__ = {'schema': USER_DATA, 'extend_existing': True}
    id: uuid.UUID = Field (default_factory=uuid.uuid4, sa_type=UUID(as_uuid=True), primary_key=True)
    password: str
    email_verified: bool = Field(default=False)

class UserRead (UserBase):
    id: uuid.UUID
    email_verified: bool


class UserReturn (UserBase):
    email_verified: bool


#-----OTP Models-----
class EmailValidationOtp (SQLModel, table=True):
    __tablename__ = "email_validation_OTP"
    __table_args__ = {'schema': USER_DATA, 'extend_existing': True}

    id: uuid.UUID = Field (default_factory=uuid.uuid4, sa_type=UUID(as_uuid=True), primary_key=True)
    user_id: uuid.UUID = Field (foreign_key=f"{USER_DATA}.users.id", nullable=False, sa_type=UUID(as_uuid=True), index=True)
    email: str
    otp: str
    expires_at: datetime = Field (sa_column=Column (DateTime(timezone=True)))


class Token (SQLModel, table=True):
    __tablename__ = "user_token"
    __table_args__ = {'schema': USER_DATA, 'extend_existing': True}

    id: uuid.UUID = Field (default_factory=uuid.uuid4, sa_type=UUID(as_uuid=True), primary_key=True)
    user_id: uuid.UUID = Field (foreign_key=f"{USER_DATA}.users.id", nullable=False, sa_type=UUID(as_uuid=True), index=True)
    token: str
    exp: datetime = Field (sa_column=Column (DateTime(timezone=True)))
    
    # Device and session tracking fields
    ip_address: Optional[str] = None
    os: Optional[str] = None
    browser: Optional[str] = None
    device_type: Optional[str] = None
    created_at: datetime = Field(sa_column=Column(DateTime(timezone=True)), default_factory=lambda: datetime.now(timezone.utc))


#-----AI-SOC Models-----

class Project(SQLModel, table=True):
    __tablename__ = "projects"
    __table_args__ = {'schema': USER_DATA, 'extend_existing': True}

    id: uuid.UUID = Field(default_factory=uuid.uuid4, sa_type=UUID(as_uuid=True), primary_key=True)
    name: str
    user_id: uuid.UUID = Field(foreign_key=f"{USER_DATA}.users.id", nullable=False, sa_type=UUID(as_uuid=True), index=True)
    
    # Alert Configuration
    alert_email: Optional[EmailStr] = None
    deny_alert_threshold: int = Field(default=5)
    deny_alert_window: int = Field(default=60) # in seconds

    is_active: bool = Field(default=True)
    created_at: datetime = Field(sa_column=Column(DateTime(timezone=True)), default_factory=lambda: datetime.now(timezone.utc))


class APIKey(SQLModel, table=True):
    __tablename__ = "api_keys"
    __table_args__ = {'schema': USER_DATA, 'extend_existing': True}

    id: uuid.UUID = Field(default_factory=uuid.uuid4, sa_type=UUID(as_uuid=True), primary_key=True)
    key_hash: str = Field(index=True, unique=True)
    project_id: uuid.UUID = Field(foreign_key=f"{USER_DATA}.projects.id", nullable=False, sa_type=UUID(as_uuid=True), index=True)
    name: str
    backend_url: str
    backend_api_key: Optional[str] = None
    is_active: bool = Field(default=True)
    created_at: datetime = Field(sa_column=Column(DateTime(timezone=True)), default_factory=lambda: datetime.now(timezone.utc))


class Policy(SQLModel, table=True):
    __tablename__ = "policies"
    __table_args__ = {'schema': USER_DATA, 'extend_existing': True}

    id: uuid.UUID = Field(default_factory=uuid.uuid4, sa_type=UUID(as_uuid=True), primary_key=True)
    project_id: uuid.UUID = Field(foreign_key=f"{USER_DATA}.projects.id", nullable=False, sa_type=UUID(as_uuid=True), index=True)
    
    # Stores: {"enabled_ingress": ["rule1", "rule2"], "enabled_egress": ["rule3"]}
    selection_json: dict = Field(default={"enabled_ingress": [], "enabled_egress": []}, sa_column=Column(JSON))
    
    created_at: datetime = Field(sa_column=Column(DateTime(timezone=True)), default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(sa_column=Column(DateTime(timezone=True)), default_factory=lambda: datetime.now(timezone.utc))


class AuditEvent(SQLModel, table=True):
    __tablename__ = "audit_events"
    __table_args__ = {'schema': USER_DATA, 'extend_existing': True}

    id: uuid.UUID = Field(default_factory=uuid.uuid4, sa_type=UUID(as_uuid=True), primary_key=True)
    project_id: uuid.UUID = Field(foreign_key=f"{USER_DATA}.projects.id", nullable=False, sa_type=UUID(as_uuid=True), index=True)
    
    # Correlation ID to link Gateway and Webhook
    request_id: str = Field(index=True, unique=True)
    
    # Ingress Data
    prompt_snippet: Optional[str] = None # First 50 chars

    # Egress Data (from LLM Response)
    response_snippet: Optional[str] = None # First 50 chars or Tool names
    model_used: Optional[str] = None
    total_tokens: int = Field(default=0)
    prompt_tokens: int = Field(default=0)
    completion_tokens: int = Field(default=0)
    
    # Security Data (from Webhook)
    verdict: Optional[str] = Field(default="PENDING") # ALLOW/DENY
    metadata_: dict = Field(default={}, sa_column=Column("metadata", JSON))

    created_at: datetime = Field(sa_column=Column(DateTime(timezone=True)), default_factory=lambda: datetime.now(timezone.utc))
