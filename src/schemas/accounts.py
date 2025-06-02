from pydantic import BaseModel, EmailStr, field_validator, ConfigDict, constr
from database import accounts_validators
from database.validators.accounts import (
    validate_password_strength,
    validate_email,
)


class EmailBase(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v):
        return v.lower()

    model_config = ConfigDict(from_attributes=True)


class PasswordBase(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        return accounts_validators.validate_password_strength(v)


class UserBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    email: EmailStr


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    def validate_password(cls, valid: str) -> str:
        return validate_password_strength(valid)

    @field_validator("email")
    def validate_email_field(cls, valid: str) -> str:
        return validate_email(valid)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str


class AccountActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    def validate_password(cls, valid: str) -> str:
        return validate_password_strength(valid)


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str

    model_config = ConfigDict(from_attributes=True)


class MessageResponseSchema(BaseModel):
    message: str
