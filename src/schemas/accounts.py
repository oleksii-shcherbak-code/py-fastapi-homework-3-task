from pydantic import BaseModel, EmailStr, field_validator
from database.validators import accounts as accounts_validators


class MessageResponseSchema(BaseModel):
    message: str


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return accounts_validators.validate_password_strength(v)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return accounts_validators.validate_email(v)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    class Config:
        from_attributes = True


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        return accounts_validators.validate_password_strength(v)


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
