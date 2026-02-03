from pydantic import BaseModel, EmailStr, field_validator

from database.validators.accounts import validate_password_strength


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, value: str) -> str:
        validate_password_strength(value)
        return value


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class ActivateAccountRequestSchema(BaseModel):
    email: EmailStr
    token: str


class ActivateAccountResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetRequestResponseSchema(BaseModel):
    message: str


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, value: str) -> str:
        validate_password_strength(value)
        return value


class PasswordResetCompleteResponseSchema(BaseModel):
    message: str


class LoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class LoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshAccessTokenRequestSchema(BaseModel):
    refresh_token: str


class RefreshAccessTokenResponseSchema(BaseModel):
    access_token: str


UserActivationRequestSchema = ActivateAccountRequestSchema
MessageResponseSchema = ActivateAccountResponseSchema

UserLoginRequestSchema = LoginRequestSchema
UserLoginResponseSchema = LoginResponseSchema

TokenRefreshRequestSchema = RefreshAccessTokenRequestSchema
TokenRefreshResponseSchema = RefreshAccessTokenResponseSchema
