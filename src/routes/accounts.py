from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password
from security.utils import generate_secure_token

from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)


router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    try:
        group_res = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
        group = group_res.scalar_one()

        new_user = UserModel(
            email=user_data.email,
            _hashed_password=hash_password(user_data.password),
            group_id=cast(int, group.id),
            is_active=False
        )
        db.add(new_user)
        await db.flush()

        token = ActivationTokenModel(
            user_id=cast(int, new_user.id),
            token=generate_secure_token()
        )
        db.add(token)

        await db.commit()
        await db.refresh(new_user)
        return new_user
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate(data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ActivationTokenModel).join(UserModel).where(
            UserModel.email == data.email,
            ActivationTokenModel.token == data.token
        )
    )
    token_record = result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user_res = await db.execute(select(UserModel).where(UserModel.id == token_record.user_id))
    user = user_res.scalar_one()

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    user.is_active = True
    await db.delete(token_record)
    await db.commit()
    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_password_reset(data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email, UserModel.is_active.is_(True)))
    user = result.scalar_one_or_none()

    if user:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        new_token = PasswordResetTokenModel(
            user_id=cast(int, user.id),
            token=generate_secure_token()
        )
        db.add(new_token)
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def complete_password_reset(data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(PasswordResetTokenModel).join(UserModel).where(UserModel.email == data.email)
    )
    token_record = result.scalar_one_or_none()

    is_valid = True
    if not token_record or token_record.token != data.token:
        is_valid = False
    else:
        expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            is_valid = False

    if not is_valid:
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    user_res = await db.execute(select(UserModel).where(UserModel.id == token_record.user_id))
    user = user_res.scalar_one_or_none()

    if not user or not user.is_active:
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        user._hashed_password = hash_password(data.password)
        await db.delete(token_record)
        await db.commit()
        return {"message": "Password reset successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login(
        data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(data.password, user._hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        token_data = {"sub": user.email, "user_id": user.id}
        refresh_token = jwt_manager.create_refresh_token(data=token_data)
        access_token = jwt_manager.create_access_token(data=token_data)

        db_refresh = RefreshTokenModel.create(
            user_id=cast(int, user.id),
            token=refresh_token,
            days_valid=settings.LOGIN_TIME_DAYS
        )
        db.add(db_refresh)
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
    except (SQLAlchemyError, BaseSecurityError):
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_token(
        data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        _ = jwt_manager.decode_refresh_token(data.refresh_token)
    except BaseSecurityError:
        raise HTTPException(status_code=400, detail="Token has expired.")

    token_res = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token))
    db_token = token_res.scalar_one_or_none()

    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_res = await db.execute(select(UserModel).where(UserModel.id == db_token.user_id))
    user = user_res.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access_token = jwt_manager.create_access_token(data={"sub": user.email, "user_id": user.id})
    return {"access_token": new_access_token}
