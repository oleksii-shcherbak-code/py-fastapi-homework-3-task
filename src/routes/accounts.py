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

from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    ActivateAccountRequestSchema,
    ActivateAccountResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetRequestResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetCompleteResponseSchema,
    LoginRequestSchema,
    LoginResponseSchema,
    RefreshAccessTokenRequestSchema,
    RefreshAccessTokenResponseSchema,
)

router = APIRouter()


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


@router.post(
    "/register/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserRegistrationResponseSchema,
)
async def register_user(
    payload: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt_existing = select(UserModel).where(UserModel.email == payload.email)
    result_existing = await db.execute(stmt_existing)
    existing_user = result_existing.scalars().first()
    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {payload.email} already exists."
        )

    stmt_group = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result_group = await db.execute(stmt_group)
    user_group = result_group.scalars().first()
    if user_group is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )

    try:
        user = UserModel.create(
            email=payload.email,
            raw_password=payload.password,
            group_id=cast(int, user_group.id),
        )
        db.add(user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=cast(int, user.id))
        db.add(activation_token)

        await db.commit()
        await db.refresh(user)

        return {"id": user.id, "email": user.email}

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    status_code=status.HTTP_200_OK,
    response_model=ActivateAccountResponseSchema,
)
async def activate_account(
    payload: ActivateAccountRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == payload.email)
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user is None:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token_record = user.activation_token
    if token_record is None or token_record.token != payload.token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    expires_at = _as_utc(token_record.expires_at)
    if expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    status_code=status.HTTP_200_OK,
    response_model=PasswordResetRequestResponseSchema,
)
async def request_password_reset_token(
    payload: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    generic_response = {"message": "If you are registered, you will receive an email with instructions."}

    stmt = select(UserModel).where(UserModel.email == payload.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user is None or not user.is_active:
        return generic_response

    await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
    token_record = PasswordResetTokenModel(user_id=cast(int, user.id))
    db.add(token_record)
    await db.commit()

    return generic_response


@router.post(
    "/reset-password/complete/",
    status_code=status.HTTP_200_OK,
    response_model=PasswordResetCompleteResponseSchema,
)
async def reset_password_complete(
    payload: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt_user = select(UserModel).where(UserModel.email == payload.email)
    result_user = await db.execute(stmt_user)
    user = result_user.scalars().first()

    if user is None or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    stmt_token = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    result_token = await db.execute(stmt_token)
    token_record = result_token.scalars().first()

    if token_record is None:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if token_record.token != payload.token:
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    expires_at = _as_utc(token_record.expires_at)
    if expires_at <= datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        user.password = payload.password
        await db.delete(token_record)
        await db.commit()
        return {"message": "Password reset successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    status_code=status.HTTP_201_CREATED,
    response_model=LoginResponseSchema,
)
async def login_user(
    payload: LoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    stmt_user = select(UserModel).where(UserModel.email == payload.email)
    result_user = await db.execute(stmt_user)
    user = result_user.scalars().first()

    if user is None or not user.verify_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    refresh_record = RefreshTokenModel.create(
        user_id=cast(int, user.id),
        days_valid=cast(int, settings.LOGIN_TIME_DAYS),
        token=refresh_token,
    )

    try:
        db.add(refresh_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post(
    "/refresh/",
    status_code=status.HTTP_200_OK,
    response_model=RefreshAccessTokenResponseSchema,
)
async def refresh_access_token(
    payload: RefreshAccessTokenRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        data = jwt_manager.decode_refresh_token(payload.refresh_token)
    except BaseSecurityError as e:
        raise HTTPException(status_code=400, detail=str(e))

    user_id = data.get("user_id")

    stmt_token = select(RefreshTokenModel).where(RefreshTokenModel.token == payload.refresh_token)
    result_token = await db.execute(stmt_token)
    token_record = result_token.scalars().first()
    if token_record is None:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    stmt_user = select(UserModel).where(UserModel.id == user_id)
    result_user = await db.execute(stmt_user)
    user = result_user.scalars().first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    return {"access_token": access_token}
