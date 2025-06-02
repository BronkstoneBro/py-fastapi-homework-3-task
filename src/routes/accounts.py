from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
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
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
)
from schemas.accounts import (
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    AccountActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/", status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:
    existing_user = await db.scalar(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists.",
        )
    user_group = await db.scalar(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    if not user_group:
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )
    try:
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id,
        )
        db.add(new_user)
        await db.flush()
        activation_token = ActivationTokenModel(
            user=new_user,
        )
        db.add(activation_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )
    return new_user


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_account(
    activation_data: AccountActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Activate a user account using the activation token.
    """
    user = await db.scalar(
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == activation_data.email)
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    if (
        not user.activation_token
        or user.activation_token.token != activation_data.token
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = user.activation_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    try:
        user.is_active = True
        await db.delete(user.activation_token)
        await db.commit()
        return {"message": "User account activated successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while activating the account.",
        )


@router.post("/login/", status_code=status.HTTP_201_CREATED)
@router.post("/signin/", status_code=status.HTTP_201_CREATED)
async def login_user(
    user_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
) -> UserLoginResponseSchema:
    user = await db.scalar(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    if not user or not user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )
    access_token = jwt_manager.create_access_token({"user_id": user.id})
    refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})
    try:
        token_obj = RefreshTokenModel.create(
            user_id=user.id,
            token=refresh_token,
            days_valid=settings.LOGIN_TIME_DAYS,
        )
        db.add(token_obj)
        await db.commit()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )
    return UserLoginResponseSchema(
        access_token=access_token, refresh_token=refresh_token
    )


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
@router.post("/reset-password/request/", status_code=status.HTTP_200_OK)
async def request_password_reset(
    reset_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Request a password reset token.
    """
    user = await db.scalar(
        select(UserModel).where(UserModel.email == reset_data.email)
    )

    # Always return the same message for security
    generic_message = {
        "message": "If you are registered, you will receive an email with instructions."
    }

    if not user or not user.is_active:
        return generic_message

    try:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )

        reset_token = PasswordResetTokenModel(user=user)
        db.add(reset_token)
        await db.commit()

        return generic_message
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing your request.",
        )


@router.post("/password-reset/complete/", status_code=status.HTTP_200_OK)
@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def complete_password_reset(
    reset_data: PasswordResetCompleteSchema,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Complete the password reset process using the reset token.
    """
    user = await db.scalar(
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == reset_data.email)
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    if (
        not user.password_reset_token
        or user.password_reset_token.token != reset_data.token
    ):
        if user.password_reset_token:
            await db.delete(user.password_reset_token)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    expires_at = user.password_reset_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if expires_at < now:
        await db.delete(user.password_reset_token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    try:
        user.password = reset_data.password
        await db.delete(user.password_reset_token)
        await db.commit()
        return {"message": "Password reset successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post("/refresh/", status_code=status.HTTP_200_OK)
@router.post("/token/refresh/", status_code=status.HTTP_200_OK)
async def refresh_access_token(
    refresh_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> TokenRefreshResponseSchema:
    """
    Refresh the access token using a valid refresh token.
    """
    try:
        payload = jwt_manager.decode_refresh_token(refresh_data.refresh_token)
        user_id = payload.get("user_id")

        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token.",
            )

        token = await db.scalar(
            select(RefreshTokenModel).where(
                RefreshTokenModel.token == refresh_data.refresh_token
            )
        )

        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found.",
            )

        user = await db.scalar(
            select(UserModel).where(UserModel.id == user_id)
        )
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )

        new_access_token = jwt_manager.create_access_token(
            {"user_id": user.id}
        )

        return TokenRefreshResponseSchema(access_token=new_access_token)

    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing your request.",
        )
