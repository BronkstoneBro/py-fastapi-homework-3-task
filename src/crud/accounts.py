from datetime import datetime, timezone
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from database import (
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    AccountActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface
from config import BaseAppSettings
from exceptions import BaseSecurityError


async def create_user(
    user: UserRegistrationRequestSchema, db: AsyncSession
) -> UserRegistrationResponseSchema:
    existing_user = await db.scalar(
        select(UserModel).where(UserModel.email == user.email)
    )
    if existing_user:
        raise ValueError(
            f"A user with this email {user.email} already exists."
        )

    user_group = await db.scalar(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    if not user_group:
        raise ValueError("An error occurred during user creation.")

    try:
        new_user = UserModel.create(
            email=user.email,
            raw_password=user.password,
            group_id=user_group.id,
        )
        db.add(new_user)
        await db.flush()
        activation_token = ActivationTokenModel(
            user=new_user,
        )
        db.add(activation_token)
        await db.commit()
        return new_user
    except SQLAlchemyError as e:
        await db.rollback()
        raise e


async def activate_account(
    db: AsyncSession, user_data: AccountActivationRequestSchema
) -> MessageResponseSchema:
    user = await db.scalar(
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == user_data.email)
    )

    if not user:
        raise ValueError("User not found.")

    if user.is_active:
        raise ValueError("User account is already active.")

    if (
        not user.activation_token
        or user.activation_token.token != user_data.token
    ):
        raise ValueError("Invalid or expired activation token.")

    expires_at = user.activation_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if expires_at < now:
        raise ValueError("Invalid or expired activation token.")

    try:
        user.is_active = True
        await db.delete(user.activation_token)
        await db.commit()
        return MessageResponseSchema(
            message="User account activated successfully."
        )
    except SQLAlchemyError as e:
        await db.rollback()
        raise e


async def reset_password(
    db: AsyncSession, user_data: PasswordResetRequestSchema
) -> MessageResponseSchema:
    user = await db.scalar(
        select(UserModel).where(UserModel.email == user_data.email)
    )

    generic_message = MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )

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
    except SQLAlchemyError as e:
        await db.rollback()
        raise e


async def complete_reset_password(
    user_data: PasswordResetCompleteSchema, db: AsyncSession
) -> MessageResponseSchema:
    user = await db.scalar(
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == user_data.email)
    )

    if not user:
        raise ValueError("Invalid email or token.")

    if (
        not user.password_reset_token
        or user.password_reset_token.token != user_data.token
    ):
        if user.password_reset_token:
            await db.delete(user.password_reset_token)
            await db.commit()
        raise ValueError("Invalid email or token.")

    expires_at = user.password_reset_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if expires_at < now:
        await db.delete(user.password_reset_token)
        await db.commit()
        raise ValueError("Invalid email or token.")

    try:
        user.password = user_data.password  # type: ignore  # password setter handles hashing
        await db.delete(user.password_reset_token)
        await db.commit()
        return MessageResponseSchema(message="Password reset successfully.")
    except SQLAlchemyError as e:
        await db.rollback()
        raise e


async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession,
    settings: BaseAppSettings,
    jwt_manager: JWTAuthManagerInterface,
) -> UserLoginResponseSchema:
    user = await db.scalar(
        select(UserModel).where(UserModel.email == data.email)
    )
    if not user or not user.verify_password(data.password):
        raise ValueError("Invalid email or password.")
    if not user.is_active:
        raise ValueError("User account is not activated.")

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
    except SQLAlchemyError as e:
        raise e

    return UserLoginResponseSchema(
        access_token=access_token, refresh_token=refresh_token
    )


async def refresh(
    token: TokenRefreshRequestSchema,
    db: AsyncSession,
    jwt_manager: JWTAuthManagerInterface,
) -> TokenRefreshResponseSchema:
    try:
        payload = jwt_manager.decode_refresh_token(token.refresh_token)
        user_id = payload.get("user_id")

        if not user_id:
            raise ValueError("Invalid refresh token.")

        token_obj = await db.scalar(
            select(RefreshTokenModel).where(
                RefreshTokenModel.token == token.refresh_token
            )
        )

        if not token_obj:
            raise ValueError("Refresh token not found.")

        user = await db.scalar(
            select(UserModel).where(UserModel.id == user_id)
        )
        if not user:
            raise ValueError("User not found.")

        new_access_token = jwt_manager.create_access_token(
            {"user_id": user.id}
        )

        return TokenRefreshResponseSchema(access_token=new_access_token)

    except BaseSecurityError:
        raise ValueError("Token has expired.")
    except SQLAlchemyError:
        raise ValueError("An error occurred while processing your request.")
