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
from starlette.responses import JSONResponse

from src.schemas.accounts import UserRegistrationRequestSchema

router = APIRouter()


@router.post("/register/")
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> JSONResponse:

    existing_user = await db.execute(select(UserModel).
                                     filter_by(email=user_data.email)
                                     )
    if existing_user.scalar():
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} "
                   f"already exists."
        )
