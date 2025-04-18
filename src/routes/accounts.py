import os
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

from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema
)
from security.passwords import hash_password
from security.token_manager import JWTAuthManager

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

    group = await db.scalar(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    if not group:
        raise HTTPException(
            status_code=500,
            detail="User group not found in the database"
        )

    hashed = hash_password(user_data.password)
    db_user = UserModel(
        email=user_data.email,
        _hashed_password=hashed,
        group=group,
        activation_token=ActivationTokenModel()
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)

    response_data = UserRegistrationResponseSchema(
        id=db_user.id,
        email=db_user.email
    ).dict()
    return JSONResponse(content=response_data, status_code=201)
