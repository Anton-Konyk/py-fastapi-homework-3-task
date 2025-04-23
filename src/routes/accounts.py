from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
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
from security.interfaces import JWTAuthManagerInterface
from starlette.responses import JSONResponse

from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
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


@router.post("/activate/")
async def account_activation(
        user_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> JSONResponse:
    existing_user = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .filter_by(email=user_data.email)
    )
    db_user = existing_user.scalar_one_or_none()
    if not db_user:
        raise HTTPException(
            status_code=409,
            detail=f"User was not created in the database."
        )

    if (not db_user.activation_token
        or db_user.activation_token.token != user_data.token
        or db_user.activation_token.expires_at < datetime.utcnow()
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    if db_user.is_active is True:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    db_user.is_active = True
    db_user.activation_token = None
    await db.commit()
    await db.refresh(db_user)

    return JSONResponse(
        content={"message": "User account activated successfully."},
        status_code=200)
