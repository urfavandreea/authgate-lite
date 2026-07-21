from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import Base, engine, get_database_session
from app.models import User
from app.schemas import RegisterRequest, RegisterResponse
from app.security import hash_password


app = FastAPI(
    title="AuthGate Lite",
    description="A lightweight authentication and RBAC service.",
    version="0.1.0",
)


Base.metadata.create_all(bind=engine)


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "AuthGate Lite is running"}


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "healthy"}


@app.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    data: RegisterRequest,
    database: Session = Depends(get_database_session),
) -> RegisterResponse:
    existing_user = database.scalar(
        select(User).where(User.email == data.email)
    )

    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    user = User(
        email=data.email,
        password_hash=hash_password(data.password),
        role="user",
    )

    database.add(user)

    try:
        database.commit()
    except IntegrityError:
        database.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    database.refresh(user)

    return RegisterResponse(
        id=user.id,
        email=user.email,
        role=user.role,
        created_at=user.created_at,
        message="User registered successfully",
    )