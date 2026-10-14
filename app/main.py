from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import Base, engine, get_database_session
from app.models import User
from app.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    RegisterRequest,
    RegisterResponse,
    UserResponse,
)
from app.security import (
    create_access_token,
    hash_password,
    verify_access_token,
    verify_password,
)


Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="AuthGate Lite",
    description="A lightweight authentication and RBAC service.",
    version="0.1.0",
)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@app.get("/")
def root() -> dict[str, str]:
    return {
        "message": "Welcome to AuthGate Lite",
    }


@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "healthy",
    }


def get_current_user(
    token: str = Depends(oauth2_scheme),
    database: Session = Depends(get_database_session),
) -> User:
    user_id = verify_access_token(token)

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = database.get(User, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    return current_user


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
            detail="A user with this email already exists",
        )

    new_user = User(
        email=data.email,
        password_hash=hash_password(data.password),
        role="user",
    )

    database.add(new_user)

    try:
        database.commit()
    except IntegrityError:
        database.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists",
        )

    database.refresh(new_user)

    return RegisterResponse(
        id=new_user.id,
        email=new_user.email,
        role=new_user.role,
        created_at=new_user.created_at,
        message="User registered successfully",
    )


@app.post("/login")
def login(
    data: LoginRequest,
    database: Session = Depends(get_database_session),
) -> dict[str, str]:
    user = database.scalar(
        select(User).where(User.email == data.email)
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    password_is_valid = verify_password(
        data.password,
        user.password_hash,
    )

    if not password_is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    access_token = create_access_token(user.id)

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


@app.get(
    "/me",
    response_model=UserResponse,
)
def read_current_user(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        role=current_user.role,
    )


@app.get("/admin/users")
def list_users(
    admin_user: User = Depends(require_admin),
    database: Session = Depends(get_database_session),
) -> list[dict[str, int | str]]:
    users = database.scalars(
        select(User)
    ).all()

    return [
        {
            "id": user.id,
            "email": user.email,
            "role": user.role,
        }
        for user in users
    ]


@app.post("/change-password")
def change_password(
    data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    database: Session = Depends(get_database_session),
) -> dict[str, str]:
    current_password_is_valid = verify_password(
        data.current_password,
        current_user.password_hash,
    )

    if not current_password_is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    current_user.password_hash = hash_password(
        data.new_password
    )

    database.commit()

    return {
        "message": "Password changed successfully",
    }