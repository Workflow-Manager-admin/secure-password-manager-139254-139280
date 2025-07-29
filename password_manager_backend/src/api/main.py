import os
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dotenv import load_dotenv
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
import base64
from cryptography.fernet import Fernet

# Load environment variables from .env if present (even if empty)
load_dotenv()

# Environment/config for future external DB integration and secrets
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "supersecretkey") # Should be set via env
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
PASSWORD_ENCRYPTION_KEY = os.getenv("PASSWORD_ENCRYPTION_KEY", Fernet.generate_key().decode())
# Database config placeholders for integration with password_manager_database
DB_HOST = os.getenv("DB_HOST", "")
DB_USER = os.getenv("DB_USER", "")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "")

# For demonstration, use in-memory 'database', but all DB logic is abstracted
fake_user_db = dict() # {email: {hashed_password, id}}
fake_password_db = dict() # {user_id: [PasswordEntry, ...]}

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# OAuth2 setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

app = FastAPI(
    title="Password Manager Backend",
    description="API for secure password management: registration, auth, CRUD, encryption.",
    version="1.0.0",
    openapi_tags=[
        {"name": "auth", "description": "User registration and authentication"},
        {"name": "passwords", "description": "Password CRUD operations"},
        {"name": "utils", "description": "Utility endpoints"},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Should restrict in prod!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- MODELS --- #

class Token(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field("bearer", description="Token type (bearer)")

class TokenData(BaseModel):
    email: Optional[str] = None

class UserBase(BaseModel):
    email: EmailStr = Field(..., description="User's email")

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, description="User password (min 8 chars)")

class UserInDB(UserBase):
    id: str
    hashed_password: str

class UserResponse(UserBase):
    id: str

class PasswordBase(BaseModel):
    site: str = Field(..., description="Site or service name")
    username: str = Field(..., description="Username for the site/service")
    notes: Optional[str] = Field("", description="Optional notes about this entry")

class PasswordCreate(PasswordBase):
    password: str = Field(..., description="Password (to be encrypted)")

class PasswordEntry(PasswordBase):
    id: str
    encrypted_password: str
    user_id: str
    created_at: datetime
    updated_at: datetime

class PasswordResponse(PasswordBase):
    id: str
    username: str
    password: Optional[str] = None  # decrypted on output
    notes: str
    created_at: datetime
    updated_at: datetime

# --- ENCRYPTION HELPERS --- #

class EncryptionManager:
    """Encryption and decryption using Fernet symmetric key."""
    def __init__(self, key: str):
        self.key = key.encode() if isinstance(key, str) else key
        self.fernet = Fernet(self.key)

    # PUBLIC_INTERFACE
    def encrypt(self, data: str) -> str:
        """Encrypt a string."""
        return self.fernet.encrypt(data.encode()).decode()

    # PUBLIC_INTERFACE
    def decrypt(self, token: str) -> str:
        """Decrypt a string. Raises ValueError if not decryptable."""
        try:
            return self.fernet.decrypt(token.encode()).decode()
        except Exception:
            raise ValueError("Invalid encrypted data.")

encryption_manager = EncryptionManager(PASSWORD_ENCRYPTION_KEY)

# --- UTILS --- #

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Generate JWT with expiration."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def get_user(email: str) -> Optional[UserInDB]:
    user = fake_user_db.get(email)
    if not user:
        return None
    return UserInDB(email=email, id=user["id"], hashed_password=user["hashed_password"])

def authenticate_user(email: str, password: str) -> Optional[UserInDB]:
    user = get_user(email)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    """Dependency to extract a user from JWT."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise credentials_exception
        user = get_user(email)
        if user is None:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception

# --- ROUTES --- #

# PUBLIC_INTERFACE
@app.get("/", tags=["utils"], summary="Health Check")
def health_check():
    """Returns status for health check."""
    return {"status": "Healthy"}

# PUBLIC_INTERFACE
@app.post("/auth/register", status_code=201, tags=["auth"], response_model=UserResponse, summary="Register user")
def register_user(user: UserCreate):
    """Register a new user with email and password."""
    if get_user(user.email):
        raise HTTPException(status_code=400, detail="Email already registered.")
    hashed_password = hash_password(user.password)
    user_id = base64.urlsafe_b64encode(os.urandom(9)).decode().strip("=")
    fake_user_db[user.email] = {"id": user_id, "hashed_password": hashed_password}
    fake_password_db[user_id] = []
    return UserResponse(email=user.email, id=user_id)

# PUBLIC_INTERFACE
@app.post("/auth/token", response_model=Token, tags=["auth"], summary="Login to get JWT token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate user and return a JWT."""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user.email}
    )
    return {"access_token": access_token, "token_type": "bearer"}

# PUBLIC_INTERFACE
@app.get("/users/me", tags=["auth"], response_model=UserResponse, summary="Get current user info")
def get_me(current_user: UserInDB = Depends(get_current_user)):
    """Get current authenticated user's details."""
    return UserResponse(email=current_user.email, id=current_user.id)

# PUBLIC_INTERFACE
@app.post("/passwords/", response_model=PasswordResponse, tags=["passwords"], status_code=201, summary="Create password entry")
def create_password(
    entry: PasswordCreate,
    current_user: UserInDB = Depends(get_current_user)
):
    """Add new password entry for user. Password is encrypted in storage."""
    password_id = base64.urlsafe_b64encode(os.urandom(9)).decode().strip("=")
    encrypted = encryption_manager.encrypt(entry.password)
    dt = datetime.utcnow()
    db_entry = PasswordEntry(
        id=password_id,
        site=entry.site,
        username=entry.username,
        encrypted_password=encrypted,
        notes=entry.notes or "",
        user_id=current_user.id,
        created_at=dt,
        updated_at=dt
    )
    fake_password_db[current_user.id].append(db_entry)
    return PasswordResponse(
        id=db_entry.id,
        site=db_entry.site,
        username=db_entry.username,
        notes=db_entry.notes,
        password=entry.password,  # display the plaintext just once
        created_at=dt,
        updated_at=dt
    )

# PUBLIC_INTERFACE
@app.get("/passwords/", response_model=List[PasswordResponse], tags=["passwords"], summary="List/View password entries")
def list_passwords(
    search: Optional[str] = None,
    current_user: UserInDB = Depends(get_current_user)
):
    """List password entries for user, optionally filtered by search term across site and username."""
    entries: List[PasswordEntry] = fake_password_db.get(current_user.id, [])
    result = []
    for entry in entries:
        if search and (search.lower() not in entry.site.lower() and search.lower() not in entry.username.lower()):
            continue
        try:
            password_plaintext = encryption_manager.decrypt(entry.encrypted_password)
        except ValueError:
            password_plaintext = ""
        result.append(PasswordResponse(
            id=entry.id,
            site=entry.site,
            username=entry.username,
            notes=entry.notes,
            password=password_plaintext,
            created_at=entry.created_at,
            updated_at=entry.updated_at
        ))
    return result

# PUBLIC_INTERFACE
@app.get("/passwords/{password_id}", response_model=PasswordResponse, tags=["passwords"], summary="Get a password entry")
def get_password(password_id: str, current_user: UserInDB = Depends(get_current_user)):
    """Retrieve a password entry by ID, decrypted."""
    entries: List[PasswordEntry] = fake_password_db.get(current_user.id, [])
    for entry in entries:
        if entry.id == password_id:
            try:
                password_plaintext = encryption_manager.decrypt(entry.encrypted_password)
            except ValueError:
                password_plaintext = ""
            return PasswordResponse(
                id=entry.id,
                site=entry.site,
                username=entry.username,
                notes=entry.notes,
                password=password_plaintext,
                created_at=entry.created_at,
                updated_at=entry.updated_at
            )
    raise HTTPException(status_code=404, detail="Password entry not found.")

# PUBLIC_INTERFACE
@app.put("/passwords/{password_id}", response_model=PasswordResponse, tags=["passwords"], summary="Update a password entry")
def update_password(
    password_id: str,
    entry_update: PasswordCreate,
    current_user: UserInDB = Depends(get_current_user)
):
    """Update a password entry for user (including encryption of updated password)."""
    entries: List[PasswordEntry] = fake_password_db.get(current_user.id, [])
    for idx, entry in enumerate(entries):
        if entry.id == password_id:
            encrypted = encryption_manager.encrypt(entry_update.password)
            dt = datetime.utcnow()
            updated_entry = PasswordEntry(
                id=entry.id,
                site=entry_update.site,
                username=entry_update.username,
                notes=entry_update.notes or "",
                encrypted_password=encrypted,
                user_id=current_user.id,
                created_at=entry.created_at,
                updated_at=dt,
            )
            entries[idx] = updated_entry
            return PasswordResponse(
                id=updated_entry.id,
                site=updated_entry.site,
                username=updated_entry.username,
                notes=updated_entry.notes,
                password=entry_update.password,
                created_at=updated_entry.created_at,
                updated_at=dt
            )
    raise HTTPException(status_code=404, detail="Password entry not found.")

# PUBLIC_INTERFACE
@app.delete("/passwords/{password_id}", tags=["passwords"], status_code=204, summary="Delete a password entry")
def delete_password(password_id: str, current_user: UserInDB = Depends(get_current_user)):
    """Delete password entry for user."""
    entries: List[PasswordEntry] = fake_password_db.get(current_user.id, [])
    for idx, entry in enumerate(entries):
        if entry.id == password_id:
            entries.pop(idx)
            return
    raise HTTPException(status_code=404, detail="Password entry not found.")

# PUBLIC_INTERFACE
@app.post("/passwords/{password_id}/copy", tags=["passwords"], status_code=200, summary="Copy password for entry")
def copy_password(password_id: str, current_user: UserInDB = Depends(get_current_user)):
    """Simulate copying the password for given entry to clipboard. (Backend just returns it; frontend must handle clipboard logic)."""
    entries: List[PasswordEntry] = fake_password_db.get(current_user.id, [])
    for entry in entries:
        if entry.id == password_id:
            try:
                password_plaintext = encryption_manager.decrypt(entry.encrypted_password)
            except ValueError:
                password_plaintext = ""
            return {"password": password_plaintext}
    raise HTTPException(status_code=404, detail="Password entry not found.")

# Future: For storing "organization" of passwords (e.g., tags/folders), add fields to PasswordBase and reflect in CRUD above.

# --- DB INTEGRATION POINTS ---
# All data access logic (user/password CRUD) is isolated, so to switch to a real DB:
# - Replace fake_user_db and fake_password_db with real DB queries using external password_manager_database container.
# - Use DB config env vars as connection details, and/or SQLAlchemy async engine.

# --- SECURITY NOTES ---
# 1. All sensitive operations require JWT tokens.
# 2. Passwords are always encrypted using Fernet before persist; backend never stores any user plaintext password at rest.
# 3. Clipboard op: Backend only returns the decrypted password; copying to clipboard is responsibility of frontend.

# --- END ---

