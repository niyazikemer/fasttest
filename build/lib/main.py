from fastapi import FastAPI, HTTPException, Depends
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
fake_users_db = {
    "bob": {
        "username": "bob",
        "email": "bob@example.com",
        "full_name": "Bob Doe",
        "hashed_password": pwd_context.hash("pass"),        
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "email": "alice@example.com", 
        "full_name": "Alice Smith",
        "hashed_password": pwd_context.hash("pass"), 
        "disabled": False,
    }
}



SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def create_access_token(fake_data: dict, expires_delta: timedelta):
    fake_data_copy = fake_data.copy()
    expire = datetime.now() + expires_delta
    fake_data_copy.update({"exp": expire})
    encoded_jwt = jwt.encode(fake_data_copy, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    user = fake_users_db.get(username)
    if user is None:
        raise credentials_exception
    return user


@app.get("/")
def main(current_user: dict = Depends(get_current_user)):
    return {"message": "Hello World", "user": current_user["username"]}


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if not pwd_context.verify(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token = create_access_token(
        fake_data={"sub": user["username"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": access_token, "token_type": "bearer"}
