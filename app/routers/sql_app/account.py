#based on this https://medium.com/data-rebels/fastapi-how-to-add-basic-and-cookie-authentication-a45c85ef47d3
#and this Based on the tutorial starting here: https://fastapi.tiangolo.com/tutorial/security/
#The medium article fills in the missing pieces of the official tutorial

from typing import Optional, List
import base64
from passlib.context import CryptContext
from datetime import datetime, timedelta

import jwt
from jwt import PyJWTError

from pydantic import BaseModel
from fastapi import APIRouter, WebSocket, Request, File, Form, UploadFile, Depends, HTTPException, status

from fastapi.encoders import jsonable_encoder
from fastapi.security import OAuth2PasswordRequestForm, OAuth2, OAuth2PasswordBearer
from fastapi.security.base import SecurityBase
from fastapi.openapi.models import SecurityBase as SecurityBaseModel
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.openapi.utils import get_openapi

from starlette.status import HTTP_403_FORBIDDEN
from starlette.responses import RedirectResponse, Response, JSONResponse
from starlette.requests import Request

from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from pathlib import Path

from sqlalchemy.orm import Session
from . import crud, models, schema #database interaction stuff. This should be from . import, but that complained
from .database import SessionLocal, engine #more database interaction stuff. Technially, this should be from .database, but this complains for unknown reasons

models.Base.metadata.create_all(bind=engine)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


router = APIRouter()
templates = Jinja2Templates(directory="templates")
router_path = Path.cwd()


SECRET_KEY = "" #generate a secure random key using the command: openssl rand -hex 32. Don't share it! git ignore this entire router in your acutal file
ALGORITHM = "" #hashing algorithm for JWT, here is a list of valid ones: https://jwt.io/ (in the dropdown box called algorithms)
ACCESS_TOKEN_EXPIRE_MINUTES = 30




class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str = None




pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)





class OAuth2PasswordBearerCookie(OAuth2):
    def __init__(
        self,
        tokenUrl: str,
        scheme_name: str = None,
        scopes: dict = None,
        auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(password={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[str]:
        header_authorization: str = request.headers.get("Authorization")
        cookie_authorization: str = request.cookies.get("Authorization")
        print(header_authorization, " header auth recieved")
        print(cookie_authorization, " cookie auth recieved")
        header_scheme, header_param = get_authorization_scheme_param(
            header_authorization
        )
        cookie_scheme, cookie_param = get_authorization_scheme_param(
            cookie_authorization
        )
        if header_scheme.lower() == "bearer":
            authorization = True
            scheme = header_scheme
            param = header_param

        elif cookie_scheme.lower() == "bearer":
            authorization = True
            scheme = cookie_scheme
            param = cookie_param

        else:
            authorization = False

        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
                )
            else:
                return None
        return param


class BasicAuth(SecurityBase):
    def __init__(self, scheme_name: str = None, auto_error: bool = True):
        self.scheme_name = scheme_name or self.__class__.__name__
        self.model = SecurityBaseModel(type= "http")
        self.auto_error = auto_error

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.headers.get("Authorization")
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "basic":
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
                )
            else:
                return None
        print(param)
        return param
basic_auth = BasicAuth(auto_error=False)
oauth2_scheme = OAuth2PasswordBearerCookie(tokenUrl="/token")

def authenticate_user(db : Session, username: str, password: str):
    user = crud.get_user_by_username(db, username)
    if not user:
        print("wrong username")
        return False
    if not verify_password(password, user.hashed_password):
        print("wrong password")
        return False
    return user

def create_access_token(*, data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@router.get("/users/", response_model=List[schema.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users

@router.post("/users/{user_id}/items/", response_model=schema.item)
def create_item_for_user(
    user_id: int, item: schema.itemCreate, sections : str, db: Session = Depends(get_db)
):
    return crud.create_user_item(db=db, item=item, sections = sections, user_id=user_id)


@router.get("/items/", response_model=List[schema.item])
def items(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    items = crud.get_items(db, skip=skip, limit=limit)
    return items


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(payload)
        username: str = payload.get("sub")
        print(username)
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except PyJWTError:
        raise credentials_exception
    user = crud.get_user_by_username(db, username=token_data.username)

    if user is None:
        raise credentials_exception
    user.disabled = False
    return user


async def get_current_active_user(current_user: schema.User = Depends(get_current_user)):
    return current_user

@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token = access_token, token_type= "bearer")


@router.get("/users/me/", response_model=schema.User)
async def read_users_me(current_user: schema.User = Depends(get_current_active_user)):
    return current_user


@router.get("/users/{username}", response_model=schema.User)
def read_user(username: str, db: Session = Depends(get_db), current_user: schema.User = Depends(get_current_active_user)):
    db_user = crud.get_user_by_username(db, username=username)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@router.post("/login/")
@router.get("/login/")
async def login_basic(auth: BasicAuth = Depends(basic_auth), db: Session = Depends(get_db)):
    print(auth)
    if not auth:
        response = Response(headers={"WWW-Authenticate": "Basic"}, status_code=401)
        return response

    try:
        decoded = base64.b64decode(auth).decode("ascii")
        username, _, password = decoded.partition(":")
        user = authenticate_user(db, username, password)
        print("authenticated")
        if not user:
            raise HTTPException(status_code=400, detail="Incorrect email or password")
        print("got user")
        access_token_expires = timedelta(minutes=5)
        access_token = create_access_token(
            data={"sub": username}, expires_delta=access_token_expires
        )
        print("made access token")
        token = jsonable_encoder(access_token)
        print(token)
        response = RedirectResponse(url="/account/manage/")
        response.set_cookie(
            "Authorization",
            value=f"Bearer {token}",
            httponly=True,
            max_age=1800,
            expires=1800,
        )
        return response

    except:
        response = Response(headers={"WWW-Authenticate": "Basic"}, status_code=401)
        return response

@router.get("/logout/")
async def route_logout_and_remove_cookie():
    response = RedirectResponse(url="/")
    response.delete_cookie("Authorization")
    return response


@router.get("/signup/")
def signup_handler(request: Request):
    context = {"request" : request}
    return templates.TemplateResponse("signup.html", context)




@router.post("/signup/")
def create_user(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    context = {"request" : request}
    user = schema.UserCreate(username = username, password = password)
    #print(db)
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    crud.create_user(db, user)
    response =  RedirectResponse(url="/account/login/")
    return response


@router.post("/manage/")
@router.get("/manage/")
async def welcome(request : Request, user : schema.User = Depends(get_current_active_user)):
    context = {"request" : request}
    context["welcome"] = f"Welcome {user.username}"
    return templates.TemplateResponse("account_management.html", context)
