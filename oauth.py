"""
FastAPI Authentication Module
This module implements a basic OAuth2 password authentication system with token-based access.
"""

from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

fake_users_db = {
    'johndoe': {
        'username': 'johndoe',
        'full_name': 'John Doe',
        'email': 'johndoe@example.com',
        'hashed_password': 'fakehashedsecret',
        'disabled': False,
    },
    'alice': {
        'username': 'alice',
        'full_name': 'Alice Wonderson',
        'email': 'alice@example.com',
        'hashed_password': 'fakehashedsecret2',
        'disabled': True,
    },
}
# * Hashing means converting a string into another string. This is done for security reasons

app = FastAPI()


def fake_hash_password(passoword: str):
    return 'fakehashed' + passoword


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def fake_decode_token(token):
    user = get_user(fake_users_db, token)
    return user


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid authentication credentials',
            headers={'WWW-Authenticate': 'Bearer'},
        )
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """
    Verifies if the current user is active in the system.

    Args:
        current_user (User): User object obtained from get_current_user dependency

    Returns:
        User: The current active user

    Raises:
        HTTPException: If user is disabled with status code 400
    """
    if current_user.disabled:
        raise HTTPException(status_code=400, detail='Inactive user')
    return current_user


@app.post('/token')
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """
    Authenticates a user and returns an access token.

    Args:
        form_data (OAuth2PasswordRequestForm): Form containing username and password

    Returns:
        dict: Contains access token and token type

    Raises:
        HTTPException: If credentials are invalid with status code 400
    """
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail='Incorrect username or Password')
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail='Incorrect username or Password')
    return {'access_token': user.username, 'token_type': 'bearer'}


@app.get('/username')
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    """
    Returns information about the currently authenticated user.

    Args:
        current_user (User): User object obtained from get_current_active_user dependency

    Returns:
        User: The current authenticated user's information
    """
    return current_user
