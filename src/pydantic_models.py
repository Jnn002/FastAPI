"""Type hints in FastAPI

FastAPI takes advantage of these type hints to do several things.

With FastAPI you declare parameters with type hints and you get:

Editor support.
Type checks.
...and FastAPI uses the same declarations to:

Define requirements: from request path parameters, query parameters, headers, bodies, dependencies, etc.
Convert data: from the request to the required type.
Validate data: coming from each request:
Generating automatic errors returned to the client when the data is invalid.
Document the API using OpenAPI:
which is then used by the automatic interactive documentation user interfaces
"""

from datetime import datetime

from pydantic import BaseModel


class User(BaseModel):
    id: int
    name: str = 'John Dutton'
    signup_ts: datetime | None = None
    friends: list[int] = []


external_data = {
    'id': '123',
    'signup_ts': '2020-06-01 12:22',
    'friends': [1, 2, '3', b'3'],
}

user = User(**external_data)
print(user)
