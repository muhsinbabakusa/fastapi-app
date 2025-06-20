from pydantic import BaseModel

class UserCrete(BaseModel):
    FirstName: str
    LastName: str
    username: str
    email: str
    password: str
    