from fastapi import Request, FastAPI
from slowapi.util import get_remote_address
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
import redis  
import json

redis_client = redis.Redis(host = "localhost", port= 6379, db=0, decode_response= True)

app = FastAPI()

limiter = Limiter(key_func=get_rate_limit_key)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

@app.get("/limited-access")
@limiter.limit(lambda request: role_limits.get(getattr(request.state.user, "role", "user"), "5/minute"))
def limited_access(request: Request):
    user = request.state.user
    return {"message": f"Access granted for role: {user.role}"}
@app.middleware("http")
async def add_user_to_request(request: Request, call_next):
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if username:
                db = SessionLocal()
                user = db.query(User).filter(User.username == username).first()
                request.state.user = user
    except:
        request.state.user = None
    response = await call_next(request)
    return response

def get_rate_limit_key(request: Request):
    user = request.state.user  # Set this earlier in a middleware or route
    role = getattr(user, "role", "user")
    ip = get_remote_address(request)
    return f"{role}:{ip}"

role_limits = {
    "user": "5/minute",
    "premium": "30/minute",
    "admin": "100/minute"
}