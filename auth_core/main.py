from fastapi import FastAPI, Depends, HTTPException, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.openapi.utils import get_openapi
from jose import JWTError, jwt
from datetime import datetime, timedelta
import redis
import uuid
from pymongo import MongoClient
from passlib.context import CryptContext
import os
from typing import Dict


# 設定密鑰與算法
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 5
RATE_LIMIT_PER_MINUTE = 3  # 每分鐘最多請求次數

app = FastAPI()

# 設定 OAuth2PasswordBearer，讓 Swagger 顯示 Bearer Token 欄位
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# 自定義 OpenAPI，確保 Swagger UI 顯示 Bearer Token 欄位
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="FastAPI Auth API",
        version="1.0.0",
        description="這是一個使用 OAuth2 Bearer Token 保護的 API",
        routes=app.routes,
    )
    
    # **修正 SecuritySchemeType.http 無法序列化的問題**
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",  # 這裡改為字串 "http"
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }

    # 將所有端點都加上 Bearer Token 安全性
    for path in openapi_schema["paths"]:
        for method in openapi_schema["paths"][path]:
            openapi_schema["paths"][path][method]["security"] = [{"BearerAuth": []}]
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema

# 設定 FastAPI 使用自訂 OpenAPI
app.openapi = custom_openapi



# 初始化 Redis
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
redis_client = redis.StrictRedis(host=REDIS_HOST, port=6379, db=0, decode_responses=True)


# 連接 MongoDB
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/auth_db")
client = MongoClient(MONGO_URI)
db = client["auth_db"]
users_collection = db["users"]

# 加密密碼的工具
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(username: str, password: str):
    user = users_collection.find_one({"username": username})
    if not user or not verify_password(password, user["password"]):
        return None
    return user

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        username = payload.get("sub")
        if jti is None or username is None:
            raise HTTPException(status_code=400, detail="Invalid token")
        
        # 檢查 token 是否已經使用過
        if redis_client.get(jti):
            raise HTTPException(status_code=401, detail="Token has already been used")
        
        # 標記 token 為已使用
        redis_client.setex(jti, ACCESS_TOKEN_EXPIRE_MINUTES * 60, "used")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def rate_limit(username: str):
    key = f"rate_limit:{username}"
    requests = redis_client.get(key)
    if requests and int(requests) >= RATE_LIMIT_PER_MINUTE:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    redis_client.incr(key)
    redis_client.expire(key, 60)  # 設置 60 秒後過期

@app.post("/register")
def register(username: str = Body(...), password: str = Body(...)):
    if users_collection.find_one({"username": username}):
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = hash_password(password)
    users_collection.insert_one({"username": username, "password": hashed_password})
    return {"message": "User registered successfully"}

@app.post("/token")
def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    rate_limit(form_data.username)  # 檢查是否超過使用次數

    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    jti = str(uuid.uuid4())  # 生成唯一的 token ID
    token = create_access_token({"sub": user["username"], "jti": jti})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/protected")
def protected_route(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    username = payload["sub"]
    rate_limit(username)  # 檢查是否超過使用次數
    return {"message": "You have accessed a protected route", "user": username}
