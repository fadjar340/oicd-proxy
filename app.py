from fastapi import FastAPI, HTTPException, Depends, Form
from fastapi.security import HTTPBearer
from jose import jwt, JWTError
import requests
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = FastAPI()
security = HTTPBearer()

# Environment variables
PROXY_DOMAIN = os.getenv("PROXY_DOMAIN")
TARGET_DOMAIN = os.getenv("TARGET_DOMAIN")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
SECRET_KEY = os.getenv("SECRET_KEY")

# Token endpoint
@app.post("/protocol/openid-connect/token")
def token(
    username: str = Form(...),
    password: str = Form(...),
    grant_type: str = Form(default="password"),
    scope: str = Form(default="openid profile"),
):
    # Forward the request to the custom OAuth2 token endpoint
    token_response = requests.post(
        f"{TARGET_DOMAIN}/oauth/token",
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": grant_type,
            "username": username,
            "password": password,
        },
    )

    if token_response.status_code != 200:
        print(f"Error from custom OAuth2 token endpoint: {token_response.status_code} - {token_response.text}")
        raise HTTPException(status_code=token_response.status_code, detail=token_response.text)

    # Extract the access token from the response
    access_token = token_response.json().get("access_token")

    # Decode the JWT token to extract user information
    try:
        decoded_token = jwt.decode(access_token, options={"verify_signature": False})  # Skip signature verification
        user_name = decoded_token.get("user_name")
        fullname = decoded_token.get("fullname")
        user_id = decoded_token.get("user_id")
        authorities = decoded_token.get("authorities", [])
        hospital_code = decoded_token.get("hospital_code")
        hospital_name = decoded_token.get("hospital_name")
    except JWTError as e:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Generate OIDC-compliant ID token
    id_token = jwt.encode(
        {
            "iss": PROXY_DOMAIN,  # Issuer (Proxy Domain)
            "sub": user_name,  # Subject (username)
            "aud": CLIENT_ID,  # Audience (client ID)
            "exp": datetime.utcnow() + timedelta(hours=1),  # Expiration time
            "iat": datetime.utcnow(),  # Issued at
            "name": fullname,  # Full name
            "user_id": user_id,  # User ID
            "authorities": authorities,  # User roles/authorities
            "hospital_code": hospital_code,  # Hospital code
            "hospital_name": hospital_name,  # Hospital name
        },
        SECRET_KEY,
        algorithm="HS256",
    )

    return {
        "access_token": access_token,
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600,
    }

# UserInfo endpoint
@app.get("/protocol/openid-connect/userinfo")
def userinfo(token: str = Depends(security)):
    try:
        # Decode the JWT token to extract user information
        decoded_token = jwt.decode(token.credentials, SECRET_KEY, algorithms=["HS256"])  # Verify signature
        user_name = decoded_token.get("user_name")
        fullname = decoded_token.get("fullname")
        user_id = decoded_token.get("user_id")
        authorities = decoded_token.get("authorities", [])
        hospital_code = decoded_token.get("hospital_code")
        hospital_name = decoded_token.get("hospital_name")

        return {
            "sub": user_name,  # Subject (username)
            "name": fullname,  # Full name
            "user_id": user_id,  # User ID
            "authorities": authorities,  # User roles/authorities
            "hospital_code": hospital_code,  # Hospital code
            "hospital_name": hospital_name,  # Hospital name
        }
    except JWTError as e:
        raise HTTPException(status_code=401, detail="Invalid token")

# Discovery endpoint
@app.get("/.well-known/openid-configuration")
def discovery():
    return {
        "issuer": PROXY_DOMAIN,
        "authorization_endpoint": f"{PROXY_DOMAIN}/protocol/openid-connect/auth",
        "token_endpoint": f"{PROXY_DOMAIN}/protocol/openid-connect/token",
        "userinfo_endpoint": f"{PROXY_DOMAIN}/protocol/openid-connect/userinfo",
        "jwks_uri": f"{PROXY_DOMAIN}/protocol/openid-connect/certs",
    }

# JWKS endpoint (not applicable for HS256, but included for compatibility)
@app.get("/protocol/openid-connect/certs")
def jwks():
    return {
        "keys": []  # HS256 does not use JWKS
    }