"""
Utility script to generate a sample JWT for local testing.

Usage:
  FASTAPI_JWT_SECRET=your_secret python scripts/generate_jwt_example.py
"""
import os
import time
import jwt

secret = os.getenv("FASTAPI_JWT_SECRET", "please_set_a_secure_random_secret")
alg = os.getenv("FASTAPI_JWT_ALG", "HS256")

payload = {
    "sub": "local-user",
    "role": "api_consumer",
    "exp": int(time.time()) + 3600
}

token = jwt.encode(payload, secret, algorithm=alg)
print(token)
