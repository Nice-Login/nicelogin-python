# NiceLogin Python SDK

> **🤖 LLM-Friendly SDK**: This SDK was designed to be easily implemented by code agents (Claude, GPT, Cursor, Copilot, etc). Just ask your code agent to read this README and it will be able to implement complete authentication in your project.

Minimalist SDK for NiceLogin. **Zero external dependencies.**

---

## Installation

```bash
pip install nicelogin-jwks-python
```

---

## Important Concepts

### `api_key` vs `api_secret`

| Credential | Where to use | Purpose |
|------------|--------------|---------|
| `api_key` | Frontend/Backend | Public operations: login, registration, password reset |
| `api_secret` | **Backend only** | Administrative operations: activate/deactivate users |

**⚠️ NEVER expose `api_secret` in the frontend!**

### Two Main Classes

| Class | Purpose |
|-------|---------|
| `NiceLogin` | HTTP client to call the API (password reset, activate user, etc) |
| `NiceLoginJWKS` | Local JWT token verifier (no HTTP requests) |

---

## Complete Usage Guide

### 1. Initialization

```python
from nicelogin_jwks import NiceLogin, NiceLoginJWKS, NiceLoginError

# Client for API operations
client = NiceLogin(
    api_key="nicelogin_your_api_key",         # Required
    api_secret="your_api_secret",              # Optional (admin only)
    base_url="https://api.v1.nicelogin.com"    # Optional (default)
)
```

### 2. Password Reset (Complete Flow)

**Scenario: User forgot password**

```python
# STEP 1: Backend requests reset token
reset_token = client.request_password_reset("user@email.com")

# STEP 2: Send reset_token via email to user
# (implement your own email sending)
send_email(
    to="user@email.com",
    subject="Password Reset",
    body=f"Use this token to reset your password: {reset_token}"
)

# STEP 3: User clicks link and provides new password
# Backend receives token and new password from frontend
client.reset_password(
    email="user@email.com",
    current_password="current_password",  # User needs to know current password
    new_password="new_password_123",
    reset_token=reset_token
)
```

### 3. Change Password (Logged In User)

**Scenario: User wants to change password knowing the current one**

```python
# Single line - requests token internally
client.change_password(
    email="user@email.com",
    current_password="current_password",
    new_password="new_password_123"
)
```

### 4. Activate/Deactivate User (Admin)

**⚠️ Requires `api_secret` - Use only in backend!**

```python
# Initialize with api_secret
admin_client = NiceLogin(
    api_key="nicelogin_xxx",
    api_secret="secret_xxx"  # REQUIRED for these operations
)

# Deactivate user (e.g., ban, suspend)
admin_client.deactivate_user("550e8400-e29b-41d4-a716-446655440000")

# Reactivate user
admin_client.activate_user("550e8400-e29b-41d4-a716-446655440000")
```

### 5. Verify JWT Token (Local, No HTTP)

**Scenario: Validate token on each request in your backend**

```python
import urllib.request
import json

# STEP 1: Fetch JWKS once (cache for 24h)
api_key = "nicelogin_your_api_key"
jwks_url = f"https://api.v1.nicelogin.com/.well-known/jwks/{api_key}"

with urllib.request.urlopen(jwks_url) as response:
    jwks = json.loads(response.read().decode())

# STEP 2: Create verifier (do this once at initialization)
verifier = NiceLoginJWKS(jwks)

# STEP 3: Verify tokens on each request
def authenticate(request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")

    # Check if token is valid (True/False)
    if not verifier.verify_token(token):
        raise Exception("Invalid token")

    # Extract user data
    payload = verifier.unpack(token)
    return {
        "user_id": payload["sub"],
        "email": payload["email"],
        "company_id": payload["company_id"]
    }
```

---

## Quick API Reference

### `NiceLogin` Class

```python
client = NiceLogin(api_key, api_secret=None, base_url="https://api.v1.nicelogin.com")
```

| Method | Parameters | Return | Description |
|--------|------------|--------|-------------|
| `request_password_reset(email)` | `email: str` | `str` (token) | Request reset token |
| `reset_password(email, current_password, new_password, reset_token)` | all `str` | `bool` | Reset password with token |
| `change_password(email, current_password, new_password)` | all `str` | `bool` | Change password (1 step) |
| `activate_user(user_id)` | `user_id: str` | `bool` | Activate user* |
| `deactivate_user(user_id)` | `user_id: str` | `bool` | Deactivate user* |

*Requires `api_secret`

### `NiceLoginJWKS` Class

```python
verifier = NiceLoginJWKS(jwks)  # jwks is dict from /.well-known/jwks/{api_key} endpoint
```

| Method | Parameters | Return | Description |
|--------|------------|--------|-------------|
| `verify_token(token)` | `token: str` | `bool` | `True` if valid |
| `unpack(token, verify=True)` | `token: str`, `verify: bool` | `dict` | Extract payload |

### Token Payload (claims)

```python
{
    "sub": "550e8400-...",        # User ID (UUID)
    "email": "user@email.com",    # User email
    "company_id": "660e8400-...", # Company ID (UUID)
    "exp": 1704153600,            # Expiration (Unix timestamp)
    "iat": 1704067200,            # Issued at (Unix timestamp)
    "jti": "unique-token-id",     # Unique token ID
    "sid": "session-id",          # Session ID (optional)
    "user_data": {"name": "John"} # Custom data (optional)
}
```

---

## Error Handling

```python
from nicelogin_jwks import NiceLogin, NiceLoginError

client = NiceLogin(api_key="...")

try:
    client.change_password("user@email.com", "wrong_password", "new_pass")
except NiceLoginError as e:
    print(f"Error {e.status}: {e.message}")
    # Error 401: Invalid credentials
```

### Common Error Codes

| Status | Meaning |
|--------|---------|
| 400 | Invalid data (weak password, invalid email) |
| 401 | Invalid credentials (api_key, password, token) |
| 404 | User not found |
| 500 | Internal server error |

---

## Integration Examples

### FastAPI

```python
from fastapi import FastAPI, Depends, HTTPException, Header
from nicelogin_jwks import NiceLogin, NiceLoginJWKS, NiceLoginError
import urllib.request
import json

app = FastAPI()

# Configuration
API_KEY = "nicelogin_xxx"
API_SECRET = "secret_xxx"

# Initialize client
client = NiceLogin(api_key=API_KEY, api_secret=API_SECRET)

# Load JWKS once
with urllib.request.urlopen(f"https://api.v1.nicelogin.com/.well-known/jwks/{API_KEY}") as r:
    jwks = json.loads(r.read().decode())
verifier = NiceLoginJWKS(jwks)

# Authentication dependency
def get_current_user(authorization: str = Header(...)):
    token = authorization.replace("Bearer ", "")
    if not verifier.verify_token(token):
        raise HTTPException(401, "Invalid token")
    return verifier.unpack(token)

# Routes
@app.post("/reset-password")
def reset_password(email: str):
    try:
        token = client.request_password_reset(email)
        # Send token via email...
        return {"message": "Email sent"}
    except NiceLoginError as e:
        raise HTTPException(e.status, e.message)

@app.get("/me")
def get_me(user: dict = Depends(get_current_user)):
    return {"user_id": user["sub"], "email": user["email"]}

@app.post("/admin/deactivate/{user_id}")
def deactivate(user_id: str, admin: dict = Depends(get_current_user)):
    client.deactivate_user(user_id)
    return {"message": "User deactivated"}
```

### Flask

```python
from flask import Flask, request, jsonify
from nicelogin_jwks import NiceLogin, NiceLoginJWKS, NiceLoginError
from functools import wraps
import urllib.request
import json

app = Flask(__name__)

# Configuration
API_KEY = "nicelogin_xxx"
client = NiceLogin(api_key=API_KEY)

# Load JWKS
with urllib.request.urlopen(f"https://api.v1.nicelogin.com/.well-known/jwks/{API_KEY}") as r:
    jwks = json.loads(r.read().decode())
verifier = NiceLoginJWKS(jwks)

# Authentication decorator
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not verifier.verify_token(token):
            return jsonify({"error": "Invalid token"}), 401
        request.user = verifier.unpack(token)
        return f(*args, **kwargs)
    return decorated

@app.route("/me")
@require_auth
def get_me():
    return jsonify({"user_id": request.user["sub"], "email": request.user["email"]})
```

### Django

```python
# middleware.py
from nicelogin_jwks import NiceLoginJWKS
import urllib.request
import json

API_KEY = "nicelogin_xxx"

# Load JWKS once
with urllib.request.urlopen(f"https://api.v1.nicelogin.com/.well-known/jwks/{API_KEY}") as r:
    jwks = json.loads(r.read().decode())
verifier = NiceLoginJWKS(jwks)

class NiceLoginMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token and verifier.verify_token(token):
            request.nicelogin_user = verifier.unpack(token)
        else:
            request.nicelogin_user = None
        return self.get_response(request)

# views.py
from django.http import JsonResponse

def me(request):
    if not request.nicelogin_user:
        return JsonResponse({"error": "Not authenticated"}, status=401)
    return JsonResponse({
        "user_id": request.nicelogin_user["sub"],
        "email": request.nicelogin_user["email"]
    })
```

---

## Implementation Checklist

For LLMs and developers, use this checklist:

- [ ] Install: `pip install nicelogin-jwks-python`
- [ ] Get `api_key` from NiceLogin dashboard
- [ ] Get `api_secret` (if you need to activate/deactivate users)
- [ ] Implement password reset endpoint
- [ ] Implement JWT token verification on protected routes
- [ ] Cache JWKS for 24h (don't fetch on every request)
- [ ] Handle errors with try/except `NiceLoginError`

---

## License

MIT
