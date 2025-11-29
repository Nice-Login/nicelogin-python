# NiceLogin Python SDK

> **🤖 LLM-Friendly SDK**: Este SDK foi desenvolvido para ser facilmente implementado por agentes de código (Claude, GPT, Cursor, Copilot, etc). Basta pedir para seu code agent ler este README que ele conseguirá implementar a autenticação completa no seu projeto.

SDK minimalista para NiceLogin. **Zero dependências externas.**

---

## Instalação

```bash
pip install nicelogin-jwks-python
```

---

## Conceitos Importantes

### `api_key` vs `api_secret`

| Credencial | Onde usar | Para quê |
|------------|-----------|----------|
| `api_key` | Frontend/Backend | Operações públicas: login, registro, reset de senha |
| `api_secret` | **Apenas Backend** | Operações administrativas: ativar/desativar usuários |

**⚠️ NUNCA exponha o `api_secret` no frontend!**

### Duas Classes Principais

| Classe | Propósito |
|--------|-----------|
| `NiceLogin` | Cliente HTTP para chamar a API (reset senha, ativar usuário, etc) |
| `NiceLoginJWKS` | Verificador local de tokens JWT (não faz requests HTTP) |

---

## Guia Completo de Uso

### 1. Inicialização

```python
from nicelogin_jwks import NiceLogin, NiceLoginJWKS, NiceLoginError

# Cliente para operações de API
client = NiceLogin(
    api_key="nicelogin_sua_api_key",         # Obrigatório
    api_secret="seu_api_secret",              # Opcional (só para admin)
    base_url="https://api.v1.nicelogin.com"   # Opcional (default)
)
```

### 2. Reset de Senha (Fluxo Completo)

**Cenário: Usuário esqueceu a senha**

```python
# PASSO 1: Backend solicita token de reset
reset_token = client.request_password_reset("usuario@email.com")

# PASSO 2: Envie o reset_token por email para o usuário
# (implemente seu próprio envio de email)
send_email(
    to="usuario@email.com",
    subject="Reset de Senha",
    body=f"Use este token para resetar sua senha: {reset_token}"
)

# PASSO 3: Usuário clica no link e informa nova senha
# Backend recebe o token e nova senha do frontend
client.reset_password(
    email="usuario@email.com",
    current_password="senha_atual",  # Usuário precisa saber a senha atual
    new_password="nova_senha_123",
    reset_token=reset_token
)
```

### 3. Trocar Senha (Usuário Logado)

**Cenário: Usuário quer trocar a senha sabendo a atual**

```python
# Uma única linha - solicita token internamente
client.change_password(
    email="usuario@email.com",
    current_password="senha_atual",
    new_password="nova_senha_123"
)
```

### 4. Ativar/Desativar Usuário (Admin)

**⚠️ Requer `api_secret` - Use apenas no backend!**

```python
# Inicialize com api_secret
admin_client = NiceLogin(
    api_key="nicelogin_xxx",
    api_secret="secret_xxx"  # OBRIGATÓRIO para estas operações
)

# Desativar usuário (ex: banir, suspender)
admin_client.deactivate_user("550e8400-e29b-41d4-a716-446655440000")

# Reativar usuário
admin_client.activate_user("550e8400-e29b-41d4-a716-446655440000")
```

### 5. Verificar Token JWT (Local, Sem HTTP)

**Cenário: Validar token em cada request do seu backend**

```python
import urllib.request
import json

# PASSO 1: Buscar JWKS uma vez (cache por 24h)
api_key = "nicelogin_sua_api_key"
jwks_url = f"https://api.v1.nicelogin.com/.well-known/jwks/{api_key}"

with urllib.request.urlopen(jwks_url) as response:
    jwks = json.loads(response.read().decode())

# PASSO 2: Criar verificador (faça isso uma vez na inicialização)
verifier = NiceLoginJWKS(jwks)

# PASSO 3: Verificar tokens em cada request
def authenticate(request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")

    # Verifica se token é válido (True/False)
    if not verifier.verify_token(token):
        raise Exception("Token inválido")

    # Extrai dados do usuário
    payload = verifier.unpack(token)
    return {
        "user_id": payload["sub"],
        "email": payload["email"],
        "company_id": payload["company_id"]
    }
```

---

## Referência Rápida da API

### Classe `NiceLogin`

```python
client = NiceLogin(api_key, api_secret=None, base_url="https://api.v1.nicelogin.com")
```

| Método | Parâmetros | Retorno | Descrição |
|--------|------------|---------|-----------|
| `request_password_reset(email)` | `email: str` | `str` (token) | Solicita token de reset |
| `reset_password(email, current_password, new_password, reset_token)` | todos `str` | `bool` | Reseta senha com token |
| `change_password(email, current_password, new_password)` | todos `str` | `bool` | Troca senha (1 passo) |
| `activate_user(user_id)` | `user_id: str` | `bool` | Ativa usuário* |
| `deactivate_user(user_id)` | `user_id: str` | `bool` | Desativa usuário* |

*Requer `api_secret`

### Classe `NiceLoginJWKS`

```python
verifier = NiceLoginJWKS(jwks)  # jwks é dict do endpoint /.well-known/jwks/{api_key}
```

| Método | Parâmetros | Retorno | Descrição |
|--------|------------|---------|-----------|
| `verify_token(token)` | `token: str` | `bool` | `True` se válido |
| `unpack(token, verify=True)` | `token: str`, `verify: bool` | `dict` | Extrai payload |

### Payload do Token (claims)

```python
{
    "sub": "550e8400-...",        # User ID (UUID)
    "email": "user@email.com",    # Email do usuário
    "company_id": "660e8400-...", # Company ID (UUID)
    "exp": 1704153600,            # Expiração (Unix timestamp)
    "iat": 1704067200,            # Emissão (Unix timestamp)
    "jti": "unique-token-id",     # ID único do token
    "sid": "session-id",          # Session ID (opcional)
    "user_data": {"name": "João"} # Dados customizados (opcional)
}
```

---

## Tratamento de Erros

```python
from nicelogin_jwks import NiceLogin, NiceLoginError

client = NiceLogin(api_key="...")

try:
    client.change_password("user@email.com", "wrong_password", "new_pass")
except NiceLoginError as e:
    print(f"Erro {e.status}: {e.message}")
    # Erro 401: Invalid credentials
```

### Códigos de Erro Comuns

| Status | Significado |
|--------|-------------|
| 400 | Dados inválidos (senha fraca, email inválido) |
| 401 | Credenciais inválidas (api_key, senha, token) |
| 404 | Usuário não encontrado |
| 500 | Erro interno do servidor |

---

## Exemplos de Integração

### FastAPI

```python
from fastapi import FastAPI, Depends, HTTPException, Header
from nicelogin_jwks import NiceLogin, NiceLoginJWKS, NiceLoginError
import urllib.request
import json

app = FastAPI()

# Configuração
API_KEY = "nicelogin_xxx"
API_SECRET = "secret_xxx"

# Inicializar cliente
client = NiceLogin(api_key=API_KEY, api_secret=API_SECRET)

# Carregar JWKS uma vez
with urllib.request.urlopen(f"https://api.v1.nicelogin.com/.well-known/jwks/{API_KEY}") as r:
    jwks = json.loads(r.read().decode())
verifier = NiceLoginJWKS(jwks)

# Dependency de autenticação
def get_current_user(authorization: str = Header(...)):
    token = authorization.replace("Bearer ", "")
    if not verifier.verify_token(token):
        raise HTTPException(401, "Token inválido")
    return verifier.unpack(token)

# Rotas
@app.post("/reset-password")
def reset_password(email: str):
    try:
        token = client.request_password_reset(email)
        # Enviar token por email...
        return {"message": "Email enviado"}
    except NiceLoginError as e:
        raise HTTPException(e.status, e.message)

@app.get("/me")
def get_me(user: dict = Depends(get_current_user)):
    return {"user_id": user["sub"], "email": user["email"]}

@app.post("/admin/deactivate/{user_id}")
def deactivate(user_id: str, admin: dict = Depends(get_current_user)):
    client.deactivate_user(user_id)
    return {"message": "Usuário desativado"}
```

### Flask

```python
from flask import Flask, request, jsonify
from nicelogin_jwks import NiceLogin, NiceLoginJWKS, NiceLoginError
from functools import wraps
import urllib.request
import json

app = Flask(__name__)

# Configuração
API_KEY = "nicelogin_xxx"
client = NiceLogin(api_key=API_KEY)

# Carregar JWKS
with urllib.request.urlopen(f"https://api.v1.nicelogin.com/.well-known/jwks/{API_KEY}") as r:
    jwks = json.loads(r.read().decode())
verifier = NiceLoginJWKS(jwks)

# Decorator de autenticação
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not verifier.verify_token(token):
            return jsonify({"error": "Token inválido"}), 401
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

# Carregar JWKS uma vez
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
        return JsonResponse({"error": "Não autenticado"}, status=401)
    return JsonResponse({
        "user_id": request.nicelogin_user["sub"],
        "email": request.nicelogin_user["email"]
    })
```

---

## Checklist de Implementação

Para LLMs e desenvolvedores, use este checklist:

- [ ] Instalar: `pip install nicelogin-jwks-python`
- [ ] Obter `api_key` do painel NiceLogin
- [ ] Obter `api_secret` (se precisar ativar/desativar usuários)
- [ ] Implementar endpoint de reset de senha
- [ ] Implementar verificação de token JWT nas rotas protegidas
- [ ] Cachear JWKS por 24h (não buscar em cada request)
- [ ] Tratar erros com try/except `NiceLoginError`

---

## Licença

MIT
