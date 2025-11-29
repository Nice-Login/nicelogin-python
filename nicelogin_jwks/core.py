"""
NiceLogin JWKS Token Verifier - Zero Dependencies
"""
import base64
import json
import hashlib
import time
from typing import Dict, Any


class NiceLoginJWKS:
    """Verificador de tokens JWT do NiceLogin."""

    def __init__(self, jwks: Dict[str, Any]):
        """
        Inicializa com JWKS (JSON Web Key Set).

        Args:
            jwks: Dict com formato {"keys": [{"kty": "RSA", "n": "...", "e": "...", "kid": "..."}]}
        """
        self._keys = {}
        for key in jwks.get("keys", []):
            if key.get("kty") == "RSA" and key.get("use", "sig") == "sig":
                kid = key.get("kid", "default")
                self._keys[kid] = {
                    "n": self._b64url_to_int(key["n"]),
                    "e": self._b64url_to_int(key["e"]),
                }

    def verify_token(self, token: str) -> bool:
        """
        Verifica se o token é válido.

        Returns:
            True se válido, False se inválido ou expirado.
        """
        try:
            self._verify_and_decode(token)
            return True
        except Exception:
            return False

    def unpack(self, token: str, verify: bool = True) -> Dict[str, Any]:
        """
        Extrai o payload do token.

        Args:
            token: JWT string
            verify: Se True, verifica assinatura antes (default: True)

        Returns:
            Dict com claims: sub, email, company_id, exp, iat, jti, sid, user_data

        Raises:
            ValueError: Se token inválido ou expirado
        """
        if verify:
            return self._verify_and_decode(token)
        else:
            parts = token.split(".")
            if len(parts) != 3:
                raise ValueError("Invalid token format")
            payload = self._b64url_decode(parts[1])
            return json.loads(payload)

    def _verify_and_decode(self, token: str) -> Dict[str, Any]:
        """Verifica assinatura RS256 e retorna payload."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid token format")

        header_b64, payload_b64, signature_b64 = parts

        # Decode header para pegar kid
        header = json.loads(self._b64url_decode(header_b64))
        if header.get("alg") != "RS256":
            raise ValueError(f"Unsupported algorithm: {header.get('alg')}")

        # Buscar chave pelo kid
        kid = header.get("kid", "default")
        if kid not in self._keys:
            # Tenta primeira chave se kid não encontrado
            if self._keys:
                kid = next(iter(self._keys))
            else:
                raise ValueError("No valid RSA key found")

        key = self._keys[kid]

        # Verificar assinatura RS256
        message = f"{header_b64}.{payload_b64}".encode("ascii")
        signature = self._b64url_decode_bytes(signature_b64)

        if not self._verify_rs256(message, signature, key["n"], key["e"]):
            raise ValueError("Invalid signature")

        # Decode payload
        payload = json.loads(self._b64url_decode(payload_b64))

        # Verificar expiração
        exp = payload.get("exp")
        if exp and time.time() > exp:
            raise ValueError("Token expired")

        return payload

    def _verify_rs256(self, message: bytes, signature: bytes, n: int, e: int) -> bool:
        """Verifica assinatura RSA PKCS#1 v1.5 com SHA256."""
        # Hash da mensagem
        digest = hashlib.sha256(message).digest()

        # DigestInfo para SHA256 (DER encoded)
        digest_info = bytes([
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20
        ]) + digest

        # RSA verification: m = s^e mod n
        sig_int = int.from_bytes(signature, "big")
        decrypted_int = pow(sig_int, e, n)

        # Converter para bytes (tamanho da chave)
        key_size = (n.bit_length() + 7) // 8
        decrypted = decrypted_int.to_bytes(key_size, "big")

        # Verificar padding PKCS#1 v1.5
        # Formato: 0x00 0x01 [0xFF padding] 0x00 [DigestInfo]
        if len(decrypted) < 11:
            return False
        if decrypted[0] != 0x00 or decrypted[1] != 0x01:
            return False

        # Encontrar separador 0x00 após padding
        separator_idx = None
        for i in range(2, len(decrypted)):
            if decrypted[i] == 0x00:
                separator_idx = i
                break
            if decrypted[i] != 0xFF:
                return False

        if separator_idx is None or separator_idx < 10:
            return False

        # Comparar DigestInfo
        return decrypted[separator_idx + 1:] == digest_info

    @staticmethod
    def _b64url_decode(data: str) -> str:
        """Decode base64url para string."""
        return NiceLoginJWKS._b64url_decode_bytes(data).decode("utf-8")

    @staticmethod
    def _b64url_decode_bytes(data: str) -> bytes:
        """Decode base64url para bytes."""
        # Adicionar padding se necessário
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        # Converter base64url para base64
        data = data.replace("-", "+").replace("_", "/")
        return base64.b64decode(data)

    @staticmethod
    def _b64url_to_int(data: str) -> int:
        """Decode base64url para integer."""
        decoded = NiceLoginJWKS._b64url_decode_bytes(data)
        return int.from_bytes(decoded, "big")
