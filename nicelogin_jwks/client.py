"""
NiceLogin Client - Zero Dependencies HTTP Client
"""
import urllib.request
import urllib.error
import json
from typing import Optional, Dict, Any


class NiceLoginError(Exception):
    """NiceLogin API error."""
    def __init__(self, message: str, status: int = 0):
        self.message = message
        self.status = status
        super().__init__(message)


class NiceLogin:
    """NiceLogin client for authentication operations."""

    def __init__(
        self,
        api_key: str,
        api_secret: Optional[str] = None,
        base_url: str = "https://api.v1.nicelogin.com"
    ):
        """
        Initialize the NiceLogin client.

        Args:
            api_key: Company API key
            api_secret: API secret (required for activate/deactivate_user)
            base_url: API base URL
        """
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = base_url.rstrip("/")

    def request_password_reset(self, email: str) -> str:
        """
        Request a password reset token.

        Args:
            email: User email

        Returns:
            Reset token (valid for 24h)

        Raises:
            NiceLoginError: If request fails
        """
        data = {"email": email, "api_key": self.api_key}
        resp = self._post("/request_password_reset", data)
        return resp["reset_token"]

    def reset_password(
        self,
        email: str,
        current_password: str,
        new_password: str,
        reset_token: str
    ) -> bool:
        """
        Reset password using a reset token.

        Args:
            email: User email
            current_password: Current password
            new_password: New password
            reset_token: Token obtained via request_password_reset()

        Returns:
            True if successful

        Raises:
            NiceLoginError: If request fails
        """
        data = {
            "email": email,
            "current_password": current_password,
            "new_password": new_password,
            "confirm_password": new_password,
            "api_key": self.api_key,
            "reset_token": reset_token
        }
        resp = self._post("/reset_password", data)
        return resp.get("success", False)

    def change_password(
        self,
        email: str,
        current_password: str,
        new_password: str
    ) -> bool:
        """
        Change password (requests token internally).

        Args:
            email: User email
            current_password: Current password
            new_password: New password

        Returns:
            True if successful

        Raises:
            NiceLoginError: If request fails
        """
        reset_token = self.request_password_reset(email)
        return self.reset_password(email, current_password, new_password, reset_token)

    def activate_user(self, user_id: str) -> bool:
        """
        Activate a user.

        Args:
            user_id: User UUID

        Returns:
            True if successful

        Raises:
            NiceLoginError: If request fails or api_secret not configured
        """
        return self._toggle_user_status(user_id, True)

    def deactivate_user(self, user_id: str) -> bool:
        """
        Deactivate a user.

        Args:
            user_id: User UUID

        Returns:
            True if successful

        Raises:
            NiceLoginError: If request fails or api_secret not configured
        """
        return self._toggle_user_status(user_id, False)

    def _toggle_user_status(self, user_id: str, is_active: bool) -> bool:
        """Toggle user status."""
        if not self.api_secret:
            raise NiceLoginError("api_secret required for user status operations", 401)
        data = {
            "api_secret": self.api_secret,
            "user_id": user_id,
            "is_active": is_active
        }
        resp = self._patch("/toggle_user_status", data)
        return resp.get("is_active") == is_active

    def _post(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Make POST request."""
        return self._request("POST", endpoint, data)

    def _patch(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Make PATCH request."""
        return self._request("PATCH", endpoint, data)

    def _request(
        self,
        method: str,
        endpoint: str,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Make HTTP request."""
        url = f"{self.base_url}{endpoint}"
        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method=method
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode("utf-8"))
                raise NiceLoginError(body.get("error", str(e)), e.code)
            except json.JSONDecodeError:
                raise NiceLoginError(str(e), e.code)
        except urllib.error.URLError as e:
            raise NiceLoginError(f"Connection error: {e.reason}", 0)
